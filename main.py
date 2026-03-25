import sqlite3
import hashlib
import os
from datetime import datetime, timedelta

class Database:
    def __init__(self):
        self.conn = sqlite3.connect('shopsphere.db')
        self.c = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        # Users table with security features
        self.c.execute('''CREATE TABLE IF NOT EXISTS users
                          (user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                           username TEXT UNIQUE NOT NULL,
                           hashed_password BLOB NOT NULL,
                           salt BLOB NOT NULL,
                           role TEXT NOT NULL DEFAULT 'customer',
                           locked_until TEXT DEFAULT NULL)''')

        # Products table
        self.c.execute('''CREATE TABLE IF NOT EXISTS products
                          (product_id INTEGER PRIMARY KEY AUTOINCREMENT,
                           name TEXT NOT NULL,
                           description TEXT,
                           price REAL NOT NULL,
                           stock INTEGER NOT NULL DEFAULT 0)''')

        # Carts table
        self.c.execute('''CREATE TABLE IF NOT EXISTS carts
                          (cart_id INTEGER PRIMARY KEY AUTOINCREMENT,
                           user_id INTEGER NOT NULL,
                           product_id INTEGER NOT NULL,
                           quantity INTEGER NOT NULL DEFAULT 1,
                           FOREIGN KEY(user_id) REFERENCES users(user_id),
                           FOREIGN KEY(product_id) REFERENCES products(product_id))''')

        # Orders table
        self.c.execute('''CREATE TABLE IF NOT EXISTS orders
                          (order_id INTEGER PRIMARY KEY AUTOINCREMENT,
                           user_id INTEGER NOT NULL,
                           order_date TEXT NOT NULL,
                           status TEXT NOT NULL DEFAULT 'placed',
                           FOREIGN KEY(user_id) REFERENCES users(user_id))''')

        # Order items table
        self.c.execute('''CREATE TABLE IF NOT EXISTS order_items
                          (order_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                           order_id INTEGER NOT NULL,
                           product_id INTEGER NOT NULL,
                           quantity INTEGER NOT NULL,
                           price REAL NOT NULL,
                           FOREIGN KEY(order_id) REFERENCES orders(order_id),
                           FOREIGN KEY(product_id) REFERENCES products(product_id))''')

        # Payments table
        self.c.execute('''CREATE TABLE IF NOT EXISTS payments
                          (payment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                           order_id INTEGER NOT NULL,
                           amount REAL NOT NULL,
                           payment_date TEXT NOT NULL,
                           method TEXT NOT NULL DEFAULT 'card',
                           FOREIGN KEY(order_id) REFERENCES orders(order_id))''')

        # Login attempts for brute-force prevention
        self.c.execute('''CREATE TABLE IF NOT EXISTS login_attempts
                          (attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                           user_id INTEGER NOT NULL,
                           timestamp TEXT NOT NULL,
                           success BOOLEAN NOT NULL,
                           FOREIGN KEY(user_id) REFERENCES users(user_id))''')

        # Security logs
        self.c.execute('''CREATE TABLE IF NOT EXISTS security_logs
                          (log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                           user_id INTEGER,
                           action TEXT NOT NULL,
                           timestamp TEXT NOT NULL,
                           FOREIGN KEY(user_id) REFERENCES users(user_id))''')

        self.conn.commit()

    def log_action(self, user_id, action):
        timestamp = datetime.now().isoformat()
        self.c.execute('INSERT INTO security_logs (user_id, action, timestamp) VALUES (?, ?, ?)', (user_id, action, timestamp))
        self.conn.commit()

    def close(self):
        self.conn.close()

class User:
    def __init__(self, db):
        self.db = db
        self.user_id = None
        self.username = None
        self.role = None

    def register(self, username, password, role='customer'):
        salt = os.urandom(32)
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        try:
            self.db.c.execute('INSERT INTO users (username, hashed_password, salt, role) VALUES (?, ?, ?, ?)',
                              (username, hashed_password, salt, role))
            self.db.conn.commit()
            user_id = self.db.c.lastrowid
            self.db.log_action(user_id, f"User registered: {username}")
            return True
        except sqlite3.IntegrityError:
            return False

    def login(self, username, password):
        self.db.c.execute('SELECT user_id, hashed_password, salt, role, locked_until FROM users WHERE username = ?', (username,))
        row = self.db.c.fetchone()
        if not row:
            return False, "User not found"

        user_id, stored_hash, salt, role, locked_until = row

        if locked_until and datetime.fromisoformat(locked_until) > datetime.now():
            return False, f"Account locked until {locked_until}"

        computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        success = computed_hash == stored_hash

        timestamp = datetime.now().isoformat()
        self.db.c.execute('INSERT INTO login_attempts (user_id, timestamp, success) VALUES (?, ?, ?)',
                          (user_id, timestamp, success))
        self.db.conn.commit()

        if success:
            self.user_id = user_id
            self.username = username
            self.role = role
            self.db.log_action(user_id, "Successful login")
            # Clear old failed attempts (optional cleanup)
            return True, "Login successful"
        else:
            # Check for brute-force
            ten_min_ago = (datetime.now() - timedelta(minutes=10)).isoformat()
            self.db.c.execute('SELECT COUNT(*) FROM login_attempts WHERE user_id = ? AND success = 0 AND timestamp > ?',
                              (user_id, ten_min_ago))
            failed_count = self.db.c.fetchone()[0]
            if failed_count >= 5:
                lock_until = (datetime.now() + timedelta(minutes=30)).isoformat()
                self.db.c.execute('UPDATE users SET locked_until = ? WHERE user_id = ?', (lock_until, user_id))
                self.db.conn.commit()
                self.db.log_action(user_id, "Account locked due to brute-force attempt")
                return False, "Account locked for 30 minutes due to too many failed attempts"
            self.db.log_action(user_id, "Failed login attempt")
            return False, "Incorrect password"

class Product:
    def __init__(self, db):
        self.db = db

    def add_product(self, name, description, price, stock):
        self.db.c.execute('INSERT INTO products (name, description, price, stock) VALUES (?, ?, ?, ?)',
                          (name, description, price, stock))
        self.db.conn.commit()
        product_id = self.db.c.lastrowid
        self.db.log_action(None, f"Product added: {name} (ID: {product_id})")

    def update_product(self, product_id, name=None, description=None, price=None, stock=None):
        updates = []
        params = []
        if name:
            updates.append('name = ?')
            params.append(name)
        if description:
            updates.append('description = ?')
            params.append(description)
        if price:
            updates.append('price = ?')
            params.append(price)
        if stock:
            updates.append('stock = ?')
            params.append(stock)
        if updates:
            query = f'UPDATE products SET {", ".join(updates)} WHERE product_id = ?'
            params.append(product_id)
            self.db.c.execute(query, params)
            self.db.conn.commit()
            self.db.log_action(None, f"Product updated: ID {product_id}")

    def delete_product(self, product_id):
        self.db.c.execute('DELETE FROM products WHERE product_id = ?', (product_id,))
        self.db.conn.commit()
        self.db.log_action(None, f"Product deleted: ID {product_id}")

    def view_products(self):
        self.db.c.execute('SELECT * FROM products')
        return self.db.c.fetchall()

    def search_products(self, keyword):
        self.db.c.execute('SELECT * FROM products WHERE name LIKE ? OR description LIKE ?',
                          (f'%{keyword}%', f'%{keyword}%'))
        return self.db.c.fetchall()

class Cart:
    def __init__(self, db, user_id):
        self.db = db
        self.user_id = user_id

    def add_to_cart(self, product_id, quantity=1):
        # Check stock
        self.db.c.execute('SELECT stock FROM products WHERE product_id = ?', (product_id,))
        stock = self.db.c.fetchone()
        if not stock or stock[0] < quantity:
            return False, "Insufficient stock"
        # Add or update
        self.db.c.execute('SELECT quantity FROM carts WHERE user_id = ? AND product_id = ?',
                          (self.user_id, product_id))
        existing = self.db.c.fetchone()
        if existing:
            new_quantity = existing[0] + quantity
            self.db.c.execute('UPDATE carts SET quantity = ? WHERE user_id = ? AND product_id = ?',
                              (new_quantity, self.user_id, product_id))
        else:
            self.db.c.execute('INSERT INTO carts (user_id, product_id, quantity) VALUES (?, ?, ?)',
                              (self.user_id, product_id, quantity))
        self.db.conn.commit()
        self.db.log_action(self.user_id, f"Added to cart: Product ID {product_id}, Quantity {quantity}")
        return True, "Added to cart"

    def remove_from_cart(self, product_id):
        self.db.c.execute('DELETE FROM carts WHERE user_id = ? AND product_id = ?',
                          (self.user_id, product_id))
        self.db.conn.commit()
        self.db.log_action(self.user_id, f"Removed from cart: Product ID {product_id}")

    def update_quantity(self, product_id, quantity):
        if quantity <= 0:
            self.remove_from_cart(product_id)
            return
        self.db.c.execute('UPDATE carts SET quantity = ? WHERE user_id = ? AND product_id = ?',
                          (quantity, self.user_id, product_id))
        self.db.conn.commit()
        self.db.log_action(self.user_id, f"Updated cart quantity: Product ID {product_id}, New Quantity {quantity}")

    def view_cart(self):
        self.db.c.execute('''SELECT c.product_id, p.name, c.quantity, p.price, (c.quantity * p.price) AS subtotal
                             FROM carts c JOIN products p ON c.product_id = p.product_id
                             WHERE user_id = ?''', (self.user_id,))
        items = self.db.c.fetchall()
        total = sum(item[4] for item in items)
        return items, total

class Order:
    def __init__(self, db, user_id):
        self.db = db
        self.user_id = user_id

    def place_order(self):
        cart = Cart(self.db, self.user_id)
        items, total = cart.view_cart()
        if not items:
            return False, "Cart is empty"

        # Check stock for all items
        for product_id, name, quantity, price, subtotal in items:
            self.db.c.execute('SELECT stock FROM products WHERE product_id = ?', (product_id,))
            stock = self.db.c.fetchone()[0]
            if stock < quantity:
                return False, f"Insufficient stock for {name}"

        order_date = datetime.now().isoformat()
        self.db.c.execute('INSERT INTO orders (user_id, order_date, status) VALUES (?, ?, ?)',
                          (self.user_id, order_date, 'placed'))
        order_id = self.db.c.lastrowid

        for product_id, name, quantity, price, subtotal in items:
            self.db.c.execute('INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
                              (order_id, product_id, quantity, price))
            self.db.c.execute('UPDATE products SET stock = stock - ? WHERE product_id = ?',
                              (quantity, product_id))

        # Clear cart
        self.db.c.execute('DELETE FROM carts WHERE user_id = ?', (self.user_id,))
        self.db.conn.commit()
        self.db.log_action(self.user_id, f"Order placed: ID {order_id}, Total {total}")
        return True, order_id, total

    def view_orders(self):
        self.db.c.execute('SELECT order_id, order_date, status FROM orders WHERE user_id = ?', (self.user_id,))
        orders = self.db.c.fetchall()
        result = []
        for order_id, order_date, status in orders:
            self.db.c.execute('''SELECT p.name, oi.quantity, oi.price
                                 FROM order_items oi JOIN products p ON oi.product_id = p.product_id
                                 WHERE order_id = ?''', (order_id,))
            items = self.db.c.fetchall()
            result.append((order_id, order_date, status, items))
        return result

    def track_order(self, order_id):
        self.db.c.execute('SELECT order_date, status FROM orders WHERE order_id = ? AND user_id = ?',
                          (order_id, self.user_id))
        order = self.db.c.fetchone()
        if not order:
            return None
        order_date, status = order
        self.db.c.execute('''SELECT p.name, oi.quantity, oi.price
                             FROM order_items oi JOIN products p ON oi.product_id = p.product_id
                             WHERE order_id = ?''', (order_id,))
        items = self.db.c.fetchall()
        return order_id, order_date, status, items

class Payment:
    def __init__(self, db):
        self.db = db

    def make_payment(self, order_id, amount, method='card'):
        payment_date = datetime.now().isoformat()
        self.db.c.execute('INSERT INTO payments (order_id, amount, payment_date, method) VALUES (?, ?, ?, ?)',
                          (order_id, amount, payment_date, method))
        self.db.c.execute('UPDATE orders SET status = "paid" WHERE order_id = ?', (order_id,))
        self.db.conn.commit()
        self.db.log_action(None, f"Payment made for order {order_id}: Amount {amount}")

class Admin(User):
    def __init__(self, db):
        super().__init__(db)

    # Admin-specific methods, e.g., manage users, but for now, use Product class directly

def main_menu(db):
    while True:
        print("\n=== ShopSphere Secure E-Commerce ===")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter choice: ").strip()
        if choice == '1':
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            role = input("Role (customer/admin): ").strip().lower() or 'customer'
            user = User(db)
            if user.register(username, password, role):
                print("Registration successful!")
            else:
                print("Username already exists.")
        elif choice == '2':
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            user = User(db)
            success, message = user.login(username, password)
            print(message)
            if success:
                if user.role == 'admin':
                    admin_menu(db, user)
                else:
                    customer_menu(db, user)
        elif choice == '3':
            break
        else:
            print("Invalid choice.")

def customer_menu(db, user):
    cart = Cart(db, user.user_id)
    order = Order(db, user.user_id)
    product = Product(db)
    while True:
        print("\n=== Customer Menu ===")
        print("1. View Products")
        print("2. Search Products")
        print("3. View Cart")
        print("4. Add to Cart")
        print("5. Remove from Cart")
        print("6. Update Quantity in Cart")
        print("7. Checkout")
        print("8. View Order History")
        print("9. Track Order")
        print("10. Logout")
        choice = input("Enter choice: ").strip()
        if choice == '1':
            products = product.view_products()
            for p in products:
                print(f"ID: {p[0]}, Name: {p[1]}, Price: {p[3]}, Stock: {p[4]}")
        elif choice == '2':
            keyword = input("Enter search keyword: ").strip()
            products = product.search_products(keyword)
            for p in products:
                print(f"ID: {p[0]}, Name: {p[1]}, Price: {p[3]}, Stock: {p[4]}")
        elif choice == '3':
            items, total = cart.view_cart()
            for item in items:
                print(f"Product ID: {item[0]}, Name: {item[1]}, Quantity: {item[2]}, Price: {item[3]}, Subtotal: {item[4]}")
            print(f"Total: {total}")
        elif choice == '4':
            product_id = int(input("Product ID: "))
            quantity = int(input("Quantity: ") or 1)
            success, msg = cart.add_to_cart(product_id, quantity)
            print(msg)
        elif choice == '5':
            product_id = int(input("Product ID: "))
            cart.remove_from_cart(product_id)
            print("Removed from cart.")
        elif choice == '6':
            product_id = int(input("Product ID: "))
            quantity = int(input("New Quantity: "))
            cart.update_quantity(product_id, quantity)
            print("Quantity updated.")
        elif choice == '7':
            success, order_id, total = order.place_order()
            if success:
                print(f"Order placed! ID: {order_id}, Total: {total}")
                pay = Payment(db)
                pay.make_payment(order_id, total)
                print("Payment simulated successfully.")
            else:
                print(order_id)  # Error message
        elif choice == '8':
            orders = order.view_orders()
            for ord_id, date, status, items in orders:
                print(f"Order ID: {ord_id}, Date: {date}, Status: {status}")
                for item in items:
                    print(f" - {item[0]} x {item[1]} @ {item[2]}")
        elif choice == '9':
            order_id = int(input("Order ID: "))
            details = order.track_order(order_id)
            if details:
                ord_id, date, status, items = details
                print(f"Order ID: {ord_id}, Date: {date}, Status: {status}")
                for item in items:
                    print(f" - {item[0]} x {item[1]} @ {item[2]}")
            else:
                print("Order not found.")
        elif choice == '10':
            break
        else:
            print("Invalid choice.")

def admin_menu(db, user):
    product = Product(db)
    order = Order(db, user.user_id)  # But admin can view all
    while True:
        print("\n=== Admin Menu ===")
        print("1. Add Product")
        print("2. Update Product")
        print("3. Delete Product")
        print("4. View All Products")
        print("5. View All Orders")
        print("6. Logout")
        choice = input("Enter choice: ").strip()
        if choice == '1':
            name = input("Name: ").strip()
            desc = input("Description: ").strip()
            price = float(input("Price: "))
            stock = int(input("Stock: "))
            product.add_product(name, desc, price, stock)
            print("Product added.")
        elif choice == '2':
            product_id = int(input("Product ID: "))
            name = input("New Name (leave blank to skip): ").strip() or None
            desc = input("New Description (leave blank): ").strip() or None
            price = input("New Price (leave blank): ").strip()
            price = float(price) if price else None
            stock = input("New Stock (leave blank): ").strip()
            stock = int(stock) if stock else None
            product.update_product(product_id, name, desc, price, stock)
            print("Product updated.")
        elif choice == '3':
            product_id = int(input("Product ID: "))
            product.delete_product(product_id)
            print("Product deleted.")
        elif choice == '4':
            products = product.view_products()
            for p in products:
                print(f"ID: {p[0]}, Name: {p[1]}, Price: {p[3]}, Stock: {p[4]}")
        elif choice == '5':
            db.c.execute('SELECT * FROM orders')
            all_orders = db.c.fetchall()
            for ord in all_orders:
                print(f"Order ID: {ord[0]}, User ID: {ord[1]}, Date: {ord[2]}, Status: {ord[3]}")
        elif choice == '6':
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    db = Database()
    try:
        main_menu(db)
    finally:
        db.close()