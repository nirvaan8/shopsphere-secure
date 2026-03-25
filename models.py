"""
models.py — ShopSphere Secure
OOP class definitions: User, Admin, Product, Cart, Order, Payment
All classes use MySQL via get_db_connection() from database.py
Demonstrates: Encapsulation, Inheritance, Abstraction, Polymorphism
"""

import hashlib
import os
from datetime import datetime, timedelta
from mysql.connector import Error
from database import get_db_connection


# ═══════════════════════════════════════════════════════════════
# Base class — shared DB helper (Abstraction)
# ═══════════════════════════════════════════════════════════════

class BaseModel:
    """
    Abstract base class providing a shared database query helper.
    All models inherit from this — demonstrates Inheritance.
    """

    def _query(self, sql, params=(), fetchone=False, fetchall=False, commit=False):
        """Encapsulated DB access — no raw connection logic in subclasses."""
        conn = get_db_connection()
        if not conn:
            raise RuntimeError("Database connection failed")
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(sql, params)
            if commit:
                conn.commit()
                return cursor.lastrowid
            if fetchone:
                return cursor.fetchone()
            if fetchall:
                return cursor.fetchall()
        finally:
            cursor.close()
            conn.close()


# ═══════════════════════════════════════════════════════════════
# User — registration, login, brute-force protection
# ═══════════════════════════════════════════════════════════════

class User(BaseModel):
    """
    Handles customer authentication and account security.
    Encapsulates password hashing, salting, and login-attempt tracking.
    """

    def __init__(self):
        self.user_id  = None
        self.username = None
        self.role     = 'customer'

    # ── Encapsulated password helpers ──────────────────────────
    def _hash_password(self, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

    def _generate_salt(self) -> bytes:
        return os.urandom(32)

    # ── Public methods ──────────────────────────────────────────
    def register(self, username: str, password: str, role: str = 'customer') -> tuple[bool, str]:
        """Register a new user with hashed + salted password."""
        if not username or not password:
            return False, "Username and password are required"

        salt   = self._generate_salt()
        hashed = self._hash_password(password, salt)

        conn = get_db_connection()
        if not conn:
            return False, "Database connection failed"
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO users (username, hashed_password, salt, role) VALUES (%s, %s, %s, %s)',
                (username, hashed, salt, role)
            )
            conn.commit()
            user_id = cursor.lastrowid
            self._log(user_id, f"User registered: {username}")
            return True, "Registration successful"
        except Error as e:
            if 'Duplicate' in str(e):
                return False, "Username already exists"
            return False, str(e)
        finally:
            cursor.close()
            conn.close()

    def login(self, username: str, password: str) -> tuple[bool, str]:
        """Authenticate user. Returns (success, message)."""
        row = self._query(
            'SELECT user_id, hashed_password, salt, role, locked_until FROM users WHERE username = %s',
            (username,), fetchone=True
        )
        if not row:
            return False, "User not found"

        # Brute-force lock check
        if row['locked_until'] and row['locked_until'] > datetime.now():
            return False, f"Account locked until {row['locked_until']}"

        computed = self._hash_password(password, row['salt'])
        success  = computed == row['hashed_password']

        # Log attempt
        self._query(
            'INSERT INTO login_attempts (user_id, timestamp, success) VALUES (%s, %s, %s)',
            (row['user_id'], datetime.now(), 1 if success else 0), commit=True
        )

        if success:
            self.user_id  = row['user_id']
            self.username = username
            self.role     = row['role']
            # Clear lock if previously set but expired
            if row['locked_until']:
                self._query('UPDATE users SET locked_until=NULL WHERE user_id=%s', (self.user_id,), commit=True)
            self._log(self.user_id, "Successful login")
            return True, "Login successful"

        # Check failed attempts in last 10 min
        ten_min_ago = datetime.now() - timedelta(minutes=10)
        result = self._query(
            'SELECT COUNT(*) AS cnt FROM login_attempts WHERE user_id=%s AND success=0 AND timestamp>%s',
            (row['user_id'], ten_min_ago), fetchone=True
        )
        if result and result['cnt'] >= 5:
            lock_until = datetime.now() + timedelta(minutes=30)
            self._query('UPDATE users SET locked_until=%s WHERE user_id=%s', (lock_until, row['user_id']), commit=True)
            self._log(row['user_id'], "Account locked — brute-force detected")
            return False, "Too many failed attempts. Account locked for 30 minutes."

        self._log(row['user_id'], "Failed login attempt")
        return False, "Incorrect password"

    def get_by_id(self, user_id: int) -> dict | None:
        return self._query('SELECT user_id, username, role FROM users WHERE user_id=%s', (user_id,), fetchone=True)

    def _log(self, user_id, action: str):
        """Write to security_logs table."""
        try:
            self._query(
                'INSERT INTO security_logs (user_id, action, timestamp) VALUES (%s, %s, %s)',
                (user_id, action, datetime.now()), commit=True
            )
        except Exception:
            pass  # Logging should never crash the app


# ═══════════════════════════════════════════════════════════════
# Admin — inherits User, adds product/order management
# (Inheritance + Polymorphism)
# ═══════════════════════════════════════════════════════════════

class Admin(User):
    """
    Admin extends User (Inheritance).
    Overrides role and adds privileged operations.
    Polymorphism: login() behaviour is inherited but role is enforced.
    """

    def __init__(self):
        super().__init__()
        self.role = 'admin'

    def get_all_orders(self) -> list:
        """Admin-only: view all orders across all users."""
        return self._query("""
            SELECT o.order_id, o.order_date, o.status, u.username,
                   COALESCE(SUM(oi.quantity * oi.price), 0) AS total
            FROM orders o
            JOIN users u ON o.user_id = u.user_id
            LEFT JOIN order_items oi ON o.order_id = oi.order_id
            GROUP BY o.order_id
            ORDER BY o.order_date DESC
        """, fetchall=True) or []

    def get_all_users(self) -> list:
        """Admin-only: list all users with order stats."""
        return self._query("""
            SELECT u.user_id, u.username, u.role, u.locked_until,
                   COUNT(DISTINCT o.order_id)              AS order_count,
                   COALESCE(SUM(oi.quantity * oi.price), 0) AS total_spent
            FROM users u
            LEFT JOIN orders o       ON o.user_id    = u.user_id
            LEFT JOIN order_items oi ON oi.order_id  = o.order_id
            GROUP BY u.user_id
            ORDER BY u.role DESC, u.username ASC
        """, fetchall=True) or []

    def unlock_user(self, user_id: int) -> bool:
        """Remove account lock for a given user."""
        self._query('UPDATE users SET locked_until=NULL WHERE user_id=%s', (user_id,), commit=True)
        self._log(user_id, f"Account manually unlocked by admin")
        return True

    def get_sales_stats(self) -> dict:
        """Return KPI stats for the admin dashboard."""
        rev  = self._query("SELECT COALESCE(SUM(amount),0) AS rev FROM payments", fetchone=True)
        ords = self._query("SELECT COUNT(*) AS cnt FROM orders", fetchone=True)
        dlv  = self._query("SELECT COUNT(*) AS cnt FROM orders WHERE status='delivered'", fetchone=True)
        cust = self._query("SELECT COUNT(*) AS cnt FROM users WHERE role='customer'", fetchone=True)
        prod = self._query("SELECT COUNT(*) AS cnt FROM products", fetchone=True)
        low  = self._query("SELECT COUNT(*) AS cnt FROM products WHERE stock > 0 AND stock <= 5", fetchone=True)
        return {
            'total_revenue':   float(rev['rev'])   if rev  else 0.0,
            'total_orders':    int(ords['cnt'])     if ords else 0,
            'delivered_count': int(dlv['cnt'])      if dlv  else 0,
            'total_customers': int(cust['cnt'])     if cust else 0,
            'total_products':  int(prod['cnt'])     if prod else 0,
            'low_stock_count': int(low['cnt'])      if low  else 0,
        }


# ═══════════════════════════════════════════════════════════════
# Product — CRUD + search
# ═══════════════════════════════════════════════════════════════

class Product(BaseModel):
    """
    Encapsulates all product operations.
    Admin uses this class to manage inventory.
    """

    def add(self, name: str, description: str, price: float, stock: int) -> int:
        """Insert a new product. Returns new product_id."""
        pid = self._query(
            'INSERT INTO products (name, description, price, stock) VALUES (%s, %s, %s, %s)',
            (name, description, price, stock), commit=True
        )
        return pid

    def update(self, product_id: int, name: str, description: str, price: float, stock: int) -> bool:
        """Update an existing product."""
        self._query(
            'UPDATE products SET name=%s, description=%s, price=%s, stock=%s WHERE product_id=%s',
            (name, description, price, stock, product_id), commit=True
        )
        return True

    def delete(self, product_id: int) -> bool:
        """Delete a product by ID."""
        self._query('DELETE FROM products WHERE product_id=%s', (product_id,), commit=True)
        return True

    def get_all(self) -> list:
        """Return all products."""
        return self._query('SELECT * FROM products ORDER BY product_id DESC', fetchall=True) or []

    def get_by_id(self, product_id: int) -> dict | None:
        return self._query('SELECT * FROM products WHERE product_id=%s', (product_id,), fetchone=True)

    def search(self, keyword: str) -> list:
        """Search products by name or description."""
        like = f'%{keyword}%'
        return self._query(
            'SELECT * FROM products WHERE name LIKE %s OR description LIKE %s',
            (like, like), fetchall=True
        ) or []

    def is_in_stock(self, product_id: int, quantity: int = 1) -> bool:
        row = self._query('SELECT stock FROM products WHERE product_id=%s', (product_id,), fetchone=True)
        return bool(row and row['stock'] >= quantity)


# ═══════════════════════════════════════════════════════════════
# Cart — per-user cart operations
# ═══════════════════════════════════════════════════════════════

class Cart(BaseModel):
    """
    Encapsulates cart state for a single user.
    Demonstrates encapsulation — user_id is stored internally.
    """

    def __init__(self, user_id: int):
        self.user_id = user_id

    def add(self, product_id: int, quantity: int = 1) -> tuple[bool, str]:
        """Add item to cart, or increment quantity if already present."""
        product = Product()
        if not product.is_in_stock(product_id, quantity):
            return False, "Insufficient stock"

        existing = self._query(
            'SELECT quantity FROM carts WHERE user_id=%s AND product_id=%s',
            (self.user_id, product_id), fetchone=True
        )
        if existing:
            new_qty = existing['quantity'] + quantity
            self._query(
                'UPDATE carts SET quantity=%s WHERE user_id=%s AND product_id=%s',
                (new_qty, self.user_id, product_id), commit=True
            )
        else:
            self._query(
                'INSERT INTO carts (user_id, product_id, quantity) VALUES (%s, %s, %s)',
                (self.user_id, product_id, quantity), commit=True
            )
        return True, f"Added {quantity} item(s) to cart"

    def remove(self, product_id: int):
        self._query(
            'DELETE FROM carts WHERE user_id=%s AND product_id=%s',
            (self.user_id, product_id), commit=True
        )

    def update_quantity(self, product_id: int, quantity: int):
        if quantity <= 0:
            self.remove(product_id)
            return
        self._query(
            'UPDATE carts SET quantity=%s WHERE user_id=%s AND product_id=%s',
            (quantity, self.user_id, product_id), commit=True
        )

    def get_items(self) -> tuple[list, float]:
        """Return (items list, total float)."""
        rows = self._query("""
            SELECT c.product_id, p.name, p.price, c.quantity,
                   (c.quantity * p.price) AS subtotal
            FROM carts c JOIN products p ON c.product_id = p.product_id
            WHERE c.user_id = %s
        """, (self.user_id,), fetchall=True) or []
        total = float(sum(r['subtotal'] for r in rows))
        return rows, total

    def clear(self):
        self._query('DELETE FROM carts WHERE user_id=%s', (self.user_id,), commit=True)

    def item_count(self) -> int:
        row = self._query(
            'SELECT SUM(quantity) AS total FROM carts WHERE user_id=%s',
            (self.user_id,), fetchone=True
        )
        return int(row['total']) if row and row['total'] else 0


# ═══════════════════════════════════════════════════════════════
# Order — placement, history, tracking
# ═══════════════════════════════════════════════════════════════

class Order(BaseModel):
    """
    Handles order lifecycle: placement, history, tracking.
    Uses Cart internally — demonstrates class collaboration.
    """

    def __init__(self, user_id: int):
        self.user_id = user_id

    def place(self, payment_method: str = 'simulated') -> tuple[bool, str | int, float]:
        """
        Place order from current cart.
        Returns (success, order_id or error_msg, total).
        """
        cart  = Cart(self.user_id)
        items, total = cart.get_items()

        if not items:
            return False, "Cart is empty", 0.0

        conn = get_db_connection()
        if not conn:
            return False, "Database connection failed", 0.0
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                'INSERT INTO orders (user_id, order_date, status) VALUES (%s, %s, %s)',
                (self.user_id, datetime.now(), 'placed')
            )
            order_id = cursor.lastrowid

            for item in items:
                cursor.execute(
                    'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (%s, %s, %s, %s)',
                    (order_id, item['product_id'], item['quantity'], item['price'])
                )
                cursor.execute(
                    'UPDATE products SET stock = stock - %s WHERE product_id = %s',
                    (item['quantity'], item['product_id'])
                )

            # Simulate payment
            cursor.execute(
                'INSERT INTO payments (order_id, amount, payment_date, method) VALUES (%s, %s, %s, %s)',
                (order_id, total, datetime.now(), payment_method)
            )

            cart.clear()
            conn.commit()
            return True, order_id, total
        except Error as e:
            conn.rollback()
            return False, str(e), 0.0
        finally:
            cursor.close()
            conn.close()

    def get_history(self) -> list:
        """Return all orders for this user with totals."""
        return self._query("""
            SELECT o.order_id, o.order_date, o.status,
                   COALESCE(SUM(oi.quantity * oi.price), 0) AS total_amount
            FROM orders o
            LEFT JOIN order_items oi ON o.order_id = oi.order_id
            WHERE o.user_id = %s
            GROUP BY o.order_id
            ORDER BY o.order_date DESC
        """, (self.user_id,), fetchall=True) or []

    def get_items(self, order_id: int) -> list:
        """Return line items for a specific order."""
        return self._query("""
            SELECT p.name, oi.quantity, oi.price,
                   (oi.quantity * oi.price) AS subtotal
            FROM order_items oi
            JOIN products p ON oi.product_id = p.product_id
            WHERE oi.order_id = %s
        """, (order_id,), fetchall=True) or []

    def track(self, order_id: int) -> dict | None:
        """Return order status + items for a given order_id (user must own it)."""
        order = self._query(
            'SELECT order_id, order_date, status FROM orders WHERE order_id=%s AND user_id=%s',
            (order_id, self.user_id), fetchone=True
        )
        if not order:
            return None
        order['items'] = self.get_items(order_id)
        return order


# ═══════════════════════════════════════════════════════════════
# Payment — simulation + history
# ═══════════════════════════════════════════════════════════════

class Payment(BaseModel):
    """
    Handles payment recording and status updates.
    In a real system this would wrap a payment gateway.
    """

    METHODS = ('card', 'upi', 'cod', 'simulated')

    def make_payment(self, order_id: int, amount: float, method: str = 'simulated') -> bool:
        """Record a payment and mark the order as paid."""
        if method not in self.METHODS:
            method = 'simulated'
        self._query(
            'INSERT INTO payments (order_id, amount, payment_date, method) VALUES (%s, %s, %s, %s)',
            (order_id, amount, datetime.now(), method), commit=True
        )
        self._query(
            "UPDATE orders SET status='paid' WHERE order_id=%s",
            (order_id,), commit=True
        )
        return True

    def get_for_order(self, order_id: int) -> dict | None:
        return self._query(
            'SELECT * FROM payments WHERE order_id=%s',
            (order_id,), fetchone=True
        )