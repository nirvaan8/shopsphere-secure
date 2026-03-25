from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import CSRFProtect
from flask_talisman import Talisman
from mysql.connector import Error
from database import get_db_connection, init_db
import mysql.connector
import hashlib
import os
import re
from datetime import datetime, timedelta

# ═══════════════════════════════════════════════════════
# App + Security setup
# ═══════════════════════════════════════════════════════

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-in-production-use-env-var')

# ── Session security ────────────────────────────────────
app.config['SESSION_COOKIE_HTTPONLY']    = True    # JS cannot access session cookie
app.config['SESSION_COOKIE_SAMESITE']   = 'Lax'   # Mitigates CSRF via cookie policy
app.config['SESSION_COOKIE_SECURE']     = False    # Set True in production (HTTPS only)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Auto session timeout
app.config['WTF_CSRF_TIME_LIMIT']       = 3600     # CSRF token valid 1 hour

# ── CSRF protection ─────────────────────────────────────
csrf = CSRFProtect(app)

# ── Content Security Policy + security headers ──────────
csp = {
    'default-src': "'self'",
    'script-src':  ["'self'", 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com'],
    'style-src':   ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'cdn.jsdelivr.net'],
    'font-src':    ["'self'", 'fonts.gstatic.com', 'cdn.jsdelivr.net'],
    'img-src':     ["'self'", 'data:'],
    'connect-src': "'self'",
}
Talisman(app,
    force_https=False,           # Set True in production
    strict_transport_security=False,
    content_security_policy=csp,
    x_content_type_options=True, # Prevents MIME-type sniffing
    x_xss_protection=True,       # Enables browser XSS filter
    frame_options='DENY',        # Blocks clickjacking via iframes
)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

init_db()


# ═══════════════════════════════════════════════════════
# Input validation helpers
# ═══════════════════════════════════════════════════════

def validate_username(username: str) -> tuple:
    """3-30 chars, alphanumeric + underscore only."""
    if not username or len(username) < 3 or len(username) > 30:
        return False, "Username must be 3-30 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username may only contain letters, numbers and underscores"
    return True, ""

def validate_password(password: str) -> tuple:
    """Min 8 chars, must have at least one letter and one digit."""
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, ""

def validate_price(value: str) -> tuple:
    try:
        p = float(value)
        if p <= 0: raise ValueError
        return True, p, ""
    except (ValueError, TypeError):
        return False, 0.0, "Price must be a positive number"

def validate_stock(value: str) -> tuple:
    try:
        s = int(value)
        if s < 0: raise ValueError
        return True, s, ""
    except (ValueError, TypeError):
        return False, 0, "Stock must be a non-negative integer"


# ═══════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════

def db_query(sql, params=(), fetchone=False, fetchall=False, commit=False):
    """Run a parameterised query and return result / lastrowid."""
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


def admin_required(f):
    """Decorator: redirects non-admins to home."""
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("Access denied. Admin only.", 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return wrapper


# ═══════════════════════════════════════════════════════
# Session timeout + response hardening
# ═══════════════════════════════════════════════════════

@app.before_request
def enforce_session_timeout():
    """Log out user if session has been idle for > 30 minutes."""
    if current_user.is_authenticated:
        last_active = session.get('_last_active')
        if last_active:
            elapsed = datetime.now() - datetime.fromisoformat(last_active)
            if elapsed > timedelta(minutes=30):
                logout_user()
                session.clear()
                flash("Session expired. Please log in again.", "warning")
                return redirect(url_for("login"))
        session['_last_active'] = datetime.now().isoformat()
        session.permanent = True


@app.after_request
def add_security_headers(response):
    """Add extra security headers not covered by Talisman."""
    response.headers['Referrer-Policy']        = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy']     = 'geolocation=(), microphone=(), camera=()'
    response.headers['Cache-Control']          = 'no-store, no-cache, must-revalidate'
    response.headers['Pragma']                 = 'no-cache'
    return response


# ═══════════════════════════════════════════════════════
# Auth — FlaskUser & context processor
# ═══════════════════════════════════════════════════════

class FlaskUser(UserMixin):
    def __init__(self, user_id, username, role):
        self.id       = user_id
        self.username = username
        self.role     = role


@login_manager.user_loader
def load_user(user_id):
    user = db_query(
        'SELECT user_id, username, role FROM users WHERE user_id = %s',
        (user_id,), fetchone=True
    )
    return FlaskUser(user['user_id'], user['username'], user['role']) if user else None


@app.context_processor
def inject_cart_count():
    if current_user.is_authenticated:
        row = db_query(
            'SELECT SUM(quantity) AS total FROM carts WHERE user_id = %s',
            (current_user.id,), fetchone=True
        )
        return {'cart_count': int(row['total']) if row and row['total'] else 0}
    return {'cart_count': 0}


# ═══════════════════════════════════════════════════════
# Cart — shared logic
# ═══════════════════════════════════════════════════════

class Cart:
    @staticmethod
    def add(user_id, product_id, quantity=1):
        conn = get_db_connection()
        if not conn:
            return False, "Database connection failed"
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT stock FROM products WHERE product_id = %s", (product_id,))
            stock = cursor.fetchone()
            if not stock or stock['stock'] < quantity:
                return False, "Insufficient stock or product not found"

            cursor.execute(
                "SELECT quantity FROM carts WHERE user_id = %s AND product_id = %s",
                (user_id, product_id)
            )
            existing = cursor.fetchone()

            if existing:
                new_qty = existing['quantity'] + quantity
                if new_qty > stock['stock']:
                    return False, "Cannot add more than available stock"
                cursor.execute(
                    "UPDATE carts SET quantity = %s WHERE user_id = %s AND product_id = %s",
                    (new_qty, user_id, product_id)
                )
            else:
                cursor.execute(
                    "INSERT INTO carts (user_id, product_id, quantity) VALUES (%s, %s, %s)",
                    (user_id, product_id, quantity)
                )
            conn.commit()
            return True, f"Added {quantity} item(s) to cart"
        except Error as e:
            conn.rollback()
            return False, str(e)
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get(user_id):
        rows = db_query("""
            SELECT c.product_id, p.name, p.price, c.quantity,
                   (c.quantity * p.price) AS subtotal
            FROM carts c JOIN products p ON c.product_id = p.product_id
            WHERE c.user_id = %s
        """, (user_id,), fetchall=True) or []
        return rows, float(sum(r['subtotal'] for r in rows))

    @staticmethod
    def remove(user_id, product_id):
        db_query(
            "DELETE FROM carts WHERE user_id = %s AND product_id = %s",
            (user_id, product_id), commit=True
        )

    @staticmethod
    def clear(user_id):
        db_query("DELETE FROM carts WHERE user_id = %s", (user_id,), commit=True)

    @staticmethod
    def update_qty(user_id, product_id, quantity):
        db_query(
            "UPDATE carts SET quantity = %s WHERE user_id = %s AND product_id = %s",
            (quantity, user_id, product_id), commit=True
        )
        row = db_query(
            "SELECT SUM(quantity) AS total FROM carts WHERE user_id = %s",
            (user_id,), fetchone=True
        )
        return int(row['total']) if row and row['total'] else 0


# ═══════════════════════════════════════════════════════
# Public routes
# ═══════════════════════════════════════════════════════

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role     = request.form.get('role', 'customer')

        ok_u, err_u = validate_username(username)
        if not ok_u:
            flash(err_u, 'danger')
            return render_template('register.html')

        ok_p, err_p = validate_password(password)
        if not ok_p:
            flash(err_p, 'danger')
            return render_template('register.html')

        salt   = os.urandom(32)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

        conn = get_db_connection()
        if not conn:
            flash('Database connection failed', 'danger')
            return render_template('register.html')
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO users (username, hashed_password, salt, role) VALUES (%s,%s,%s,%s)',
                (username, hashed, salt, role)
            )
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash('Username already exists', 'danger')
        except Error as e:
            flash(f'Database error: {e}', 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db_connection()
        if not conn:
            flash('Database connection failed', 'danger')
            return render_template('login.html')
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()

        if not user:
            flash('User not found', 'danger')
            cursor.close(); conn.close()
            return render_template('login.html')

        # Brute-force lock check
        if user['locked_until'] and user['locked_until'] > datetime.now():
            flash(f"Account locked until {user['locked_until']}", 'danger')
            cursor.close(); conn.close()
            return render_template('login.html')
        elif user['locked_until']:
            cursor.execute('UPDATE users SET locked_until=NULL WHERE user_id=%s', (user['user_id'],))
            conn.commit()

        computed = hashlib.pbkdf2_hmac('sha256', password.encode(), user['salt'], 100000)
        success  = computed == user['hashed_password']

        cursor.execute(
            'INSERT INTO login_attempts (user_id, timestamp, success) VALUES (%s,%s,%s)',
            (user['user_id'], datetime.now().isoformat(), 1 if success else 0)
        )
        conn.commit()

        if success:
            login_user(FlaskUser(user['user_id'], user['username'], user['role']))
            flash('Login successful!', 'success')
            cursor.close(); conn.close()
            return redirect(url_for('admin_sales_dashboard' if user['role'] == 'admin' else 'products'))

        ten_min_ago = (datetime.now() - timedelta(minutes=10)).isoformat()
        cursor.execute(
            'SELECT COUNT(*) AS failed FROM login_attempts WHERE user_id=%s AND success=0 AND timestamp>%s',
            (user['user_id'], ten_min_ago)
        )
        if cursor.fetchone()['failed'] >= 5:
            lock_until = (datetime.now() + timedelta(minutes=30)).isoformat()
            cursor.execute('UPDATE users SET locked_until=%s WHERE user_id=%s', (lock_until, user['user_id']))
            conn.commit()
            flash('Too many failed attempts. Account locked for 30 minutes.', 'danger')
        else:
            flash('Invalid password', 'danger')

        cursor.close(); conn.close()
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('home'))


# ═══════════════════════════════════════════════════════
# Customer routes
# ═══════════════════════════════════════════════════════

@app.route('/products')
@login_required
def products():
    keyword = request.args.get('search', '').strip()
    if keyword:
        rows = db_query(
            "SELECT product_id,name,description,price,stock FROM products WHERE name LIKE %s OR description LIKE %s",
            (f'%{keyword}%', f'%{keyword}%'), fetchall=True
        )
    else:
        rows = db_query("SELECT product_id,name,description,price,stock FROM products", fetchall=True)
    return render_template('products.html', products=rows or [], keyword=keyword)


@app.route('/add-to-cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    try:
        qty = max(1, int(request.form.get('quantity', 1)))
    except (ValueError, TypeError):
        qty = 1
    ok, msg = Cart.add(current_user.id, product_id, qty)
    flash(msg, 'success' if ok else 'danger')
    return redirect(url_for('products'))


@app.route('/cart')
@login_required
def cart():
    items, total = Cart.get(current_user.id)
    return render_template('cart.html', items=items, total=total)


@app.route('/remove-from-cart/<int:product_id>', methods=['POST'])
@login_required
def remove_from_cart(product_id):
    Cart.remove(current_user.id, product_id)
    flash("Item removed from cart", "info")
    return redirect(url_for('cart'))


@app.route('/update-cart/<int:product_id>', methods=['POST'])
@login_required
def update_cart(product_id):
    data = request.get_json() or {}
    qty  = max(1, int(data.get('quantity', 1)))
    cart_count = Cart.update_qty(current_user.id, product_id, qty)
    return jsonify({'success': True, 'cart_count': cart_count})


@app.route('/checkout')
@login_required
def checkout():
    items, total = Cart.get(current_user.id)
    if not items:
        flash("Your cart is empty", "warning")
        return redirect(url_for('cart'))
    return render_template('checkout.html', items=items, total=total)


@app.route('/place_order', methods=['POST'])
@login_required
def place_order():
    conn = get_db_connection()
    if not conn:
        flash("Database connection failed", "danger")
        return redirect(url_for('cart'))
    cursor = conn.cursor(dictionary=True)
    try:
        items, total = Cart.get(current_user.id)
        if not items:
            flash("Cart is empty", "danger")
            return redirect(url_for('cart'))

        payment_method = request.form.get('payment_method', 'simulated')
        cursor.execute(
            "INSERT INTO orders (user_id,order_date,status) VALUES (%s,%s,'placed')",
            (current_user.id, datetime.now().isoformat())
        )
        order_id = cursor.lastrowid

        for item in items:
            cursor.execute(
                "INSERT INTO order_items (order_id,product_id,quantity,price) VALUES (%s,%s,%s,%s)",
                (order_id, item['product_id'], item['quantity'], item['price'])
            )
            cursor.execute(
                "UPDATE products SET stock=stock-%s WHERE product_id=%s",
                (item['quantity'], item['product_id'])
            )

        cursor.execute(
            "INSERT INTO payments (order_id,amount,payment_date,method) VALUES (%s,%s,%s,%s)",
            (order_id, total, datetime.now().isoformat(), payment_method)
        )
        Cart.clear(current_user.id)
        conn.commit()
        flash(f"Order #{order_id} placed successfully using {payment_method.upper()}!", 'success')
        return redirect(url_for('products'))
    except Error as e:
        conn.rollback()
        flash(f"Error placing order: {e}", "danger")
        return redirect(url_for('checkout'))
    finally:
        cursor.close(); conn.close()


@app.route('/orders')
@login_required
def order_history():
    orders = db_query("""
        SELECT o.order_id, o.order_date, o.status,
               COALESCE(SUM(oi.quantity*oi.price),0) AS total_amount
        FROM orders o
        LEFT JOIN order_items oi ON o.order_id=oi.order_id
        WHERE o.user_id=%s
        GROUP BY o.order_id ORDER BY o.order_date DESC
    """, (current_user.id,), fetchall=True) or []

    order_items = {}
    for o in orders:
        order_items[o['order_id']] = db_query("""
            SELECT p.name, oi.quantity, oi.price, (oi.quantity*oi.price) AS subtotal
            FROM order_items oi JOIN products p ON oi.product_id=p.product_id
            WHERE oi.order_id=%s ORDER BY p.name
        """, (o['order_id'],), fetchall=True) or []

    return render_template('orders.html', orders=orders, order_items=order_items)


@app.route('/dashboard')
@login_required
def dashboard():
    orders = db_query("""
        SELECT o.order_id, o.order_date, o.status,
               COALESCE(SUM(oi.quantity*oi.price),0) AS total_amount
        FROM orders o
        LEFT JOIN order_items oi ON o.order_id=oi.order_id
        WHERE o.user_id=%s
        GROUP BY o.order_id ORDER BY o.order_date DESC
    """, (current_user.id,), fetchall=True) or []
    return render_template('dashboard.html', orders=orders)


# ═══════════════════════════════════════════════════════
# Admin routes
# ═══════════════════════════════════════════════════════

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    return redirect(url_for('admin_sales_dashboard'))


@app.route('/admin/sales')
@login_required
@admin_required
def admin_sales_dashboard():
    rev_row  = db_query("SELECT COALESCE(SUM(amount),0) AS rev FROM payments", fetchone=True)
    ord_row  = db_query("SELECT COUNT(*) AS cnt FROM orders", fetchone=True)
    del_row  = db_query("SELECT COUNT(*) AS cnt FROM orders WHERE status='Delivered'", fetchone=True)
    cust_row = db_query("SELECT COUNT(*) AS cnt FROM users WHERE role='customer'", fetchone=True)
    prod_row = db_query("SELECT COUNT(*) AS cnt FROM products", fetchone=True)
    low_row  = db_query("SELECT COUNT(*) AS cnt FROM products WHERE stock>0 AND stock<=5", fetchone=True)

    total_revenue   = float(rev_row['rev'])  if rev_row  else 0.0
    total_orders    = int(ord_row['cnt'])    if ord_row  else 0
    delivered_count = int(del_row['cnt'])    if del_row  else 0
    total_customers = int(cust_row['cnt'])   if cust_row else 0
    total_products  = int(prod_row['cnt'])   if prod_row else 0
    low_stock_count = int(low_row['cnt'])    if low_row  else 0

    revenue_by_day = db_query("""
        SELECT DATE(payment_date) AS day, SUM(amount) AS revenue
        FROM payments
        WHERE payment_date >= DATE_SUB(NOW(), INTERVAL 14 DAY)
        GROUP BY DATE(payment_date) ORDER BY day ASC
    """, fetchall=True) or []
    for r in revenue_by_day:
        r['day']     = str(r['day'])
        r['revenue'] = float(r['revenue'])

    status_counts = db_query(
        "SELECT status, COUNT(*) AS cnt FROM orders GROUP BY status",
        fetchall=True
    ) or []

    top_products = db_query("""
        SELECT p.name, SUM(oi.quantity) AS units_sold, SUM(oi.quantity*oi.price) AS revenue
        FROM order_items oi JOIN products p ON oi.product_id=p.product_id
        GROUP BY oi.product_id ORDER BY revenue DESC LIMIT 8
    """, fetchall=True) or []
    for p in top_products:
        p['revenue'] = float(p['revenue'])

    recent_orders = db_query("""
        SELECT o.order_id, o.status, u.username,
               COALESCE(SUM(oi.quantity*oi.price),0) AS total_amount
        FROM orders o
        JOIN users u ON o.user_id=u.user_id
        LEFT JOIN order_items oi ON o.order_id=oi.order_id
        GROUP BY o.order_id ORDER BY o.order_date DESC LIMIT 8
    """, fetchall=True) or []
    for o in recent_orders:
        o['total_amount'] = float(o['total_amount'])

    all_users = db_query("""
        SELECT u.user_id, u.username, u.role,
               u.locked_until,
               COUNT(DISTINCT o.order_id)          AS order_count,
               COALESCE(SUM(oi.quantity*oi.price), 0) AS total_spent
        FROM users u
        LEFT JOIN orders o  ON o.user_id  = u.user_id
        LEFT JOIN order_items oi ON oi.order_id = o.order_id
        GROUP BY u.user_id
        ORDER BY total_spent DESC
    """, fetchall=True) or []
    for u in all_users:
        u['total_spent'] = float(u['total_spent'])

    return render_template('admin_dashboard.html',
        total_revenue=total_revenue,
        total_orders=total_orders,
        delivered_count=delivered_count,
        total_customers=total_customers,
        total_products=total_products,
        low_stock_count=low_stock_count,
        revenue_by_day=revenue_by_day,
        status_counts=status_counts,
        top_products=top_products,
        recent_orders=recent_orders,
        all_users=all_users,
    )


@app.route('/admin/products')
@login_required
@admin_required
def admin_products():
    products = db_query("SELECT * FROM products ORDER BY product_id DESC", fetchall=True) or []
    return render_template('admin_products.html', products=products)


@app.route('/admin/products/add', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_product():
    if request.method == 'POST':
        name        = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        price_str   = request.form.get('price', '')
        stock_str   = request.form.get('stock', '')

        if not name or not price_str or not stock_str:
            flash("Name, price, and stock are required", 'danger')
            return redirect(url_for('admin_add_product'))

        ok_p, price, err_p = validate_price(price_str)
        if not ok_p:
            flash(err_p, 'danger')
            return redirect(url_for('admin_add_product'))
        ok_s, stock, err_s = validate_stock(stock_str)
        if not ok_s:
            flash(err_s, 'danger')
            return redirect(url_for('admin_add_product'))

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO products (name,description,price,stock) VALUES (%s,%s,%s,%s)",
                (name, description, price, stock)
            )
            conn.commit()
            flash("Product added successfully!", 'success')
            return redirect(url_for('admin_products'))
        except Error as e:
            flash(f"Error adding product: {e}", 'danger')
        finally:
            cursor.close(); conn.close()

    return render_template('admin_add_product.html')


@app.route('/admin/products/edit/<int:product_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_product(product_id):
    if request.method == 'POST':
        name        = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        price_str   = request.form.get('price', '')
        stock_str   = request.form.get('stock', '')

        if not name or not price_str or not stock_str:
            flash("Name, price, and stock are required", 'danger')
            return redirect(url_for('admin_edit_product', product_id=product_id))

        ok_p, price, err_p = validate_price(price_str)
        if not ok_p:
            flash(err_p, 'danger')
            return redirect(url_for('admin_edit_product', product_id=product_id))
        ok_s, stock, err_s = validate_stock(stock_str)
        if not ok_s:
            flash(err_s, 'danger')
            return redirect(url_for('admin_edit_product', product_id=product_id))

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "UPDATE products SET name=%s,description=%s,price=%s,stock=%s WHERE product_id=%s",
                (name, description, price, stock, product_id)
            )
            conn.commit()
            flash("Product updated successfully!", 'success')
            return redirect(url_for('admin_products'))
        except Error as e:
            flash(f"Error updating product: {e}", 'danger')
        finally:
            cursor.close(); conn.close()

    product = db_query("SELECT * FROM products WHERE product_id=%s", (product_id,), fetchone=True)
    if not product:
        flash("Product not found", 'danger')
        return redirect(url_for('admin_products'))
    return render_template('admin_edit_product.html', product=product)


@app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_product(product_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM products WHERE product_id=%s", (product_id,))
        conn.commit()
        flash("Product deleted successfully!", 'success')
    except Error as e:
        flash(f"Error deleting product: {e}", 'danger')
    finally:
        cursor.close(); conn.close()
    return redirect(url_for('admin_products'))


@app.route('/admin/unlock-accounts')
@login_required
@admin_required
def admin_unlock_accounts():
    locked_users = db_query("""
        SELECT user_id, username, role, locked_until FROM users
        WHERE locked_until IS NOT NULL AND locked_until > NOW()
        ORDER BY locked_until DESC
    """, fetchall=True) or []

    all_users = db_query("""
        SELECT u.user_id, u.username, u.role, u.locked_until,
               COUNT(DISTINCT o.order_id)              AS order_count,
               COALESCE(SUM(oi.quantity * oi.price), 0) AS total_spent
        FROM users u
        LEFT JOIN orders o       ON o.user_id     = u.user_id
        LEFT JOIN order_items oi ON oi.order_id   = o.order_id
        GROUP BY u.user_id
        ORDER BY u.role DESC, u.username ASC
    """, fetchall=True) or []
    for u in all_users:
        u["total_spent"] = float(u["total_spent"])

    return render_template("admin_unlock_accounts.html", locked_users=locked_users, all_users=all_users)


@app.route('/admin/unlock-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_unlock_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET locked_until=NULL WHERE user_id=%s", (user_id,))
        conn.commit()
        flash(
            "Account unlocked successfully." if cursor.rowcount else "User not found or already unlocked.",
            'success' if cursor.rowcount else 'info'
        )
    except Error as e:
        flash(f"Database error: {e}", 'danger')
    finally:
        cursor.close(); conn.close()
    return redirect(url_for('admin_unlock_accounts'))


# ═══════════════════════════════════════════════════════
if __name__ == '__main__':
    app.run(debug=True)