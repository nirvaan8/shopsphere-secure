# ShopSphere Secure 🛒🔐

> Cyber-Enabled OOP Based E-Commerce Website with Database Integration  
> DBMS + Object-Oriented Programming Project — NIIT University, Neemrana  
> **Team:** Nirvaan Katyal & Mayur

---

## Overview

ShopSphere Secure is a full-stack e-commerce web application built with **Python (Flask)** and **MySQL**, designed around a clean OOP class hierarchy and hardened with **8 cybersecurity layers**. It serves as both a functional shopping platform and a reference implementation of secure web development practices.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11 + Flask |
| Database | MySQL 8.0 |
| DB Driver | mysql-connector-python |
| Auth | Flask-Login |
| CSRF | Flask-WTF |
| Security Headers | Flask-Talisman |
| Frontend | Jinja2 + Bootstrap Icons |
| Charts | Chart.js 4.4 |

---

## Cybersecurity Features

| # | Feature | How |
|---|---|---|
| 1 | **Password Hashing + Salting** | PBKDF2-SHA256, 100k iterations, 32-byte random salt per user |
| 2 | **Brute-Force Prevention** | 5 failed logins in 10 min → 30-min account lock |
| 3 | **SQL Injection Prevention** | 100% parameterised queries — zero string concatenation in SQL |
| 4 | **CSRF Protection** | Flask-WTF tokens in every POST form + X-CSRFToken on all fetch() |
| 5 | **Session Timeout** | Auto-logout after 30 min idle, HttpOnly + SameSite cookies |
| 6 | **Content Security Policy** | Talisman CSP restricts script/style/img sources |
| 7 | **Security Headers** | X-Frame-Options: DENY, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| 8 | **Input Validation** | Server-side regex + length checks on all form submissions |

---

## OOP Class Architecture

```
BaseModel           ← shared _query() helper (Abstraction)
├── User            ← registration, login, brute-force tracking (Encapsulation)
│   └── Admin       ← inherits User, adds privileged methods (Inheritance)
├── Product         ← CRUD + search
├── Cart            ← per-user cart operations
├── Order           ← placement, history, tracking
└── Payment         ← recording + status update
```

Demonstrates: **Encapsulation · Inheritance · Abstraction · Polymorphism**

---

## Database Schema (3NF)

```
users           → user_id, username, hashed_password, salt, role, locked_until
products        → product_id, name, description, price, stock
carts           → cart_id, user_id (FK), product_id (FK), quantity
orders          → order_id, user_id (FK), order_date, status
order_items     → order_item_id, order_id (FK), product_id (FK), quantity, price
payments        → payment_id, order_id (FK), amount, payment_date, method
login_attempts  → attempt_id, user_id (FK), timestamp, success
security_logs   → log_id, user_id (FK), action, timestamp
```

---

## Features

**Customer**
- Register / Login with brute-force protection
- Product browsing with search + quick-view modal
- Cart with AJAX quantity stepper (no page reload)
- Checkout with Card / UPI / COD / Simulated payment
- Order history with status progress tracker + live filter
- Personal dashboard with order stats

**Admin**
- Sales dashboard — revenue trend chart, status doughnut, top products bar chart
- Product CRUD with server-side validation
- All users table with order count, spend, active/locked status
- One-click account unlock

---

## Project Structure

```
shopsphere-secure/
├── app.py                          # Routes + all security middleware
├── models.py                       # OOP classes
├── database.py                     # MySQL connection + schema init
├── seed_products.py                # Sample data seeder
├── check_cart.py                   # Debug utility
├── requirements.txt
└── templates/
    ├── base.html
    ├── home.html
    ├── login.html / register.html
    ├── products.html
    ├── cart.html
    ├── checkout.html
    ├── orders.html
    ├── dashboard.html
    ├── admin_dashboard.html
    ├── admin_products.html
    ├── admin_add_product.html
    ├── admin_edit_product.html
    └── admin_unlock_accounts.html
```

---

## Setup

```bash
# 1. Clone
git clone https://github.com/nirvaan8/shopsphere-secure
cd shopsphere-secure

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create MySQL database
mysql -u root -p
CREATE DATABASE shopsphere_secure;

# 4. Update credentials in database.py
# host, user, password

# 5. Run (auto-creates all tables)
python app.py

# 6. Seed sample products
python seed_products.py

# 7. Visit
http://localhost:5000
```

### Create Admin Account
```sql
-- After registering normally via /register:
UPDATE users SET role='admin' WHERE username='your_username';
```

---

## What to Set in Production

```python
# app.py
app.config['SESSION_COOKIE_SECURE'] = True   # HTTPS only
Talisman(app, force_https=True, strict_transport_security=True)
app.secret_key = os.environ.get('SECRET_KEY') # use env var, never hardcode
```

---

## Team

| Name | GitHub | LinkedIn |
|---|---|---|
| Nirvaan Katyal | [@nirvaan8](https://github.com/nirvaan8) | [linkedin.com/in/nirvaan-katyal-a8571928a](https://linkedin.com/in/nirvaan-katyal-a8571928a) |
| Mayur | — | — |

---

## License

Academic project — NIIT University, 2025.
