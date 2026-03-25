"""
seed_products.py — ShopSphere Secure
Inserts sample products into MySQL. Safe to run multiple times
(skips insert if products already exist).
"""

from database import get_db_connection


def seed_products():
    conn = get_db_connection()
    if not conn:
        print("Could not connect to MySQL.")
        return

    cursor = conn.cursor(dictionary=True)

    # Skip if data already present
    cursor.execute("SELECT COUNT(*) AS cnt FROM products")
    if cursor.fetchone()['cnt'] > 0:
        print("Products table already has data. Skipping seed.")
        cursor.close()
        conn.close()
        return

    products = [
        ("Wireless Mouse",           "Ergonomic wireless mouse with 16000 DPI",          899.00,  50),
        ("USB-C 65W Charger",        "Fast PD 3.0 charging adapter, foldable plug",      1499.00, 30),
        ("Noise-Cancelling Earbuds", "TWS earphones with ANC and 40h battery",           2499.00, 20),
        ("RGB Mechanical Keyboard",  "Blue switches, per-key RGB, aluminium frame",      3499.00, 15),
        ("Laptop Cooling Pad",       "Adjustable stand with 6 silent fans",               799.00, 40),
        ("Portable Power Bank",      "20000mAh, dual USB-C, 65W fast charging",          1999.00, 25),
        ("Webcam 1080p",             "Full HD webcam with built-in mic and privacy cover", 1299.00, 18),
        ("HDMI 2.1 Cable 2m",        "8K/60Hz, braided, gold-plated connectors",          349.00, 60),
    ]

    cursor.executemany(
        "INSERT INTO products (name, description, price, stock) VALUES (%s, %s, %s, %s)",
        products
    )
    conn.commit()
    print(f"Inserted {len(products)} products successfully.")
    cursor.close()
    conn.close()


if __name__ == "__main__":
    seed_products()