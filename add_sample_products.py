import sqlite3

def add_sample_products():
    conn = sqlite3.connect('shopsphere.db')
    c = conn.cursor()

    # Sample data (you can edit/add more)
    samples = [
        ("Wireless Mouse", "Ergonomic 2.4GHz mouse with RGB lighting", 899.50, 45),
        ("USB-C Fast Charger 65W", "PD 3.0 fast charging adapter", 1499.00, 25),
        ("Bluetooth Earbuds Pro", "Noise-cancelling true wireless earphones", 2499.99, 18),
        ("Mechanical Gaming Keyboard", "RGB backlit with blue switches", 3499.00, 12),
        ("Adjustable Laptop Stand", "Aluminum foldable stand for better posture", 799.00, 35)
    ]

    # Insert multiple rows at once (efficient)
    c.executemany(
        "INSERT INTO products (name, description, price, stock) VALUES (?, ?, ?, ?)",
        samples
    )

    conn.commit()
    print(f"Added {c.rowcount} sample products successfully!")
    conn.close()

if __name__ == "__main__":
    add_sample_products()