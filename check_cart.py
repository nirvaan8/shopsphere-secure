"""
check_cart.py — quick debug utility
Prints all rows in the carts table joined with product names.
"""

from database import get_db_connection


def check_cart():
    conn = get_db_connection()
    if not conn:
        print("Could not connect to MySQL.")
        return

    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT c.cart_id, u.username, p.name AS product, c.quantity,
               (c.quantity * p.price) AS subtotal
        FROM carts c
        JOIN users    u ON c.user_id    = u.user_id
        JOIN products p ON c.product_id = p.product_id
        ORDER BY c.cart_id
    """)
    rows = cursor.fetchall()

    if not rows:
        print("Cart is empty.")
    else:
        print(f"{'ID':<6} {'User':<15} {'Product':<30} {'Qty':<5} {'Subtotal'}")
        print("-" * 65)
        for r in rows:
            print(f"{r['cart_id']:<6} {r['username']:<15} {r['product']:<30} {r['quantity']:<5} ₹{r['subtotal']:.2f}")

    cursor.close()
    conn.close()


if __name__ == "__main__":
    check_cart()