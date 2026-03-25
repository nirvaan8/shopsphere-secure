import mysql.connector
from mysql.connector import Error


def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host='localhost',
            database='shopsphere_secure',
            user='shopuser',
            password='root1234'
        )
        conn.autocommit = False
        return conn
    except Error as e:
        print(f"MySQL connection error: {e}")
        return None


def init_db():
    conn = get_db_connection()
    if not conn:
        return

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id        INT AUTO_INCREMENT PRIMARY KEY,
            username       VARCHAR(50)  UNIQUE NOT NULL,
            hashed_password BLOB        NOT NULL,
            salt           BLOB         NOT NULL,
            role           ENUM('customer','admin') DEFAULT 'customer',
            locked_until   DATETIME     DEFAULT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            product_id  INT AUTO_INCREMENT PRIMARY KEY,
            name        VARCHAR(100) NOT NULL,
            description TEXT,
            price       DECIMAL(10,2) NOT NULL,
            stock       INT NOT NULL DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS carts (
            cart_id    INT AUTO_INCREMENT PRIMARY KEY,
            user_id    INT NOT NULL,
            product_id INT NOT NULL,
            quantity   INT NOT NULL DEFAULT 1,
            FOREIGN KEY (user_id)    REFERENCES users(user_id)    ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(product_id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            order_id   INT AUTO_INCREMENT PRIMARY KEY,
            user_id    INT NOT NULL,
            order_date DATETIME NOT NULL,
            status     ENUM('placed','paid','shipped','delivered','cancelled') DEFAULT 'placed',
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS order_items (
            order_item_id INT AUTO_INCREMENT PRIMARY KEY,
            order_id      INT NOT NULL,
            product_id    INT NOT NULL,
            quantity      INT          NOT NULL,
            price         DECIMAL(10,2) NOT NULL,
            FOREIGN KEY (order_id)    REFERENCES orders(order_id)      ON DELETE CASCADE,
            FOREIGN KEY (product_id)  REFERENCES products(product_id)  ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            payment_id   INT AUTO_INCREMENT PRIMARY KEY,
            order_id     INT NOT NULL,
            amount       DECIMAL(10,2) NOT NULL,
            payment_date DATETIME      NOT NULL,
            method       ENUM('card','upi','cod','simulated') DEFAULT 'simulated',
            FOREIGN KEY (order_id) REFERENCES orders(order_id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            attempt_id INT AUTO_INCREMENT PRIMARY KEY,
            user_id    INT      NOT NULL,
            timestamp  DATETIME NOT NULL,
            success    TINYINT(1) NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)

    # Required by PDF + used by models.py for security event logging
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            log_id    INT AUTO_INCREMENT PRIMARY KEY,
            user_id   INT  DEFAULT NULL,
            action    VARCHAR(255) NOT NULL,
            timestamp DATETIME     NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
        )
    """)

    conn.commit()
    cursor.close()
    conn.close()
    print("MySQL tables initialised.")