import sqlite3

def setup_database():
    # Connect to SQLite (this automatically creates 'database.db' if it doesn't exist)
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # 1. Create the Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # 2. Create the Credentials Table (The Vault)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Save changes and close the connection
    conn.commit()
    conn.close()
    
    print("Success: database.db created and tables initialized!")

if __name__ == '__main__':
    setup_database()