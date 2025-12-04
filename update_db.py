import sqlite3

DB_NAME = "document_tracker.db"

conn = sqlite3.connect(DB_NAME)
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'Offline';")
    conn.commit()
    print("✅ Column 'status' added successfully.")
except sqlite3.OperationalError as e:
    print(f"⚠️ Skipped: {e}")  # This will show if column already exists
finally:
    conn.close()
