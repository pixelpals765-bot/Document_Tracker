import sqlite3
from werkzeug.security import generate_password_hash

DB_NAME = "document_tracker.db"


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def reorder_documents_table():
    """Rebuilds the documents table so program_title appears next to document_type."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check current structure
    cursor.execute("PRAGMA table_info(documents)")
    columns = [col[1] for col in cursor.fetchall()]

    desired_order = [
        "id", "control_number", "code", "document_type", "program_title",
        "send_to", "signatories", "file_path", "created_by", "created_at",
        "office", "status", "received_by", "received_date"
    ]

    # Skip rebuild if already correct
    if columns == desired_order:
        print("✅ 'documents' table already in correct column order.")
        conn.close()
        return

    print("🔧 Rebuilding 'documents' table to reorder columns...")

    # Rename old table
    cursor.execute("ALTER TABLE documents RENAME TO documents_old")

    # Recreate table in correct column order
    cursor.execute('''
        CREATE TABLE documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_number TEXT,
            code TEXT,
            document_type TEXT,
            program_title TEXT,
            send_to TEXT,
            signatories TEXT,
            file_path TEXT,
            created_by TEXT,
            created_at TEXT,
            office TEXT,
            status TEXT DEFAULT 'Pending',
            received_by TEXT,
            received_date TEXT
        )
    ''')

    # Copy data into new structure
    cursor.execute('''
        INSERT INTO documents (
            id, control_number, code, document_type, program_title,
            send_to, signatories, file_path, created_by, created_at,
            office, status, received_by, received_date
        )
        SELECT
            id, control_number, code, document_type, program_title,
            send_to, signatories, file_path, created_by, created_at,
            office, status, received_by, received_date
        FROM documents_old
    ''')

    # Drop the old table
    cursor.execute("DROP TABLE documents_old")

    conn.commit()
    conn.close()
    print("✅ 'documents' table reordered successfully.")


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # ------------------ USERS TABLE ------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            office TEXT,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
            status TEXT DEFAULT 'Offline'
        )
    ''')

    # ------------------ DOCUMENTS TABLE ------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_number TEXT,
            code TEXT,
            document_type TEXT,
            send_to TEXT,
            signatories TEXT,
            file_path TEXT,
            created_by TEXT,
            created_at TEXT,
            office TEXT,
            status TEXT DEFAULT 'Pending',
            received_by TEXT,
            received_date TEXT
        )
    ''')

    # ------------------ BACKUP DOCUMENTS TABLE ------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS backup_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_number TEXT,
            code TEXT,
            document_type TEXT,
            
            program_title TEXT,
            send_to TEXT,
            signatories TEXT,
            file_path TEXT,
            created_by TEXT,
            created_at TEXT,
            office TEXT,
            status TEXT DEFAULT 'Pending',
            received_by TEXT,
            received_date TEXT
        )
    ''')

    # ------------------ CONTROL NUMBERS TABLE ------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS control_numbers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_no TEXT UNIQUE NOT NULL,
            office TEXT NOT NULL,
            program TEXT NOT NULL,
            code TEXT NOT NULL,
            source_of_fund TEXT,
            assigned_by TEXT,
            assigned_date TEXT,
            received INTEGER DEFAULT 0,
            received_by TEXT,
            received_date TEXT
        )
    ''')

    # ------------------ SAVED DOCUMENTS TABLE ------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS saved_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_number TEXT,
            code TEXT,
            document_type TEXT,
            program_title TEXT,
            file_path TEXT,
            saved_by TEXT,
            office TEXT,
            saved_date TEXT
        )
    ''')

    # ------------------ AUDIT TRAIL TABLE ------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_trail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            office TEXT,
            action TEXT,
            datetime TEXT
        )
    ''')

    # ------------------------------------------------------------
    # 🆕 NEW TABLE: RETURNED DOCUMENTS
    # ------------------------------------------------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS returned_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_number TEXT,
            code TEXT,
            obr_number TEXT,        -- 🆕 added here
            document_type TEXT,
            program_title TEXT,
            returned_by TEXT,
            remarks TEXT,
            returned_date TEXT,
            status TEXT,
            received_by TEXT,
            received_date TEXT
        )
    ''')

    # ------------------------------------------------------------
    # 🆕 NEW TABLE: FOR OBLIGATION
    # ------------------------------------------------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS for_obligation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_number TEXT,
            code TEXT,
            document_type TEXT,
            program_title TEXT,
            obligation_request_no TEXT,
            file_path TEXT,                -- 🆕 added here
            date_obligated TEXT,
            obligated_by TEXT,
            status TEXT
        )
    ''')

    # ------------------------------------------------------------
    # 🆕 NEW TABLE: SIGNED DOCUMENTS
    # ------------------------------------------------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS signed_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_no TEXT,
            code TEXT,
            document_type TEXT,
            program_title TEXT,
            assigned_no TEXT,
            signed_by TEXT,
            signed_office TEXT,
            signed_date TEXT,
            remarks TEXT,
            received_by TEXT,
            received_office TEXT,
            received_date TEXT,
            status TEXT
        )
    ''')

    # ------------------------------------------------------------
    # 🆕 NEW TABLE: SIGNATORIES (for Setup → Signatories)
    # ------------------------------------------------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS signatories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            office TEXT,
            designation TEXT
        )
    ''')

    # ------------------ Ensure backward compatibility ------------------
    try:
        cursor.execute("ALTER TABLE control_numbers ADD COLUMN source_of_fund TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE control_numbers ADD COLUMN received INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE control_numbers ADD COLUMN received_by TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE control_numbers ADD COLUMN received_date TEXT")
    except sqlite3.OperationalError:
        pass

    # Add new columns to documents table
    try:
        cursor.execute("ALTER TABLE documents RENAME COLUMN document_name TO control_number")
    except sqlite3.OperationalError:
        pass

    new_doc_columns = [
        ("code", "TEXT"),
        ("office", "TEXT"),
        ("status", "TEXT DEFAULT 'Pending'"),
        ("received_by", "TEXT"),
        ("received_date", "TEXT")
    ]

    for col_name, col_type in new_doc_columns:
        try:
            cursor.execute(f"ALTER TABLE documents ADD COLUMN {col_name} {col_type}")
        except sqlite3.OperationalError:
            pass

    # Add program_title column
    try:
        cursor.execute("ALTER TABLE documents ADD COLUMN program_title TEXT")
    except sqlite3.OperationalError:
        pass

    # Add temp_password to users
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN temp_password TEXT")
    except sqlite3.OperationalError:
        pass

    # ------------------ Default admin account ------------------
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    admin = cursor.fetchone()

    if admin is None:
        hashed_admin_pw = generate_password_hash("admin123")
        cursor.execute("""
            INSERT INTO users (name, username, password, office, role, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("Administrator", "admin", hashed_admin_pw, "MMO", "admin", "Online"))
    else:
        cursor.execute("SELECT password FROM users WHERE username = 'admin'")
        admin_row = cursor.fetchone()
        admin_pw = admin_row["password"] if admin_row else None
        if not admin_pw or len(admin_pw) < 20:
            new_pw = generate_password_hash("admin123")
            cursor.execute("""
                UPDATE users
                SET password = ?, temp_password = NULL
                WHERE username = 'admin'
            """, (new_pw,))

    conn.commit()
    conn.close()

    # Reorder table after initialization
    reorder_documents_table()

    print("✅ Database initialized successfully.")


def reset_admin_password():
    """Manual password reset for admin account."""
    conn = get_db_connection()
    cursor = conn.cursor()

    new_pw = generate_password_hash("admin123")
    cursor.execute("""
        UPDATE users
        SET password = ?, temp_password = NULL
        WHERE username = 'admin'
    """, (new_pw,))
    conn.commit()
    conn.close()
    print("🔐 Admin password has been reset to default (admin123).")


if __name__ == "__main__":
    print("📦 Database Utility Menu")
    print("1. Initialize database")
    print("2. Reset admin password manually")
    choice = input("Choose an option (1 or 2): ")

    if choice == "1":
        init_db()
    elif choice == "2":
        reset_admin_password()
    else:
        print("❌ Invalid choice. Exiting...")
