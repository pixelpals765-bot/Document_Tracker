import os
import sqlite3
from datetime import datetime

from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify,send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database import get_db_connection, init_db

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # 🔒 Change this to a strong secret key

# ✅ Add this line near the top (before any route)
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')

# Make sure the folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize DB
init_db()

DB_NAME = "document_tracker.db"


# ---------- Helper Functions ----------
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def is_admin():
    """Return True if the logged-in user is admin."""
    return 'role' in session and session['role'] == 'admin'


# ---------- Routes ----------

@app.route('/')
def index():
    return redirect(url_for('login'))


# ---------- AUDIT TRAIL FUNCTION ----------

@app.route('/audit_trail')
def audit_trail():
    return render_template('audit_trail.html')


def log_audit_action(username, office, action):
    conn = get_db_connection()
    conn.execute("""
        INSERT INTO audit_trail (username, office, action, datetime)
        VALUES (?, ?, ?, strftime('%Y-%m-%d %I:%M:%S %p', 'now', 'localtime'))
    """, (username, office, action))
    conn.commit()
    conn.close()


@app.route('/get_audit_trail')
def get_audit_trail():
    if 'username' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM audit_trail ORDER BY id DESC')
    logs = cursor.fetchall()
    conn.close()

    # Convert to list of dicts
    logs_list = [dict(log) for log in logs]

    return jsonify(logs_list)



# ---------- LOGIN ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            # Update user status to Online
            conn.execute("UPDATE users SET status = 'Online' WHERE id = ?", (user['id'],))
            conn.commit()
            conn.close()

            # Store session data
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['office'] = user['office']

            # 🟢 Log login action (with office)
            log_audit_action(user['username'], user['office'], f"{user['username']} Logged In")

            # Redirect by role and office
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['office'].upper() == 'MBO':
                return redirect(url_for('mbo_dashboard'))
            elif user['office'].upper() == 'MMO':
                return redirect(url_for('mmo_dashboard'))
            elif user['office'].upper() == 'OMACC':
                return redirect(url_for('omacc_dashboard'))
            elif user['office'].upper() == 'OMASS':
                return redirect(url_for('omass_dashboard'))
            elif user['office'].upper() == 'PESO':
                return redirect(url_for('peso_dashboard'))
            elif user['office'].upper() == 'HRMO':
                return redirect(url_for('hrmo_dashboard'))
            elif user['office'].upper() == 'GSO':
                return redirect(url_for('gso_dashboard'))
            elif user['office'].upper() == 'MSWDO':
                return redirect(url_for('mswdo_dashboard'))
            elif user['office'].upper() == 'MTO':
                return redirect(url_for('mto_dashboard'))
            elif user['office'].upper() == 'MCR':
                return redirect(url_for('mcr_dashboard'))
            elif user['office'].upper() == 'TOURISM':
                return redirect(url_for('municipal_tourism_dashboard'))
            elif user['office'].upper() == 'MPDO':
                return redirect(url_for('mpdo_dashboard'))
            elif user['office'].upper() == 'SB':
                return redirect(url_for('sb_dashboard'))
            elif user['office'].upper() == 'SSB':
                return redirect(url_for('ssb_dashboard'))
            elif user['office'].upper() == 'MHO':
                return redirect(url_for('mho_dashboard'))
            elif user['office'].upper() == 'MDRRMO':
                return redirect(url_for('mdrrmo_dashboard'))
            elif user['office'].upper() == 'OME':
                return redirect(url_for('ome_dashboard'))
            elif user['office'].upper() == 'PORT':
                return redirect(url_for('port_dashboard'))
            elif user['office'].upper() == 'MAO':
                return redirect(url_for('mao_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            conn.close()
            return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')



# ---------- DASHBOARDS ----------
@app.route('/admin')
def admin_dashboard():
    if is_admin():
        return render_template('admin_dashboard.html', username=session['username'])
    return redirect(url_for('login'))


@app.route('/user')
def user_dashboard():
    if 'role' in session and session['role'] == 'user':
        return render_template('user_dashboard.html', username=session['username'])
    return redirect(url_for('login'))


# ---------- ADD USER ----------
@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if not is_admin():
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']              # created user's username
        password = request.form['password']
        office = request.form['office']
        role = request.form['role']

        try:
            conn = sqlite3.connect(DB_NAME, timeout=10)
            cursor = conn.cursor()

            hashed_password = generate_password_hash(password)

            # Insert user
            cursor.execute("""
                INSERT INTO users (name, username, password, office, role)
                VALUES (?, ?, ?, ?, ?)
            """, (name, username, hashed_password, office, role))

            conn.commit()

            # -------------------------------
            # AUDIT TRAIL: Log user creation
            # -------------------------------
            admin_username = session.get("username")
            admin_office = session.get("office")

            action_text = f"{admin_username} created user {username}"

            # Format datetime to 12-hour format
            from datetime import datetime
            formatted_datetime = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")

            cursor.execute("""
                INSERT INTO audit_trail (action, datetime, username, office)
                VALUES (?, ?, ?, ?)
            """, (action_text, formatted_datetime, admin_username, admin_office))

            conn.commit()



        finally:
            conn.close()

        return redirect(url_for('view_users'))

    return redirect(url_for('view_users'))


# ---------- LOG OUT ----------
@app.route('/logout')
def logout():
    if 'user_id' in session:
        # Update user status
        conn = get_db_connection()
        conn.execute("UPDATE users SET status = 'Offline' WHERE id = ?", (session['user_id'],))
        conn.commit()
        conn.close()

        # 🟢 Log logout action (with office)
        log_audit_action(session['username'], session['office'], f"{session['username']} Logged Out")

    session.clear()
    return redirect(url_for('login'))




# ---------- VIEW USERS ----------
@app.route('/view_users')
def view_users():
    if not is_admin():
        return redirect(url_for('login'))

    conn = get_db()
    cur = conn.cursor()
    # No more temp_password or reset logic
    cur.execute("SELECT id, name, username, office, password, status FROM users")
    users = cur.fetchall()
    conn.close()

    return render_template('view_users.html', users=users)


# ---------- EDIT USERS ----------
@app.route('/edit_users')
def edit_users():
    if not is_admin():
        return redirect(url_for('login'))

    q = request.args.get('q', '').strip()
    conn = get_db()
    cur = conn.cursor()

    # Always fetch all users to display them all
    cur.execute("SELECT * FROM users")
    all_users = cur.fetchall()
    message = None
    highlight_id = None

    # If there’s a search term, find a matching user to highlight
    if q:
        cur.execute("SELECT * FROM users WHERE name LIKE ? OR username LIKE ?", (f'%{q}%', f'%{q}%'))
        matched_user = cur.fetchone()
        if matched_user:
            highlight_id = matched_user['id']
        else:
            message = "User not found."

    conn.close()
    return render_template('edit_users.html', users=all_users, message=message, highlight_id=highlight_id)


# ---------- UPDATE USER ----------
@app.route('/update_user', methods=['POST'])
def update_user():
    if not is_admin():
        return redirect(url_for('login'))

    admin_username = session.get("username")
    admin_office = session.get("office")

    user_id = request.form['user_id']
    new_name = request.form['name']
    new_username = request.form['username']
    new_office = request.form['office']
    new_password = request.form['password']

    conn = get_db()
    cur = conn.cursor()

    # --- Get existing user before updating ---
    cur.execute("SELECT name, username, office FROM users WHERE id=?", (user_id,))
    old = cur.fetchone()

    if not old:
        conn.close()
        flash("❌ User not found!")
        return redirect(url_for('edit_users'))

    old_name, old_username, old_office = old['name'], old['username'], old['office']

    # Track which fields changed
    changes = []

    if new_name != old_name:
        changes.append("Name")
    if new_username != old_username:
        changes.append("Username")
    if new_office != old_office:
        changes.append("Office/Department")
    if new_password.strip():
        changes.append("Password")

    # --- Perform the update ---
    if new_password.strip():
        from werkzeug.security import generate_password_hash
        hashed = generate_password_hash(new_password)
        cur.execute("""
            UPDATE users 
            SET name=?, username=?, office=?, password=? 
            WHERE id=?
        """, (new_name, new_username, new_office, hashed, user_id))
    else:
        cur.execute("""
            UPDATE users 
            SET name=?, username=?, office=? 
            WHERE id=?
        """, (new_name, new_username, new_office, user_id))

    conn.commit()

    # --- Insert into audit_trail ---
    if changes:
        changed_fields = ", ".join(changes)

        # action message example: "admin edited gray's Name"
        action_message = f"{admin_username} edited {old_username}'s {changed_fields}"

        # Store datetime in 12-hour format
        dt = datetime.now().strftime("%Y-%m-%d %I:%M %p")

        cur.execute("""
            INSERT INTO audit_trail (username, office, action, datetime)
            VALUES (?, ?, ?, ?)
        """, (admin_username, admin_office, action_message, dt))

        conn.commit()

    conn.close()

    flash("✅ User details updated successfully!")
    return redirect(url_for('edit_users'))

# ---------- DELETE USER ----------
@app.route('/delete_user', methods=['POST'])
def delete_user():
    if not is_admin():
        return redirect(url_for('login'))

    admin_username = session.get("username")
    admin_office = session.get("office")

    user_id = request.form['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()

    # --- Get user info before deleting ---
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        flash("User not found!", "error")
        return redirect(url_for('edit_users'))

    deleted_username = user['username']

    # --- Delete the user ---
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()

    # --- Prepare audit message ---
    action_message = f"{admin_username} deleted {deleted_username}'s Account"
    dt = datetime.now().strftime("%Y-%m-%d %I:%M %p")  # 12-hour format

    # --- Insert audit trail record ---
    cursor.execute("""
        INSERT INTO audit_trail (username, office, action, datetime)
        VALUES (?, ?, ?, ?)
    """, (admin_username, admin_office, action_message, dt))

    conn.commit()
    conn.close()

    flash("User deleted successfully!", "success")
    return redirect(url_for('edit_users'))


# ---------- VIEW/AUDIT TRAIL /ASSIGN CTRL NO----------
@app.route('/view_documents')
def view_documents():
    # render_template('view_documents.html')
    pass




# ---------- ASSIGN CONTROL NUMBER WITH AUDIT TRAIL ----------
@app.route("/assign_control_no", methods=["POST"])
def assign_control_no():
    control_no = request.form["control_no"].strip()
    assigned_office = request.form["office"].strip()  # recipient office
    program = request.form["program"].strip()
    code = request.form["code"].strip()
    source_of_fund = request.form["source_of_fund"].strip()
    assigned_by = "admin"  # or session["username"]
    admin_office = "MMO"   # admin's office
    assigned_date = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")  # 12-hour format

    conn = get_db()
    cur = conn.cursor()

    try:
        # Insert control number
        cur.execute("""
            INSERT INTO control_numbers 
            (control_no, office, program, code, source_of_fund, assigned_by, assigned_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (control_no, assigned_office, program, code, source_of_fund, assigned_by, assigned_date))

        # Insert into audit trail
        action_text = f"{assigned_by} Issued Control Number {control_no} to {assigned_office}"
        cur.execute("""
            INSERT INTO audit_trail (username, office, action, datetime)
            VALUES (?, ?, ?, ?)
        """, (assigned_by, admin_office, action_text, assigned_date))

        conn.commit()
        flash("✅ Control number assigned successfully!", "success")
    except sqlite3.IntegrityError:
        flash("❌ Control number already exists. Please use another one.", "error")
    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        abort(404)

@app.route('/download/<filename>')
def download_file(filename):
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)




# ---------- MBO DASHBOARD ----------m
@app.route('/mbo_dashboard')
def mbo_dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()

    # If you still need the control_numbers table listing, keep this.
    # Otherwise you can remove this block.
    cur.execute("""
        SELECT * FROM control_numbers
        WHERE office = 'MBO'
        ORDER BY assigned_date DESC
    """)
    mbo_control_numbers = cur.fetchall()

    # --- Counts coming from control_numbers (optional) ---
    cur.execute("""
        SELECT COUNT(*) FROM control_numbers
        WHERE office = 'MBO' AND (received = 0 OR received IS NULL)
    """)
    pending_control_numbers = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*) FROM control_numbers
        WHERE office = 'MBO' AND received = 1
    """)
    completed_control_numbers = cur.fetchone()[0]

    # --- NEW: counts coming from documents table (this is what /receive_document updates) ---
    # Count documents sent to MBO that are pending (status NULL or 'Pending')
    cur.execute("""
        SELECT COUNT(*) FROM documents
        WHERE send_to = 'MBO' AND (status IS NULL OR status = 'Pending')
    """)
    pending_docs = cur.fetchone()[0]

    # Count documents that were received by MBO (status = 'Received')
    cur.execute("""
        SELECT COUNT(*) FROM documents
        WHERE send_to = 'MBO' AND status = 'Received'
    """)
    received_docs = cur.fetchone()[0]

    # Alternative received count using received_date (uncomment to use instead)
    # cur.execute("""
    #     SELECT COUNT(*) FROM documents
    #     WHERE send_to = 'MBO' AND received_date IS NOT NULL
    # """)
    # received_docs = cur.fetchone()[0]

    # Total documents for MBO (pending + received)
    total_docs_for_mbo = pending_docs + received_docs

    conn.close()

    return render_template(
        'mbo_dashboard.html',
        username=session.get('username'),
        # control_numbers (optional)
        issued_docs_mbo=mbo_control_numbers,
        pending_control_numbers_mbo=pending_control_numbers,
        completed_control_numbers_mbo=completed_control_numbers,

        # documents table counts (used for the Received Documents card)
        total_docs_mbo=total_docs_for_mbo,
        pending_docs_mbo=pending_docs,
        received_docs_mbo=received_docs,

        # if you still need a separate issued control no count from control_numbers:
        issued_count_mbo=pending_control_numbers
    )




# ---------- GET UPDATED ISSUED COUNT (for AJAX refresh) ----------
@app.route("/get_issued_count_mbo", methods=["GET"])
def get_issued_count_mbo():
    if "username" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*) FROM control_numbers
        WHERE office = 'MBO' AND (received = 0 OR received IS NULL)
    """)
    issued_control_no = cur.fetchone()[0]

    conn.close()
    return jsonify({"success": True, "issued_count": issued_control_no})

@app.route("/get_mbo_received_count")
def get_mbo_received_count():
    from database import get_db_connection
    conn = get_db_connection()
    count = conn.execute(
        "SELECT COUNT(*) FROM documents WHERE received_by IS NOT NULL AND status = 'Received'"
    ).fetchone()[0]
    conn.close()
    return jsonify({"count": count})



# ---------- ISSUED CONTROL NUMBERS ----------
@app.route('/issued_control_numbers_mbo')
def issued_control_numbers_mbo():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            id, 
            control_no, 
            program, 
            code, 
            source_of_fund,
            assigned_date, 
            received, 
            received_date, 
            received_by
        FROM control_numbers
        WHERE office = 'MBO'
        ORDER BY assigned_date DESC
    """)

    rows = cur.fetchall()
    conn.close()

    issued = [
        {
            "id": row["id"],
            "control_no": row["control_no"],
            "program": row["program"],
            "code": row["code"],
            "source_of_fund": row["source_of_fund"],
            "assigned_date": row["assigned_date"],
            "received": row["received"],
            "received_date": row["received_date"],
            "received_by": row["received_by"],
        }
        for row in rows
    ]

    return jsonify(issued)


# ---------- RECEIVE CONTROL NUMBER (API — Called from JS) ----------
@app.route("/receive_control_number_mbo", methods=["POST"])
def receive_control_number_mbo():
    data = request.get_json()
    control_no = data.get("control_no")
    received_by = data.get("received_by")  # Username of the receiving user

    if not control_no or not received_by:
        return jsonify({"success": False, "error": "Missing data"})

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Update received status
        timestamp = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")  # 12-hour format
        cur.execute("""
            UPDATE control_numbers
            SET received = 1,
                received_date = ?,
                received_by = ?
            WHERE control_no = ?
        """, (timestamp, received_by, control_no))

        # Fetch who assigned the control number
        cur.execute("SELECT assigned_by FROM control_numbers WHERE control_no = ?", (control_no,))
        assigned_by_row = cur.fetchone()
        assigned_by = assigned_by_row["assigned_by"] if assigned_by_row else "admin"

        # Insert into audit trail
        action_text = f"{received_by} Received Issued Control Number {control_no} Issued by {assigned_by}"

        cur.execute("""
            INSERT INTO audit_trail (username, office, action, datetime)
            VALUES (?, ?, ?, ?)
        """, (received_by, "MBO", action_text, timestamp))

        conn.commit()
        return jsonify({"success": True})

    except Exception as e:
        print("Error updating received control number (MBO):", e)
        return jsonify({"success": False, "error": str(e)})

    finally:
        conn.close()




# ---------- RECEIVE DOCUMENT (Legacy - kept for redirect use if needed) ----------
@app.route('/receive_document_mbo/<control_no>', methods=['POST'])
def receive_document_mbo(control_no):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE control_numbers
        SET received = 1
        WHERE control_no = ?
    """, (control_no,))
    conn.commit()
    conn.close()

    flash(f"Control No. {control_no} marked as received.", "success")
    return redirect(url_for('mbo_dashboard'))


# ---------- RECEIVED CONTROL NUMBERS ----------
@app.route('/received_control_numbers_mbo')
def received_control_numbers_mbo():
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT 
                id, 
                control_no, 
                program, 
                code, 
                source_of_fund,
                assigned_date, 
                received_date, 
                received_by
            FROM control_numbers
            WHERE office = 'MBO' AND received = 1
            ORDER BY received_date DESC
        """)

        rows = cur.fetchall()
        conn.close()

        data = [
            {
                "id": row["id"],
                "control_no": row["control_no"],
                "program": row["program"],
                "code": row["code"],
                "source_of_fund": row["source_of_fund"],
                "assigned_date": row["assigned_date"],
                "received_date": row["received_date"],
                "received_by": row["received_by"]
            }
            for row in rows
        ]

        return jsonify(data)

    except Exception as e:
        print("Error fetching received control numbers (MBO):", e)
        return jsonify({'error': str(e)}), 500


# ---------- ADD DOCUMENT (MBO) ----------
@app.route("/add_document_mbo", methods=["POST"])
def add_document_mbo():
    if "username" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    if "document_file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"})

    file = request.files["document_file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No file selected"})

    filename = secure_filename(file.filename)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    # 🔹 Get combined value from dropdown
    selected_value = request.form.get("control_number")
    if selected_value and "|" in selected_value:
        code, control_number = selected_value.split("|", 1)
    else:
        code = None
        control_number = selected_value

    document_type = request.form.get("document_type")
    send_to = request.form.get("send_to")
    signatories = request.form.get("signatories")

    username = session.get("username")
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    cursor = conn.cursor()

    # 🔹 Get the user's office
    cursor.execute("SELECT office FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    office = user["office"] if user else "Unknown"

    # 🔹 Fetch the program title from control_numbers table
    cursor.execute("SELECT program FROM control_numbers WHERE control_no = ?", (control_number,))
    control_row = cursor.fetchone()
    program_title = control_row["program"] if control_row else None

    # 🔹 Insert into the documents table including program_title
    cursor.execute("""
        INSERT INTO documents 
            (control_number, code, document_type, send_to, signatories, file_path, created_by, created_at, office, program_title)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (control_number, code, document_type, send_to, signatories, file_path, username, created_at, office, program_title))

    conn.commit()
    conn.close()

    return jsonify({"success": True})


# ---------- GET RECEIVED CONTROL NUMBERS (for dropdown) ----------
@app.route("/get_received_control_numbers_mbo")
def get_received_control_numbers_mbo():
    if "username" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    username = session["username"]

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT code, control_no, program
        FROM control_numbers
        WHERE received_by = ? AND received_date IS NOT NULL
        ORDER BY received_date DESC
    """, (username,))

    rows = cursor.fetchall()
    conn.close()

    data = []
    for row in rows:
        code = row["code"] or ""
        control_no = row["control_no"] or ""
        program = row["program"] or ""
        label = f"{code} - {control_no} - {program}"
        value = f"{code}|{control_no}"
        data.append({"label": label, "value": value})

    return jsonify({"success": True, "data": data})



@app.route('/mbo_documents')
def mbo_documents():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    documents = conn.execute('''
        SELECT id, control_number, code, document_type, program_title,
               created_by, office, status
        FROM documents
        WHERE send_to = 'MBO'
          AND (status IS NULL OR status = 'Pending')
        ORDER BY id DESC
    ''').fetchall()
    conn.close()

    return jsonify([dict(row) for row in documents])


@app.route("/received_documents")
def received_documents():
    return render_template("received_documents.html")

@app.route('/for_signature')
def for_signature():
    return render_template("for_signature.html")

@app.route("/count_for_signature")
def count_for_signature():
    if "office" not in session:
        return jsonify({"count": 0})

    office = session["office"]

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    row = cursor.execute("""
        SELECT COUNT(*) AS total
        FROM documents
        WHERE send_to = ?
          AND document_type != 'Obligation Request'
          AND (status IS NULL OR status != 'Returned')
    """, (office,)).fetchone()

    conn.close()

    return jsonify({"count": row["total"]})




# ----------- RECEIVED DOCUMENTS (MBO) -------------
@app.route('/receive_document/<int:id>', methods=['POST'])
def receive_document(id):
    if "username" not in session or "office" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    username = session["username"]
    office = session["office"]
    received_by = f"{username} - {office}"
    received_date = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Fetch all needed document fields
        doc = cursor.execute("""
            SELECT control_number, code, document_type, program_title, created_by, office
            FROM documents
            WHERE id = ?
        """, (id,)).fetchone()

        if not doc:
            conn.close()
            return jsonify({"success": False, "error": "Document not found"})

        # UPDATE documents table as received
        cursor.execute("""
            UPDATE documents
            SET status = ?, received_by = ?, received_date = ?
            WHERE id = ?
        """, ("Received", received_by, received_date, id))

        # --------------------------------------------------------
        # ✅ INSERT INTO for_obligation IF DOCUMENT TYPE MATCHES
        # --------------------------------------------------------
        if doc["document_type"] == "Obligation Request":
            cursor.execute("""
                INSERT INTO for_obligation (
                    control_number, code, document_type, program_title,
                    obligation_request_no, date_obligated, obligated_by
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                doc["control_number"],
                doc["code"],
                doc["document_type"],
                doc["program_title"],
                None,       # obligation_request_no
                None,       # date_obligated
                None        # obligated_by
            ))

        # --------------------------------------------------------
        # AUDIT TRAIL
        # --------------------------------------------------------
        action_text = (
            f"{username} Received {doc['code']} {doc['control_number']} "
            f"{doc['document_type']} sent by {doc['created_by']} - {doc['office']}"
        )

        audit_time = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")

        cursor.execute("""
            INSERT INTO audit_trail (username, office, action, datetime)
            VALUES (?, ?, ?, ?)
        """, (username, office, action_text, audit_time))

        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": "Document received successfully!"})

    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"success": False, "error": str(e)})



# ---------- FOR OBLIGATION ----------
@app.route('/for_obligation')
def for_obligation_page():
    return render_template('for_obligation.html')

# ---------- COUNT FOR OBLIGATION ----------
@app.route("/count_for_obligation")
def count_for_obligation():
    conn = get_db_connection()
    cursor = conn.cursor()

    count = cursor.execute("""
        SELECT COUNT(*) AS total
        FROM for_obligation
        WHERE status IS NULL
           OR status = ''
           OR status = 'Pending'
    """).fetchone()["total"]

    conn.close()
    return jsonify({"count": count})


# ---------- FOR OBLIGATION TABLE----------
@app.route("/get_for_obligation")
def get_for_obligation():
    conn = get_db_connection()
    cursor = conn.cursor()

    rows = cursor.execute("""
        SELECT id, control_number, code, document_type, program_title
        FROM for_obligation
        WHERE status IS NULL 
           OR status = ''
           OR status = 'Pending'
    """).fetchall()

    conn.close()

    return jsonify([dict(row) for row in rows])

# ---------- FOR OBLIGATION MODAL ----------
@app.route("/get_single_obligation/<int:doc_id>")
def get_single_obligation(doc_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    row = cursor.execute("""
        SELECT id, control_number, code, document_type, program_title
        FROM for_obligation
        WHERE id = ?
    """, (doc_id,)).fetchone()

    conn.close()

    if row:
        return jsonify({"success": True, "doc": dict(row)})
    else:
        return jsonify({"success": False, "error": "Document not found"}), 404


@app.route("/save_obligation", methods=["POST"])
def save_obligation():
    data = request.json

    doc_id = data.get("doc_id")
    obligation_no = data.get("obligation_no")

    if "username" not in session or "office" not in session:
        return jsonify({"success": False, "error": "User not logged in"}), 401

    username = session["username"]
    office = session["office"]
    obligated_by = f"{username} - {office}"
    date_obligated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE for_obligation
            SET obligation_request_no = ?,
                date_obligated = ?,
                obligated_by = ?,
                status = 'Obligated'
            WHERE id = ?
        """, (obligation_no, date_obligated, obligated_by, doc_id))

        conn.commit()
        conn.close()

        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# ---------- RECEIVED DOCUMENTS LIST (for MBO Modal) ----------
@app.route('/mbo_received_documents')
def mbo_received_documents():
    if 'username' not in session:
        return jsonify([])

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('''
        SELECT 
            id, 
            control_number, 
            code, 
            program_title, 
            document_type, 
            file_path,
            received_by
        FROM documents
        WHERE send_to = 'MBO' AND status = 'Received'
        ORDER BY received_date DESC
    ''')
    docs = cursor.fetchall()
    conn.close()

    result = []
    for row in docs:
        file_path = row["file_path"] or ""
        # Extract just the filename (e.g. "eBPILS-001.pdf" from "uploads\\eBPILS-001.pdf")
        filename = os.path.basename(file_path.replace("\\", "/")) if file_path else ""

        result.append({
            "id": row["id"],
            "control_number": row["control_number"],
            "code": row["code"],
            "program_title": row["program_title"],
            "document_type": row["document_type"],
            "filename": filename,
            "received_by": row["received_by"] or "-"
        })

    return jsonify(result)


@app.route("/save_document", methods=["POST"])
def save_document():
    if "username" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json()
    control_number = data.get("control_number")
    code = data.get("code")
    document_type = data.get("document_type")
    program_title = data.get("program_title")
    file_path = data.get("file_path")

    saved_by = session["username"]
    office = session.get("office", "MBO")
    saved_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build full code (the one being saved)
    full_code = f"{code}-{control_number}"

    conn = get_db_connection()
    cursor = conn.cursor()

    # ✅ FIXED DUPLICATE CHECK: use full_code instead of code
    cursor.execute("""
        SELECT id 
        FROM saved_documents 
        WHERE code = ? AND control_number = ? AND document_type = ?
    """, (full_code, control_number, document_type))

    existing = cursor.fetchone()

    if existing:
        conn.close()
        return jsonify({
            "success": False,
            "error": f"Document {full_code} ({document_type}) already saved."
        }), 400

    # Save document
    cursor.execute("""
        INSERT INTO saved_documents (
            control_number, 
            code, 
            document_type,
            program_title, 
            file_path, 
            saved_by, 
            office, 
            saved_date
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        control_number,
        full_code,
        document_type,
        program_title,
        file_path,
        saved_by,
        office,
        saved_date
    ))

    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": f"Document {full_code} saved successfully!"})


@app.route('/return_document/<int:doc_id>', methods=['POST'])
def return_document(doc_id):
    if 'username' not in session or 'office' not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.get_json()
    remarks = data.get("reason", "").strip()

    username = session['username']
    office = session['office']
    returned_by = f"{username} - {office}"
    returned_date = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Fetch original document info
    cursor.execute("SELECT * FROM documents WHERE id = ?", (doc_id,))
    doc = cursor.fetchone()

    if not doc:
        conn.close()
        return jsonify({"success": False, "error": "Document not found"})

    # Insert into returned_documents
    cursor.execute("""
        INSERT INTO returned_documents 
            (control_number, code, document_type, program_title, returned_by, remarks, returned_date, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        doc["control_number"], doc["code"], doc["document_type"],
        doc["program_title"], returned_by, remarks, returned_date, "Returned"
    ))

    # Update main documents table
    cursor.execute("""
        UPDATE documents
        SET status = 'Returned'
        WHERE id = ?
    """, (doc_id,))

    # 🔥 ALSO UPDATE for_obligation table (fixes your issue)
    cursor.execute("""
        UPDATE for_obligation
        SET status = 'RETURNED'
        WHERE id = ?
    """, (doc_id,))

    # Audit trail
    action_text = (
        f"{username} Returned {doc['code']} {doc['control_number']} "
        f"{doc['document_type']} to {doc['office']} - {remarks}"
    )
    audit_time = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")

    cursor.execute("""
        INSERT INTO audit_trail (username, office, action, datetime)
        VALUES (?, ?, ?, ?)
    """, (username, office, action_text, audit_time))

    conn.commit()
    conn.close()

    return jsonify({"success": True})



















# ---------- MMO DASHBOARD ----------
@app.route('/mmo_dashboard')
def mmo_dashboard():
    if 'office' in session and session['office'].upper() == 'MMO':
        return render_template('mmo_dashboard.html', username=session['username'])
    return redirect(url_for('login'))

# ---------- OMAcc DASHBOARD ----------
@app.route('/omacc_dashboard')
def omacc_dashboard():
    if 'office' in session and session['office'].upper() == 'OMACC':
        return render_template('omacc_dashboard.html', username=session['username'])
    return redirect(url_for('login'))

# ---------- PESO DASHBOARD ----------
@app.route('/peso_dashboard')
def peso_dashboard():
    if 'office' in session and session['office'].upper() == 'PESO':
        return render_template('peso_dashboard.html', username=session['username'])
    return redirect(url_for('login'))


# ---------- HRMO DASHBOARD ----------
@app.route('/hrmo_dashboard')
def hrmo_dashboard():
    if 'office' in session and session['office'].upper() == 'HRMO':
        return render_template('hrmo_dashboard.html', username=session['username'])
    return redirect(url_for('login'))

# ---------- GSO DASHBOARD ----------
@app.route('/gso_dashboard')
def gso_dashboard():
    if 'office' in session and session['office'].upper() == 'GSO':
        return render_template('gso_dashboard.html', username=session['username'])
    return redirect(url_for('login'))


# ---------- MSWDO DASHBOARD ----------
@app.route('/mswdo_dashboard')
def mswdo_dashboard():
    if 'office' in session and session['office'].upper() == 'MSWDO':
        return render_template('mswdo_dashboard.html', username=session['username'])
    return redirect(url_for('login'))

# ---------- OMAss DASHBOARD ----------
@app.route('/omass_dashboard')
def omass_dashboard():
    if 'office' in session and session['office'].upper() == 'OMASS':
        return render_template('omass_dashboard.html', username=session['username'])
    return redirect(url_for('login'))

# ---------- MTO DASHBOARD ----------
@app.route('/mto_dashboard')
def mto_dashboard():
    if 'office' in session and session['office'].upper() == 'MTO':
        return render_template('mto_dashboard.html', username=session['username'])
    return redirect(url_for('login'))

# ---------- MCR DASHBOARD ----------
@app.route('/mcr_dashboard')
def mcr_dashboard():
    if 'office' in session and session['office'].upper() == 'MCR':
        return render_template('mcr_dashboard.html', username=session['username'])
    return redirect(url_for('login'))

# ---------- TOURISM DASHBOARD ----------
@app.route('/municipal_tourism_dashboard')
def municipal_tourism_dashboard():
    if 'office' in session and session['office'].upper() == 'TOURISM':
        return render_template('municipal_tourism_dashboard.html', username=session['username'])
    return redirect(url_for('login'))


# ---------- MPDO DASHBOARD ----------
@app.route('/mpdo_dashboard')
def mpdo_dashboard():
    if 'office' in session and session['office'].upper() == 'MPDO':
        return render_template('mpdo_dashboard.html', username=session['username'])
    return redirect(url_for('login'))


# ---------- SB DASHBOARD ----------
@app.route('/sb_dashboard')
def sb_dashboard():
    if 'office' in session and session['office'].upper() == 'SB':
        return render_template('sb_dashboard.html', username=session['username'])
    return redirect(url_for('login'))

# ---------- SSB DASHBOARD ----------
@app.route('/ssb_dashboard')
def ssb_dashboard():
    if 'office' in session and session['office'].upper() == 'SSB':
        return render_template('ssb_dashboard.html', username=session['username'])
    return redirect(url_for('login'))

# ---------- MHO DASHBOARD ----------
@app.route('/mho_dashboard')
def mho_dashboard():
    if 'office' in session and session['office'].upper() == 'MHO':
        return render_template('mho_dashboard.html', username=session['username'])
    return redirect(url_for('login'))


# ---------- MDRRMO DASHBOARD ----------
@app.route('/mdrrmo_dashboard')
def mdrrmo_dashboard():
    if 'office' in session and session['office'].upper() == 'MDRRMO':
        return render_template('mdrrmo_dashboard.html', username=session['username'])
    return redirect(url_for('login'))


# ---------- OME DASHBOARD ----------
@app.route('/ome_dashboard')
def ome_dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()

    # 1️⃣ All control numbers assigned to OME (for table display)
    cur.execute("""
        SELECT * FROM control_numbers
        WHERE office = 'OME'
        ORDER BY assigned_date DESC
    """)
    ome_docs = cur.fetchall()

    # 2️⃣ Count pending (not yet received)
    cur.execute("""
        SELECT COUNT(*) FROM control_numbers
        WHERE office = 'OME' AND (received = 0 OR received IS NULL)
    """)
    pending_docs = cur.fetchone()[0]

    # 3️⃣ Count completed (already received)
    cur.execute("""
        SELECT COUNT(*) FROM control_numbers
        WHERE office = 'OME' AND received = 1
    """)
    completed_docs = cur.fetchone()[0]

    # 4️⃣ Count how many control numbers have been issued to OME but are still NOT received
    cur.execute("""
        SELECT COUNT(*) FROM control_numbers
        WHERE office = 'OME' AND (received = 0 OR received IS NULL)
    """)
    issued_control_no = cur.fetchone()[0]

    conn.close()

    # 5️⃣ Render to dashboard template
    return render_template(
        'ome_dashboard.html',
        username=session.get('username'),
        total_docs_ome=pending_docs + completed_docs,
        pending_docs_ome=pending_docs,
        completed_docs_ome=completed_docs,
        issued_count_ome=issued_control_no,
        issued_docs_ome=ome_docs
    )



# ---------- GET UPDATED ISSUED COUNT (for AJAX refresh) ----------
@app.route("/get_issued_count_ome", methods=["GET"])
def get_issued_count_ome():
    if "username" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*) FROM control_numbers
        WHERE office = 'OME' AND (received = 0 OR received IS NULL)
    """)
    issued_control_no = cur.fetchone()[0]

    conn.close()
    return jsonify({"success": True, "issued_count": issued_control_no})


# ---------- ISSUED CONTROL NUMBERS ----------
@app.route('/issued_control_numbers_ome')
def issued_control_numbers_ome():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            id, 
            control_no, 
            program, 
            code, 
            source_of_fund,
            assigned_date, 
            received, 
            received_date, 
            received_by
        FROM control_numbers
        WHERE office = 'OME'
        ORDER BY assigned_date DESC
    """)

    rows = cur.fetchall()
    conn.close()

    issued = [
        {
            "id": row["id"],
            "control_no": row["control_no"],
            "program": row["program"],
            "code": row["code"],
            "source_of_fund": row["source_of_fund"],
            "assigned_date": row["assigned_date"],
            "received": row["received"],
            "received_date": row["received_date"],
            "received_by": row["received_by"],
        }
        for row in rows
    ]

    return jsonify(issued)


# ---------- RECEIVE CONTROL NUMBER (API — Called from JS) ----------
@app.route("/receive_control_number_ome", methods=["POST"])
def receive_control_number_ome():
    data = request.get_json()
    control_no = data.get("control_no")
    received_by = data.get("received_by")

    if not control_no or not received_by:
        return jsonify({"success": False, "error": "Missing data"})

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("""
            UPDATE control_numbers
            SET received = 1,
                received_date = ?,
                received_by = ?
            WHERE control_no = ?
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), received_by, control_no))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        print("Error updating received control number (OME):", e)
        return jsonify({"success": False, "error": str(e)})
    finally:
        conn.close()


# ---------- RECEIVE CONTROL NUMBER (LEGACY - with ID parameter) ----------
@app.route('/receive_control_number_ome/<int:id>', methods=['POST'])
def receive_control_number_ome_by_id(id):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    username = session['username']
    received_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE control_numbers
        SET received = 1,
            received_date = ?,
            received_by = ?
        WHERE id = ?
    ''', (received_date, username, id))

    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'received_date': received_date,
        'received_by': username
    })


# ---------- RECEIVE DOCUMENT (Legacy - kept for redirect use if needed) ----------
@app.route('/receive_document_ome/<control_no>', methods=['POST'])
def receive_document_ome(control_no):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE control_numbers
        SET received = 1
        WHERE control_no = ?
    """, (control_no,))
    conn.commit()
    conn.close()

    flash(f"Control No. {control_no} marked as received.", "success")
    return redirect(url_for('ome_dashboard'))


# ---------- RECEIVED CONTROL NUMBERS ----------
@app.route('/received_control_numbers_ome')
def received_control_numbers_ome():
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
            SELECT 
                id, 
                control_no, 
                program, 
                code, 
                source_of_fund,
                assigned_date, 
                received_date, 
                received_by
            FROM control_numbers
            WHERE office = 'OME' AND received = 1
            ORDER BY received_date DESC
        """)

        rows = cur.fetchall()
        conn.close()

        data = [
            {
                "id": row["id"],
                "control_no": row["control_no"],
                "program": row["program"],
                "code": row["code"],
                "source_of_fund": row["source_of_fund"],
                "assigned_date": row["assigned_date"],
                "received_date": row["received_date"],
                "received_by": row["received_by"]
            }
            for row in rows
        ]

        return jsonify(data)

    except Exception as e:
        print("Error fetching received control numbers (OME):", e)
        return jsonify({'error': str(e)}), 500


# ---------- ADD DOCUMENT (OME) ----------
# ---------- ADD DOCUMENT (OME) ----------
@app.route("/add_document_ome", methods=["POST"])
def add_document_ome():
    if "username" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    if "document_file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"})

    file = request.files["document_file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No file selected"})

    filename = secure_filename(file.filename)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    # 🔹 Get combined value from dropdown
    selected_value = request.form.get("control_number")
    if selected_value and "|" in selected_value:
        code, control_number = selected_value.split("|", 1)
    else:
        code = None
        control_number = selected_value

    document_type = request.form.get("document_type")
    send_to = request.form.get("send_to")
    signatories = request.form.get("signatories")

    username = session.get("username")
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    cursor = conn.cursor()

    # 🔹 Get the user's office
    cursor.execute("SELECT office FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    office = user["office"] if user else "Unknown"

    # 🔹 Fetch the program title from control_numbers table
    cursor.execute("SELECT program FROM control_numbers WHERE control_no = ?", (control_number,))
    control_row = cursor.fetchone()
    program_title = control_row["program"] if control_row else None

    # 🔹 Insert into the documents table including program_title
    cursor.execute("""
        INSERT INTO documents 
            (control_number, code, document_type, send_to, signatories, file_path, created_by, created_at, office, program_title)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (control_number, code, document_type, send_to, signatories, file_path, username, created_at, office, program_title))

    conn.commit()
    conn.close()

    return jsonify({"success": True})


# ---------- GET RECEIVED CONTROL NUMBERS (for dropdown) ----------
@app.route("/get_received_control_numbers_ome")
def get_received_control_numbers_ome():
    if "username" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    username = session["username"]

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT code, control_no, program
        FROM control_numbers
        WHERE received_by = ? AND received_date IS NOT NULL
        ORDER BY received_date DESC
    """, (username,))

    rows = cursor.fetchall()
    conn.close()

    data = []
    for row in rows:
        code = row["code"] or ""
        control_no = row["control_no"] or ""
        program = row["program"] or ""
        label = f"{code} - {control_no} - {program}"
        value = f"{code}|{control_no}"  # <--- combine code and control number
        data.append({"label": label, "value": value})

    return jsonify({"success": True, "data": data})


# ---------- PORT DASHBOARD ----------
@app.route('/port_dashboard')
def port_dashboard():
    if 'office' in session and session['office'].upper() == 'PORT':
        return render_template('port_dashboard.html', username=session['username'])
    return redirect(url_for('login'))


# ---------- MAO DASHBOARD ----------
@app.route('/mao_dashboard')
def mao_dashboard():
    if 'office' in session and session['office'].upper() == 'MAO':
        return render_template('mao_dashboard.html', username=session['username'])
    return redirect(url_for('login'))




# ---------- RUN ----------
if __name__ == '__main__':
    app.run(debug=True)
