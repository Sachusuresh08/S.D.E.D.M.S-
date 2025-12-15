from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, 'users.db')

app = Flask(__name__)
app.secret_key = 'change_this_to_a_secure_random_value'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
    )''')
    conn.commit()
    # Ensure files table exists for uploaded files
    c.execute('''CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT NOT NULL,
        filename TEXT NOT NULL,
        mimetype TEXT,
        data BLOB NOT NULL,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    # Requests table (for upload/download approval workflow)
    c.execute('''CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        requester TEXT NOT NULL,
        action TEXT NOT NULL,
        filename TEXT,
        mimetype TEXT,
        data BLOB,
        file_id INTEGER,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    # Per-user approvals for requests
    c.execute('''CREATE TABLE IF NOT EXISTS request_approvals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id INTEGER NOT NULL,
        approver TEXT NOT NULL,
        approved INTEGER NOT NULL DEFAULT 0,
        approved_at DATETIME
    )''')
    conn.commit()
    # Notifications table for broadcasting messages to users
    c.execute('''CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        read INTEGER NOT NULL DEFAULT 0
    )''')
    conn.commit()
    # Ensure `role` column exists for older databases
    c.execute("PRAGMA table_info(users)")
    cols = [r[1] for r in c.fetchall()]
    if 'role' not in cols:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        conn.commit()
    # Ensure default admin exists
    c.execute("SELECT id FROM users WHERE username = ?", ('stephan',))
    if not c.fetchone():
        # Insert default admin with password '5233' (hashed)
        admin_hash = generate_password_hash('5233')
        c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', ('stephan', admin_hash, 'admin'))
        conn.commit()
    conn.close()

# Note: older Flask versions had `before_first_request` decorator. To keep
# compatibility with newer Flask releases, we call `init_db()` at startup
# (it's also called in the __main__ block below).

def get_user(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, password, role FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    conn.close()
    return row

def list_users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, role FROM users ORDER BY id')
    rows = c.fetchall()
    conn.close()
    return rows

def save_file(owner, filename, mimetype, data_bytes):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO files (owner, filename, mimetype, data) VALUES (?, ?, ?, ?)', (owner, filename, mimetype, data_bytes))
    conn.commit()
    conn.close()

def create_request_upload(requester, filename, mimetype, data_bytes):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO requests (requester, action, filename, mimetype, data) VALUES (?, ?, ?, ?, ?)', (requester, 'upload', filename, mimetype, data_bytes))
    req_id = c.lastrowid
    conn.commit()
    conn.close()
    return req_id

def create_request_download(requester, file_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT filename, mimetype FROM files WHERE id = ?', (file_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return None
    filename, mimetype = row
    c.execute('INSERT INTO requests (requester, action, filename, mimetype, file_id) VALUES (?, ?, ?, ?, ?)', (requester, 'download', filename, mimetype, file_id))
    req_id = c.lastrowid
    conn.commit()
    conn.close()
    return req_id

def list_pending_requests():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, requester, action, filename, file_id, status, created_at FROM requests WHERE status = 'pending' ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return rows

def add_approval(request_id, approver):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # check if approver already recorded for this request
    c.execute('SELECT id FROM request_approvals WHERE request_id = ? AND approver = ?', (request_id, approver))
    if c.fetchone():
        conn.close()
        return False
    c.execute('INSERT INTO request_approvals (request_id, approver, approved, approved_at) VALUES (?, ?, 1, CURRENT_TIMESTAMP)', (request_id, approver))
    conn.commit()
    conn.close()
    return True

def add_rejection(request_id, approver):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # check if already recorded (approval or rejection)
    c.execute('SELECT id FROM request_approvals WHERE request_id = ? AND approver = ?', (request_id, approver))
    if c.fetchone():
        conn.close()
        return False
    c.execute('INSERT INTO request_approvals (request_id, approver, approved, approved_at) VALUES (?, ?, 0, CURRENT_TIMESTAMP)', (request_id, approver))
    # mark request as rejected
    c.execute("UPDATE requests SET status = 'rejected' WHERE id = ?", (request_id,))
    conn.commit()
    conn.close()
    # broadcast notification to all users
    broadcast_notification(f'Request {request_id} has been rejected by {approver}')
    return True

def broadcast_notification(message):
    # insert a notification row for every user
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT username FROM users')
    rows = c.fetchall()
    for (username,) in rows:
        c.execute('INSERT INTO notifications (recipient, message) VALUES (?, ?)', (username, message))
    conn.commit()
    conn.close()

def count_approvals(request_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM request_approvals WHERE request_id = ? AND approved = 1', (request_id,))
    (n,) = c.fetchone()
    conn.close()
    return n

def total_user_count():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM users')
    (n,) = c.fetchone()
    conn.close()
    return n

def finalize_request_if_unanimous(request_id):
    # If approvals == total users, perform the request
    approvals = count_approvals(request_id)
    total = total_user_count()
    # If any rejection exists, set rejected and broadcast
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM request_approvals WHERE request_id = ? AND approved = 0', (request_id,))
    (rejections,) = c.fetchone()
    conn.close()
    if rejections > 0:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE requests SET status = 'rejected' WHERE id = ?", (request_id,))
        conn.commit()
        conn.close()
        broadcast_notification(f'Request {request_id} was rejected')
        return False
    if approvals >= total and total > 0:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, requester, action, filename, mimetype, data, file_id FROM requests WHERE id = ?', (request_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return False
        rid, requester, action, filename, mimetype, data_blob, file_id = row
        if action == 'upload':
            # move pending data into files table
            c.execute('INSERT INTO files (owner, filename, mimetype, data) VALUES (?, ?, ?, ?)', (requester, filename, mimetype, data_blob))
            file_id = c.lastrowid
            # update request to point to the created file
            c.execute('UPDATE requests SET file_id = ? WHERE id = ?', (file_id, request_id))
        # for download action no DB change necessary; granting is enough
        c.execute("UPDATE requests SET status = 'approved' WHERE id = ?", (request_id,))
        conn.commit()
        conn.close()
        # Broadcast a notification that includes a download link when appropriate
        if action == 'upload' and file_id:
            link = f'/download/{file_id}'
            broadcast_notification(f'Request {request_id} was approved by all users. Download: <a href="{link}">{filename}</a>')
        elif action == 'download':
            # for download requests, notify requester they can download via download_request
            broadcast_notification(f'Request {request_id} was approved by all users. Requester can download via <a href="/download_request/{request_id}">this link</a>')
        return True
    return False

def list_files_for_user(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Admin sees all files
    if session.get('role') == 'admin':
        c.execute('SELECT id, owner, filename, mimetype, uploaded_at FROM files ORDER BY uploaded_at DESC')
    else:
        c.execute('SELECT id, owner, filename, mimetype, uploaded_at FROM files WHERE owner = ? ORDER BY uploaded_at DESC', (username,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_file(file_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, owner, filename, mimetype, data FROM files WHERE id = ?', (file_id,))
    row = c.fetchone()
    conn.close()
    return row

def delete_user(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Handle login
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = get_user(username)
        if user and check_password_hash(user[2], password):
            session['user'] = username
            # user row: (id, username, password, role)
            try:
                session['role'] = user[3]
            except Exception:
                session['role'] = 'user'
            return redirect(url_for('protected'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('index'))

    registered = request.args.get('registered')
    return render_template('index.html', registered=registered)

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('reg_username', '').strip()
    password = request.form.get('reg_password', '')
    # Public registration may request a role, but prevent creating an admin account
    role = request.form.get('reg_role', 'user')
    if not username or not password:
        flash('Username and password are required')
        return redirect(url_for('index'))

    hashed = generate_password_hash(password)
    # Only allow creating an 'admin' role if the current session is admin
    if role == 'admin' and session.get('role') != 'admin':
        flash('Cannot create admin account')
        return redirect(url_for('index'))

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed, role))
        conn.commit()
        conn.close()
        # After registration, refresh to login page
        return redirect(url_for('index', registered=1))
    except sqlite3.IntegrityError:
        flash('Username already exists')
        return redirect(url_for('index'))

@app.route('/protected')
def protected():
    if 'user' in session:
        files = list_files_for_user(session.get('user'))
        return render_template('protected.html', user=session.get('user'), files=files)
    flash('Please log in to access that page')
    return redirect(url_for('index'))


@app.route('/upload', methods=['POST'])
def upload():
    # Create an upload request that all users must approve
    if 'user' not in session:
        flash('Please log in to request uploads')
        return redirect(url_for('index'))
    if 'file' not in request.files:
        flash('No file provided')
        return redirect(url_for('protected'))
    f = request.files['file']
    if f.filename == '':
        flash('No file selected')
        return redirect(url_for('protected'))
    filename = secure_filename(f.filename)
    data = f.read()
    mimetype = f.mimetype
    req_id = create_request_upload(session.get('user'), filename, mimetype, data)
    flash(f'Upload request {req_id} created; waiting for all users to approve')
    return redirect(url_for('protected'))


@app.route('/download/<int:file_id>')
def download(file_id):
    # Allow download of a stored file to any logged-in user (file must exist)
    if 'user' not in session:
        flash('Please log in to download files')
        return redirect(url_for('index'))
    row = get_file(file_id)
    if not row:
        flash('File not found')
        return redirect(url_for('protected'))
    fid, owner, fname, mimetype, data = row
    from flask import Response
    return Response(data, mimetype=(mimetype or 'application/octet-stream'), headers={
        'Content-Disposition': f'attachment; filename="{fname}"'
    })


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # Admin-only view: list users and allow deletion
    if session.get('role') != 'admin':
        flash('Admin access required')
        return redirect(url_for('protected') if 'user' in session else url_for('index'))

    if request.method == 'POST':
        # Admin may create a user or delete a user.
        # Create user if creation fields present
        create_username = request.form.get('create_username')
        create_password = request.form.get('create_password')
        create_role = request.form.get('create_role', 'user')
        if create_username and create_password:
            # Admin is allowed to create admin accounts.
            try:
                hashed = generate_password_hash(create_password)
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (create_username, hashed, create_role))
                conn.commit()
                conn.close()
                flash(f'User {create_username} created with role {create_role}')
            except sqlite3.IntegrityError:
                flash('Username already exists')
            return redirect(url_for('admin'))

        # Otherwise handle deletion
        username = request.form.get('delete_username')
        if username:
            if username == session.get('user'):
                flash('Cannot delete the currently logged-in admin')
            else:
                delete_user(username)
                flash(f'User {username} removed')
        return redirect(url_for('admin'))

    users = list_users()
    return render_template('admin.html', users=users)


@app.route('/request_download/<int:file_id>', methods=['POST'])
def request_download(file_id):
    if 'user' not in session:
        flash('Please log in to request downloads')
        return redirect(url_for('index'))
    req_id = create_request_download(session.get('user'), file_id)
    if not req_id:
        flash('File not found')
        return redirect(url_for('protected'))
    flash(f'Download request {req_id} created; waiting for all users to approve')
    return redirect(url_for('protected'))


@app.route('/requests', methods=['GET'])
def requests_view():
    if 'user' not in session:
        flash('Please log in to view requests')
        return redirect(url_for('index'))
    reqs = list_pending_requests()
    # build approvals count and whether current user approved
    approvals = {}
    user_approved = {}
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    for r in reqs:
        rid = r[0]
        c.execute('SELECT COUNT(*) FROM request_approvals WHERE request_id = ? AND approved = 1', (rid,))
        approvals[rid] = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM request_approvals WHERE request_id = ? AND approver = ?', (rid, session.get('user')))
        user_approved[rid] = (c.fetchone()[0] > 0)
        # whether current user has rejected
        c.execute('SELECT COUNT(*) FROM request_approvals WHERE request_id = ? AND approver = ? AND approved = 0', (rid, session.get('user')))
        user_rejected = (c.fetchone()[0] > 0)
        user_approved[rid] = user_approved[rid] and not user_rejected
        # attach rejected flag
        approvals.setdefault('rejected_'+str(rid), user_rejected)
    conn.close()
    total = total_user_count()
    return render_template('requests.html', requests=reqs, approvals=approvals, user_approved=user_approved, total_users=total)


@app.route('/notifications')
def notifications_view():
    if 'user' not in session:
        flash('Please log in')
        return redirect(url_for('index'))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, recipient, message, created_at FROM notifications WHERE recipient = ? ORDER BY created_at DESC', (session.get('user'),))
    notes = c.fetchall()
    conn.close()
    return render_template('notifications.html', notifications=notes)


@app.route('/approve_request', methods=['POST'])
def approve_request():
    if 'user' not in session:
        flash('Please log in to approve requests')
        return redirect(url_for('index'))
    req_id = request.form.get('request_id')
    if not req_id:
        flash('Missing request id')
        return redirect(url_for('requests_view'))
    # add approval if not already
    added = add_approval(int(req_id), session.get('user'))
    if not added:
        flash('You already approved this request')
        return redirect(url_for('requests_view'))
    # check unanimous
    finalized = finalize_request_if_unanimous(int(req_id))
    if finalized:
        flash('Request approved by all users and finalized')
    else:
        flash('Approval recorded')
    return redirect(url_for('requests_view'))


@app.route('/reject_request', methods=['POST'])
def reject_request():
    if 'user' not in session:
        flash('Please log in to reject requests')
        return redirect(url_for('index'))
    req_id = request.form.get('request_id')
    if not req_id:
        flash('Missing request id')
        return redirect(url_for('requests_view'))
    added = add_rejection(int(req_id), session.get('user'))
    if not added:
        flash('You already responded to this request')
        return redirect(url_for('requests_view'))
    flash('Rejection recorded and broadcast to all users')
    return redirect(url_for('requests_view'))


@app.route('/download_request/<int:req_id>')
def download_request(req_id):
    # allow requester to download the file after request is approved
    if 'user' not in session:
        flash('Please log in')
        return redirect(url_for('index'))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT requester, action, file_id, filename, mimetype, status FROM requests WHERE id = ?', (req_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        flash('Request not found')
        return redirect(url_for('protected'))
    requester, action, file_id, filename, mimetype, status = row
    if requester != session.get('user'):
        flash('Only requester can download from this request')
        return redirect(url_for('protected'))
    if status != 'approved':
        flash('Request not yet approved by all users')
        return redirect(url_for('requests_view'))
    if action != 'download':
        flash('This request is not a download request')
        return redirect(url_for('protected'))
    # fetch file
    f = get_file(file_id)
    if not f:
        flash('File not found')
        return redirect(url_for('protected'))
    fid, owner, fname, fmime, data = f
    from flask import Response
    return Response(data, mimetype=(fmime or 'application/octet-stream'), headers={
        'Content-Disposition': f'attachment; filename="{fname}"'
    })

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
