import os
import random
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    flash,
)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance", "attendance.db")
SECRET_KEY_PATH = os.path.join(BASE_DIR, "instance", "secret_key")


def _load_or_create_secret_key():
    """Load a persistent secret key (so sessions survive restarts).

    Priority:
      1. SECRET_KEY environment variable
      2. instance/secret_key file
      3. freshly generated key saved to instance/secret_key
    """
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key

    if os.path.exists(SECRET_KEY_PATH):
        with open(SECRET_KEY_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()

    os.makedirs(os.path.dirname(SECRET_KEY_PATH), exist_ok=True)
    new_key = secrets.token_hex(32)
    with open(SECRET_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(new_key)
    return new_key


app = Flask(__name__)
app.config["SECRET_KEY"] = _load_or_create_secret_key()
app.config["DATABASE"] = DB_PATH

# ----- Secure session cookie configuration -----
# Cookies cannot be read by JavaScript (mitigates XSS session theft).
app.config["SESSION_COOKIE_HTTPONLY"] = True
# Restrict cookie to first-party navigation (mitigates CSRF).
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Set to True when serving over HTTPS (production). False for local dev.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
# Renew the session cookie on every request (sliding expiration).
app.config["SESSION_REFRESH_EACH_REQUEST"] = True
# Default lifetime when a session is marked permanent ("remember me").
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

PIN_LENGTH = 6
SESSION_DURATION_MINUTES = 30  # default lifetime of an attendance session PIN


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    """Return a per-request database connection stored on ``g``."""
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON;")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create the database schema and seed a demo admin account."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT    NOT NULL UNIQUE,
            password   TEXT    NOT NULL,
            name       TEXT    NOT NULL,
            role       TEXT    NOT NULL CHECK (role IN ('admin','teacher','student')),
            email      TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT    NOT NULL,
            teacher_id  INTEGER NOT NULL,
            pin         TEXT    NOT NULL,
            expiry_time DATETIME NOT NULL,
            is_active   INTEGER NOT NULL DEFAULT 1,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS attendance (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id    INTEGER NOT NULL,
            student_id    INTEGER NOT NULL,
            check_in_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status        TEXT    NOT NULL DEFAULT 'present',
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
            FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE (session_id, student_id)
        );
        """
    )

    # Seed a default admin if no users exist yet.
    cur = conn.execute("SELECT COUNT(*) AS n FROM users;")
    if cur.fetchone()["n"] == 0:
        conn.execute(
            "INSERT INTO users (username, password, name, role, email) "
            "VALUES (?, ?, ?, ?, ?);",
            (
                "admin",
                generate_password_hash("admin123"),
                "System Admin",
                "admin",
                "admin@example.com",
            ),
        )
        conn.execute(
            "INSERT INTO users (username, password, name, role, email) "
            "VALUES (?, ?, ?, ?, ?);",
            (
                "teacher",
                generate_password_hash("teacher123"),
                "Demo Teacher",
                "teacher",
                "teacher@example.com",
            ),
        )
        conn.execute(
            "INSERT INTO users (username, password, name, role, email) "
            "VALUES (?, ?, ?, ?, ?);",
            (
                "student",
                generate_password_hash("student123"),
                "Demo Student",
                "student",
                "student@example.com",
            ),
        )

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for(f"{session.get('role', 'student')}_dashboard"))
            return f(*args, **kwargs)

        return decorated

    return decorator


def current_user():
    if "user_id" not in session:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?;", (session["user_id"],)).fetchone()


def generate_pin(length=PIN_LENGTH):
    return "".join(random.choices("0123456789", k=length))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for(f"{session['role']}_dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for(f"{session['role']}_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?;", (username,)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()
            # Persist the session cookie when "Remember me" is checked,
            # so the user stays logged in after closing the browser.
            session.permanent = remember
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["name"] = user["name"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['name']}!", "success")
            # Route the user to the dashboard matching their role.
            return redirect(url_for(f"{user['role']}_dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for(f"{session['role']}_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip() or None
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        role = request.form.get("role", "student")

        errors = []
        if len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if len(name) < 2:
            errors.append("Full name is required.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if role not in ("teacher", "student"):
            errors.append("Invalid role selection.")

        if not errors:
            db = get_db()
            existing = db.execute(
                "SELECT id FROM users WHERE username = ?;", (username,)
            ).fetchone()
            if existing:
                errors.append("Username is already taken.")

        if errors:
            for err in errors:
                flash(err, "danger")
            return render_template(
                "register.html",
                username=username,
                name=name,
                email=email or "",
                role=role,
            )

        get_db().execute(
            "INSERT INTO users (username, password, name, role, email) "
            "VALUES (?, ?, ?, ?, ?);",
            (
                username,
                generate_password_hash(password),
                name,
                role,
                email,
            ),
        )
        get_db().commit()
        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    """Backward-compatible alias that redirects to the role dashboard."""
    return redirect(url_for(f"{session['role']}_dashboard"))


@app.route("/teacher_dashboard")
@login_required
@role_required("teacher")
def teacher_dashboard():
    db = get_db()
    sessions = db.execute(
        "SELECT s.*, "
        "(SELECT COUNT(*) FROM attendance a WHERE a.session_id = s.id) AS checked_in "
        "FROM sessions s WHERE s.teacher_id = ? ORDER BY s.created_at DESC;",
        (session["user_id"],),
    ).fetchall()
    return render_template(
        "teacher_dashboard.html", user=current_user(), sessions=sessions
    )


@app.route("/student_dashboard")
@login_required
@role_required("student")
def student_dashboard():
    db = get_db()
    attendance = db.execute(
        "SELECT a.*, s.title AS session_title, s.pin AS session_pin "
        "FROM attendance a "
        "JOIN sessions s ON a.session_id = s.id "
        "WHERE a.student_id = ? "
        "ORDER BY a.check_in_time DESC;",
        (session["user_id"],),
    ).fetchall()
    return render_template(
        "student_dashboard.html", user=current_user(), attendance=attendance
    )


@app.route("/admin_dashboard")
@login_required
@role_required("admin")
def admin_dashboard():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY created_at DESC;").fetchall()
    sessions = db.execute(
        "SELECT s.*, u.name AS teacher_name "
        "FROM sessions s JOIN users u ON s.teacher_id = u.id "
        "ORDER BY s.created_at DESC;"
    ).fetchall()
    return render_template(
        "admin_dashboard.html", user=current_user(), users=users, sessions=sessions
    )


@app.route("/sessions/create", methods=["GET", "POST"])
@login_required
@role_required("teacher", "admin")
def create_session():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        minutes = int(request.form.get("duration", SESSION_DURATION_MINUTES))

        if not title:
            flash("Session title is required.", "danger")
        else:
            pin = generate_pin()
            expiry = datetime.now() + timedelta(minutes=minutes)
            get_db().execute(
                "INSERT INTO sessions (title, teacher_id, pin, expiry_time) "
                "VALUES (?, ?, ?, ?);",
                (title, session["user_id"], pin, expiry.strftime("%Y-%m-%d %H:%M:%S")),
            )
            get_db().commit()
            flash(f"Session created! Active PIN: {pin}", "success")
            return redirect(url_for(f"{session['role']}_dashboard"))

    return render_template("create_session.html")


@app.route("/sessions/start", methods=["POST"])
@login_required
@role_required("teacher", "admin")
def start_class():
    title = request.form.get("title", "").strip() or f"Class Session {datetime.now().strftime('%b %d, %H:%M')}"
    pin = generate_pin()
    expiry = datetime.now() + timedelta(seconds=60)
    
    db = get_db()
    db.execute(
        "INSERT INTO sessions (title, teacher_id, pin, expiry_time) "
        "VALUES (?, ?, ?, ?);",
        (title, session["user_id"], pin, expiry.strftime("%Y-%m-%d %H:%M:%S")),
    )
    db.commit()
    flash(f"Class started! PIN: {pin} (Expires in 60 seconds)", "success")
    return redirect(url_for(f"{session['role']}_dashboard"))


@app.route("/sessions/<int:session_id>")
@login_required
def view_session(session_id):
    db = get_db()
    s = db.execute(
        "SELECT s.*, u.name AS teacher_name FROM sessions s "
        "JOIN users u ON s.teacher_id = u.id WHERE s.id = ?;",
        (session_id,),
    ).fetchone()
    if not s:
        flash("Session not found.", "danger")
        return redirect(url_for(f"{session['role']}_dashboard"))

    records = db.execute(
        "SELECT a.*, u.name AS student_name, u.username AS student_username "
        "FROM attendance a JOIN users u ON a.student_id = u.id "
        "WHERE a.session_id = ? ORDER BY a.check_in_time;",
        (session_id,),
    ).fetchall()

    return render_template(
        "session_detail.html",
        attendance_session=s,
        records=records,
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@app.route("/attendance/join", methods=["GET", "POST"])
@login_required
@role_required("student")
def join_session():
    if request.method == "POST":
        pin = request.form.get("pin", "").strip()
        if not pin.isdigit() or len(pin) != PIN_LENGTH:
            flash(f"PIN must be a {PIN_LENGTH}-digit number.", "danger")
        else:
            db = get_db()
            s = db.execute(
                "SELECT * FROM sessions WHERE pin = ? AND is_active = 1;", (pin,)
            ).fetchone()

            if not s:
                flash("No active session found for that PIN.", "danger")
            elif datetime.strptime(s["expiry_time"], "%Y-%m-%d %H:%M:%S") < datetime.now():
                flash("This session PIN has expired.", "warning")
                db.execute("UPDATE sessions SET is_active = 0 WHERE id = ?;", (s["id"],))
                db.commit()
            else:
                existing = db.execute(
                    "SELECT id FROM attendance WHERE session_id = ? AND student_id = ?;",
                    (s["id"], session["user_id"]),
                ).fetchone()
                if existing:
                    flash("You have already checked in to this session.", "info")
                else:
                    db.execute(
                        "INSERT INTO attendance (session_id, student_id) VALUES (?, ?);",
                        (s["id"], session["user_id"]),
                    )
                    db.commit()
                    flash("Attendance recorded successfully!", "success")
                return redirect(url_for("student_dashboard"))

    return render_template("join_session.html")


@app.route("/sessions/<int:session_id>/end", methods=["POST"])
@login_required
@role_required("teacher", "admin")
def end_session(session_id):
    db = get_db()
    s = db.execute("SELECT * FROM sessions WHERE id = ?;", (session_id,)).fetchone()
    if s and (s["teacher_id"] == session["user_id"] or session["role"] == "admin"):
        db.execute("UPDATE sessions SET is_active = 0 WHERE id = ?;", (session_id,))
        db.commit()
        flash("Session ended.", "info")
    return redirect(url_for(f"{session['role']}_dashboard"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
@app.route('/export/<int:session_id>')
@login_required
def export_csv(session_id):
    import csv, io
    from flask import Response
    db = get_db()
    
    # Grab all students who checked into this specific class
    records = db.execute(
        "SELECT u.name, u.username, a.check_in_time "
        "FROM attendance a JOIN users u ON a.student_id = u.id "
        "WHERE a.session_id = ? ORDER BY a.check_in_time;",
        (session_id,)
    ).fetchall()
    
    # Create the CSV spreadsheet in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Student Name', 'Roll Number', 'Check-In Time'])
    
    for r in records:
        writer.writerow([r['name'], r['username'], r['check_in_time']])
        
    # Send it to the teacher's browser as a download
    return Response(
        output.getvalue(), 
        mimetype="text/csv", 
        headers={"Content-Disposition": f"attachment;filename=Class_Attendance.csv"}
    )
if __name__ == "__main__":
    init_db()
    print(f"[*] Database initialized at {DB_PATH}")
    print("[*] Demo accounts -> admin/admin123 | teacher/teacher123 | student/student123")
    app.run(debug=True, host="0.0.0.0", port=5000)
