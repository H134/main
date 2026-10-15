import os, re, sqlite3
from functools import wraps
import bcrypt
from flask import Flask, render_template_string, request, redirect, url_for, session, flash, g

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))   # use a fixed env var in production
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
DB = "users.db"

# ---------- database ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    with sqlite3.connect(DB) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL)""")

# ---------- validation ----------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def validate(username, email, password):
    errors = []
    if not USERNAME_RE.match(username):
        errors.append("Username must be 3-20 characters: letters, numbers, underscore.")
    if not EMAIL_RE.match(email):
        errors.append("Enter a valid email address.")
    if len(password) < 8 or not re.search(r"\d", password) or not re.search(r"[A-Za-z]", password):
        errors.append("Password must be 8+ characters with letters and numbers.")
    return errors

# ---------- auth helper ----------
def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper

# ---------- templates ----------
BASE = """<!doctype html><title>Secure Login</title>
<style>body{font-family:sans-serif;max-width:380px;margin:60px auto}input{width:100%;padding:8px;margin:6px 0}
button{padding:8px 16px}.err{color:#b00}.ok{color:#080}</style>
{% with msgs = get_flashed_messages(with_categories=true) %}{% for c,m in msgs %}<p class="{{c}}">{{m}}</p>{% endfor %}{% endwith %}
"""
REGISTER = BASE + """<h2>Register</h2><form method="post">
<input name="username" placeholder="Username" required>
<input name="email" type="email" placeholder="Email" required>
<input name="password" type="password" placeholder="Password" required>
<button>Register</button></form><p><a href="{{url_for('login')}}">Login</a></p>"""
LOGIN = BASE + """<h2>Login</h2><form method="post">
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button>Login</button></form><p><a href="{{url_for('register')}}">Register</a></p>"""
DASH = BASE + """<h2>Welcome, {{user}}!</h2><p>You are logged in.</p>
<form method="post" action="{{url_for('logout')}}"><button>Logout</button></form>"""

# ---------- routes ----------
@app.route("/")
def index():
    return redirect(url_for("dashboard"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        errors = validate(username, email, password)
        if errors:
            for e in errors: flash(e, "err")
            return render_template_string(REGISTER)
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        try:
            # parameterized query -> prevents SQL injection
            get_db().execute("INSERT INTO users(username,email,password_hash) VALUES(?,?,?)",
                             (username, email, hashed))
            get_db().commit()
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "err")
            return render_template_string(REGISTER)
        flash("Registered! Please log in.", "ok")
        return redirect(url_for("login"))
    return render_template_string(REGISTER)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row and bcrypt.checkpw(password.encode(), row["password_hash"]):
            session.clear()
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "err")   # same message for both cases
    return render_template_string(LOGIN)

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template_string(DASH, user=session["username"])

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Logged out.", "ok")
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)