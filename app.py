import os
import re
import json
import secrets
import sqlite3
import string
import socket
import hashlib
import threading
from datetime import datetime, timedelta
from functools import wraps

import libsql
from flask import Flask, render_template, request, jsonify, session, g, send_from_directory

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True

TURSO_URL = os.environ.get("TURSO_DATABASE_URL", "")
TURSO_TOKEN = os.environ.get("TURSO_AUTH_TOKEN", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")

USE_TURSO = bool(TURSO_URL and TURSO_TOKEN)

SLOT_SYMBOLS = [
    {"id": "cherry",  "emoji": "🍒", "payout3": 5},
    {"id": "lemon",   "emoji": "🍋", "payout3": 8},
    {"id": "grape",   "emoji": "🍇", "payout3": 12},
    {"id": "star",    "emoji": "⭐", "payout3": 20},
    {"id": "seven",   "emoji": "7️⃣", "payout3": 50},
    {"id": "diamond", "emoji": "💎", "payout3": 100},
]

# =================================================
# PASSWORT-HASHING
# =================================================
def hash_password(password):
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000
    ).hex()
    return f"{salt}${pwd_hash}"

def verify_password(password, stored):
    if not stored or '$' not in stored:
        return False
    try:
        salt, pwd_hash = stored.split('$', 1)
        check_hash = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000
        ).hex()
        return secrets.compare_digest(check_hash, pwd_hash)
    except Exception:
        return False

# =================================================
# DATENBANK
# =================================================
_db_initialized = False
_init_lock = threading.Lock()

def _ensure_tables(db):
    global _db_initialized
    if _db_initialized:
        return
    with _init_lock:
        if _db_initialized:
            return
        try:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT NOT NULL,
                    password_hash TEXT NOT NULL DEFAULT '',
                    code TEXT NOT NULL DEFAULT '',
                    balance REAL NOT NULL DEFAULT 100.0,
                    history TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    last_update TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS guests (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE,
                    balance REAL NOT NULL DEFAULT 100.0,
                    history TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    last_update TEXT NOT NULL DEFAULT ''
                );
            """)
            db.commit()
        except Exception as e:
            print(f"⚠️ Table-Create: {e}")

        try:
            cols = [r[1] for r in db.execute("PRAGMA table_info(accounts)").fetchall()]
            for col, ddl in [
                ("password_hash", "ALTER TABLE accounts ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''"),
                ("code", "ALTER TABLE accounts ADD COLUMN code TEXT NOT NULL DEFAULT ''"),
                ("last_update", "ALTER TABLE accounts ADD COLUMN last_update TEXT NOT NULL DEFAULT ''"),
            ]:
                if col not in cols:
                    try: db.execute(ddl)
                    except Exception: pass
        except Exception as e:
            print(f"Migration accounts: {e}")

        try:
            cols = [r[1] for r in db.execute("PRAGMA table_info(guests)").fetchall()]
            for col, ddl in [
                ("username", "ALTER TABLE guests ADD COLUMN username TEXT"),
                ("last_update", "ALTER TABLE guests ADD COLUMN last_update TEXT NOT NULL DEFAULT ''"),
            ]:
                if col not in cols:
                    try: db.execute(ddl)
                    except Exception: pass
        except Exception as e:
            print(f"Migration guests: {e}")

        try: db.commit()
        except Exception: pass
        _db_initialized = True

def get_db():
    if "db" not in g:
        if USE_TURSO:
            g.db = libsql.connect(database=TURSO_URL, auth_token=TURSO_TOKEN)
        else:
            g.db = sqlite3.connect("accounts.db")
            g.db.row_factory = sqlite3.Row
            try: g.db.execute("PRAGMA foreign_keys = ON")
            except Exception: pass
        _ensure_tables(g.db)
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        try: db.close()
        except Exception: pass

def row_get(row, key, default=None):
    """Sicherer Zugriff auf Spalten (funktioniert mit und ohne row_factory)."""
    if row is None:
        return default
    try:
        keys = row.keys()
        if key in keys:
            val = row[key]
            return default if val is None else val
    except Exception:
        pass
    try:
        val = row[key]
        return default if val is None else val
    except Exception:
        return default

def row_get_int(row, key, default=0):
    """Zugriff auf Integer-Spalten mit sicherem Cast."""
    val = row_get(row, key, default)
    try:
        return int(val)
    except (TypeError, ValueError):
        return default

def row_to_dict(row):
    """Wandelt eine Row in ein dict um (funktioniert mit und ohne row_factory)."""
    if row is None:
        return {}
    try:
        return dict(row)
    except Exception:
        pass
    try:
        return {k: row[k] for k in row.keys()}
    except Exception:
        return {}

# =================================================
# HELPER
# =================================================
def generate_code(length=6):
    alphabet = string.ascii_uppercase + string.digits
    alphabet = alphabet.replace("O", "").replace("0", "").replace("I", "").replace("1", "")
    return "".join(secrets.choice(alphabet) for _ in range(length))

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-]{3,20}$")

def check_email_syntax(email):
    return bool(EMAIL_RE.match(email))

def check_email_mx(email):
    try:
        domain = email.split("@")[1]
        socket.getaddrinfo(domain, None)
        return True
    except Exception:
        return False

def check_email(email):
    if not check_email_syntax(email):
        return False, "E-Mail-Format ungültig."
    if not check_email_mx(email):
        return False, "E-Mail-Domain existiert nicht oder empfängt keine Mails."
    return True, "OK"

def now_iso():
    return datetime.utcnow().isoformat()

def username_exists(db, username, exclude_account_id=None, exclude_guest_id=None):
    row = db.execute("SELECT id FROM accounts WHERE username = ?", (username,)).fetchone()
    if row:
        if exclude_account_id is None or row_get_int(row, "id") != exclude_account_id:
            return True
    row = db.execute("SELECT id FROM guests WHERE username = ?", (username,)).fetchone()
    if row:
        if exclude_guest_id is None or str(row_get(row, "id", "")) != str(exclude_guest_id):
            return True
    return False

def account_to_dict(row):
    """Konvertiert Account-Row zu dict. Nutzt row_to_dict für maximale Kompatibilität."""
    d = row_to_dict(row)
    try:
        history = json.loads(d.get("history") or "[]")
    except Exception:
        history = []
    return {
        "id": d.get("id"),
        "username": d.get("username") or "",
        "email": d.get("email") or "",
        "balance": d.get("balance") if d.get("balance") is not None else 0.0,
        "history": history,
        "last_update": d.get("last_update") or "",
    }

def guest_to_dict(row):
    d = row_to_dict(row)
    try:
        history = json.loads(d.get("history") or "[]")
    except Exception:
        history = []
    return {
        "id": d.get("id"),
        "username": d.get("username"),
        "balance": d.get("balance") if d.get("balance") is not None else 0.0,
        "history": history,
        "created_at": d.get("created_at") or "",
        "last_seen": d.get("last_seen") or "",
        "last_update": d.get("last_update") or "",
    }

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("account_id"):
            return jsonify({"error": "Nicht eingeloggt."}), 401
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"error": "Admin-Login nötig."}), 401
        return f(*args, **kwargs)
    return wrapper

def get_current_account():
    acc_id = session.get("account_id")
    if not acc_id:
        return None
    db = get_db()
    return db.execute("SELECT * FROM accounts WHERE id = ?", (acc_id,)).fetchone()

def get_guest_by_id(guest_id):
    if not guest_id:
        return None
    db = get_db()
    return db.execute("SELECT * FROM guests WHERE id = ?", (guest_id,)).fetchone()

def get_any_user_by_name(username):
    db = get_db()
    row = db.execute("SELECT * FROM accounts WHERE username = ?", (username,)).fetchone()
    if row:
        return ("account", row)
    row = db.execute("SELECT * FROM guests WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
    if row:
        return ("guest", row)
    return (None, None)

def add_history_to_account(db, account_id, entry):
    row = db.execute("SELECT history FROM accounts WHERE id = ?", (account_id,)).fetchone()
    if not row:
        return
    try:
        history = json.loads(row_get(row, "history", "[]") or "[]")
    except Exception:
        history = []
    history.insert(0, entry)
    history = history[:50]
    db.execute("UPDATE accounts SET history = ? WHERE id = ?", (json.dumps(history), account_id))

def add_history_to_guest(db, guest_id, entry):
    row = db.execute("SELECT history FROM guests WHERE id = ?", (guest_id,)).fetchone()
    if not row:
        return
    try:
        history = json.loads(row_get(row, "history", "[]") or "[]")
    except Exception:
        history = []
    history.insert(0, entry)
    history = history[:50]
    db.execute("UPDATE guests SET history = ? WHERE id = ?", (json.dumps(history), guest_id))

# =================================================
# HAUPTSEITEN
# =================================================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/admin")
def admin_page():
    return render_template("admin.html")

@app.route("/service-worker.js")
def service_worker():
    return send_from_directory(app.static_folder, "service-worker.js", mimetype="application/javascript")

@app.route("/manifest.json")
def manifest():
    return send_from_directory(app.static_folder, "manifest.json", mimetype="application/manifest+json")

# =================================================
# ADMIN
# =================================================
@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(silent=True) or {}
    if data.get("password", "") != ADMIN_PASSWORD:
        return jsonify({"error": "Falsches Passwort."}), 401
    session["is_admin"] = True
    session.permanent = True
    return jsonify({"ok": True})

@app.route("/api/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("is_admin", None)
    return jsonify({"ok": True})

@app.route("/api/admin/check", methods=["GET"])
def admin_check():
    return jsonify({"is_admin": bool(session.get("is_admin"))})

@app.route("/api/admin/data", methods=["GET"])
@admin_required
def admin_data():
    db = get_db()
    accounts_rows = db.execute("SELECT * FROM accounts ORDER BY created_at DESC").fetchall()
    guests_rows = db.execute("SELECT * FROM guests ORDER BY last_seen DESC").fetchall()

    accounts = []
    for r in accounts_rows:
        d = row_to_dict(r)
        name = d.get("username") or ""
        email = d.get("email") or ""
        bal = d.get("balance")
        if bal is None: bal = 0.0
        accounts.append({
            "type": "account",
            "id": d.get("id"),
            "name": name,
            "email": email if email else "-",
            "balance": bal,
            "created_at": d.get("created_at") or "",
        })

    guests = []
    for r in guests_rows:
        d = row_to_dict(r)
        uname = d.get("username")
        bal = d.get("balance")
        if bal is None: bal = 0.0
        guests.append({
            "type": "guest",
            "id": d.get("id"),
            "name": uname if uname else None,
            "has_name": bool(uname),
            "email": "-",
            "balance": bal,
            "created_at": d.get("created_at") or "",
            "last_seen": d.get("last_seen") or "",
        })

    return jsonify({
        "accounts": accounts,
        "guests": guests,
        "totals": {
            "account_count": len(accounts),
            "guest_count": len(guests),
            "account_balance": sum(a["balance"] for a in accounts),
            "guest_balance": sum(g["balance"] for g in guests),
        }
    })

@app.route("/api/admin/set_balance", methods=["POST"])
@admin_required
def admin_set_balance():
    data = request.get_json(silent=True) or {}
    kind = data.get("type")
    target_id = data.get("id")
    try:
        new_balance = float(data.get("balance"))
    except (TypeError, ValueError):
        return jsonify({"error": "Ungültiges Guthaben."}), 400

    db = get_db()
    ts = now_iso()
    if kind == "account":
        db.execute("UPDATE accounts SET balance = ?, last_update = ? WHERE id = ?", (new_balance, ts, target_id))
        print(f"🛠️ Admin: Account {target_id} → {new_balance:.2f} €")
    elif kind == "guest":
        db.execute("UPDATE guests SET balance = ?, last_update = ? WHERE id = ?", (new_balance, ts, target_id))
        print(f"🛠️ Admin: Gast {str(target_id)[:10]}… → {new_balance:.2f} €")
    else:
        return jsonify({"error": "Ungültiger Typ."}), 400
    db.commit()
    return jsonify({"ok": True, "balance": new_balance, "last_update": ts})

@app.route("/api/admin/delete", methods=["POST"])
@admin_required
def admin_delete():
    data = request.get_json(silent=True) or {}
    kind = data.get("type")
    target_id = data.get("id")
    db = get_db()
    if kind == "account":
        db.execute("DELETE FROM accounts WHERE id = ?", (target_id,))
    elif kind == "guest":
        db.execute("DELETE FROM guests WHERE id = ?", (target_id,))
    else:
        return jsonify({"error": "Ungültiger Typ."}), 400
    db.commit()
    return jsonify({"ok": True})

# =================================================
# AUTH
# =================================================
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    start_balance = data.get("start_balance", None)
    start_history = data.get("start_history", None)

    if not username or len(username) < 3:
        return jsonify({"error": "Nutzername muss mind. 3 Zeichen haben."}), 400
    if len(username) > 20:
        return jsonify({"error": "Nutzername darf max. 20 Zeichen haben."}), 400
    if not re.match(r"^[A-Za-z0-9_\-]+$", username):
        return jsonify({"error": "Nur Buchstaben, Zahlen, _ und - erlaubt."}), 400
    if not password or len(password) < 6:
        return jsonify({"error": "Passwort muss mind. 6 Zeichen haben."}), 400

    ok, msg = check_email(email)
    if not ok:
        return jsonify({"error": msg}), 400

    db = get_db()
    if username_exists(db, username):
        return jsonify({"error": "Nutzername ist schon vergeben."}), 409

    pwd_hash = hash_password(password)

    try:
        balance = float(start_balance) if start_balance is not None else 100.0
    except (TypeError, ValueError):
        balance = 100.0
    if balance < 0:
        balance = 100.0

    history = []
    if isinstance(start_history, list):
        for h in start_history[:50]:
            if isinstance(h, dict):
                history.append(h)

    ts = now_iso()
    cur = db.execute(
        "INSERT INTO accounts (username, email, password_hash, balance, history, created_at, last_update) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (username, email, pwd_hash, balance, json.dumps(history), ts, ts)
    )
    db.commit()
    try:
        acc_id = cur.lastrowid
    except Exception:
        acc_id = None
    if not acc_id:
        row = db.execute("SELECT id FROM accounts WHERE username = ?", (username,)).fetchone()
        acc_id = row_get_int(row, "id")

    session.clear()
    session["account_id"] = acc_id
    session.permanent = True
    print(f"✅ Registrierung: {username} (ID {acc_id})")
    return jsonify({"ok": True, "username": username, "balance": balance, "last_update": ts})

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Nutzername und Passwort nötig."}), 400

    db = get_db()
    row = db.execute("SELECT * FROM accounts WHERE username = ?", (username,)).fetchone()
    if not row:
        return jsonify({"error": "Nutzername oder Passwort falsch."}), 401

    stored = row_get(row, "password_hash", "")
    if not verify_password(password, stored):
        return jsonify({"error": "Nutzername oder Passwort falsch."}), 401

    session.clear()
    session["account_id"] = row_get_int(row, "id")
    session.permanent = True
    print(f"✅ Login: {row_get(row, 'username')}")
    return jsonify({"ok": True, "account": account_to_dict(row)})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("account_id", None)
    return jsonify({"ok": True})

@app.route("/api/me", methods=["GET"])
def me():
    row = get_current_account()
    if not row:
        return jsonify({"logged_in": False})
    return jsonify({"logged_in": True, "account": account_to_dict(row)})

@app.route("/api/update_password", methods=["POST"])
@login_required
def update_password():
    row = get_current_account()
    db = get_db()
    data = request.get_json(silent=True) or {}
    old_password = data.get("old_password") or ""
    new_password = data.get("new_password") or ""

    if not verify_password(old_password, row_get(row, "password_hash", "")):
        return jsonify({"error": "Altes Passwort falsch."}), 401
    if not new_password or len(new_password) < 6:
        return jsonify({"error": "Neues Passwort muss mind. 6 Zeichen haben."}), 400

    new_hash = hash_password(new_password)
    db.execute("UPDATE accounts SET password_hash = ? WHERE id = ?", (new_hash, row_get_int(row, "id")))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/update_email", methods=["POST"])
@login_required
def update_email():
    row = get_current_account()
    db = get_db()
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    ok, msg = check_email(email)
    if not ok:
        return jsonify({"error": msg}), 400
    db.execute("UPDATE accounts SET email = ? WHERE id = ?", (email, row_get_int(row, "id")))
    db.commit()
    return jsonify({"ok": True, "email": email})

# =================================================
# GÄSTE
# =================================================
@app.route("/api/guest/create", methods=["POST"])
def guest_create():
    db = get_db()
    guest_id = secrets.token_urlsafe(16)
    ts = now_iso()
    db.execute(
        "INSERT INTO guests (id, balance, history, created_at, last_seen, last_update) VALUES (?, 100.0, '[]', ?, ?, ?)",
        (guest_id, ts, ts, ts)
    )
    db.commit()
    return jsonify({"ok": True, "guest_id": guest_id, "balance": 100.0, "last_update": ts})

@app.route("/api/guest/sync", methods=["POST"])
def guest_sync():
    data = request.get_json(silent=True) or {}
    guest_id = (data.get("guest_id") or "").strip()
    balance = data.get("balance", None)
    history = data.get("history", None)
    if not guest_id:
        return jsonify({"error": "guest_id fehlt."}), 400
    try:
        balance = float(balance)
    except (TypeError, ValueError):
        return jsonify({"error": "Ungültiges Guthaben."}), 400

    hist = []
    if isinstance(history, list):
        for h in history[:50]:
            if isinstance(h, dict):
                hist.append(h)

    db = get_db()
    row = db.execute("SELECT id FROM guests WHERE id = ?", (guest_id,)).fetchone()
    ts = now_iso()
    if row:
        db.execute("UPDATE guests SET balance = ?, history = ?, last_seen = ?, last_update = ? WHERE id = ?",
                   (balance, json.dumps(hist), ts, ts, guest_id))
    else:
        db.execute("INSERT INTO guests (id, balance, history, created_at, last_seen, last_update) VALUES (?, ?, ?, ?, ?, ?)",
                   (guest_id, balance, json.dumps(hist), ts, ts, ts))
    db.commit()
    return jsonify({"ok": True, "last_update": ts})

@app.route("/api/guest/me", methods=["POST"])
def guest_me():
    data = request.get_json(silent=True) or {}
    guest_id = (data.get("guest_id") or "").strip()
    if not guest_id:
        return jsonify({"error": "guest_id fehlt."}), 400
    row = get_guest_by_id(guest_id)
    if not row:
        return jsonify({"exists": False})
    return jsonify({"exists": True, "guest": guest_to_dict(row)})

@app.route("/api/guest/set_name", methods=["POST"])
def guest_set_name():
    data = request.get_json(silent=True) or {}
    guest_id = (data.get("guest_id") or "").strip()
    username = (data.get("username") or "").strip()

    if not guest_id:
        return jsonify({"error": "guest_id fehlt."}), 400
    if not USERNAME_RE.match(username):
        return jsonify({"error": "Name: 3–20 Zeichen, nur Buchstaben, Zahlen, _ und -"}), 400

    db = get_db()
    row = db.execute("SELECT id FROM guests WHERE id = ?", (guest_id,)).fetchone()
    if not row:
        return jsonify({"error": "Gast nicht gefunden."}), 404

    if username_exists(db, username, exclude_guest_id=guest_id):
        return jsonify({"error": "Name ist schon vergeben."}), 409

    db.execute("UPDATE guests SET username = ? WHERE id = ?", (username, guest_id))
    db.commit()
    print(f"✅ Gast {guest_id[:10]}… → Name: {username}")
    return jsonify({"ok": True, "username": username})

# =================================================
# USER-SUCHE
# =================================================
@app.route("/api/users/search", methods=["POST"])
def users_search():
    data = request.get_json(silent=True) or {}
    query = (data.get("q") or "").strip()
    my_guest_id = (data.get("guest_id") or "").strip()
    my_account_id = session.get("account_id")

    if len(query) < 1:
        return jsonify({"users": []})

    db = get_db()
    like = f"%{query}%"

    account_rows = db.execute(
        "SELECT id, username FROM accounts WHERE username LIKE ? AND id != ? LIMIT 10",
        (like, my_account_id if my_account_id else -1)
    ).fetchall()

    guest_rows = db.execute(
        "SELECT id, username FROM guests WHERE username LIKE ? AND username IS NOT NULL AND id != ? LIMIT 10",
        (like, my_guest_id if my_guest_id else "")
    ).fetchall()

    users = []
    for r in account_rows:
        d = row_to_dict(r)
        users.append({"type": "account", "id": d.get("id"), "username": d.get("username")})
    for r in guest_rows:
        d = row_to_dict(r)
        users.append({"type": "guest", "id": d.get("id"), "username": d.get("username")})

    return jsonify({"users": users[:15]})

# =================================================
# PAY
# =================================================
@app.route("/api/pay", methods=["POST"])
def pay():
    data = request.get_json(silent=True) or {}
    recipient_name = (data.get("recipient") or "").strip()
    try:
        amount = float(data.get("amount", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Ungültiger Betrag."}), 400

    if amount <= 0:
        return jsonify({"error": "Betrag muss größer als 0 sein."}), 400
    if amount > 1000000:
        return jsonify({"error": "Betrag zu hoch."}), 400
    if not recipient_name:
        return jsonify({"error": "Empfänger fehlt."}), 400

    sender_type = None
    sender_row = None
    acc = get_current_account()
    if acc:
        sender_type = "account"
        sender_row = acc
    else:
        guest_id = (data.get("guest_id") or "").strip()
        if not guest_id:
            return jsonify({"error": "Nicht eingeloggt."}), 401
        g = get_guest_by_id(guest_id)
        if not g:
            return jsonify({"error": "Gast nicht gefunden."}), 404
        if not row_get(g, "username"):
            return jsonify({"error": "Du brauchst erst einen Namen."}), 400
        sender_type = "guest"
        sender_row = g

    recipient_type, recipient_row = get_any_user_by_name(recipient_name)
    if not recipient_type:
        return jsonify({"error": f"Empfänger '{recipient_name}' nicht gefunden."}), 404

    sender_id = row_get(sender_row, "id")
    recipient_id = row_get(recipient_row, "id")

    if str(sender_id) == str(recipient_id) and sender_type == recipient_type:
        return jsonify({"error": "Du kannst dir nicht selbst Geld senden."}), 400

    sender_balance = row_get(sender_row, "balance", 0.0)
    if sender_balance < amount:
        return jsonify({"error": f"Nicht genug Guthaben. Du hast {sender_balance:.2f} €."}), 400

    db = get_db()
    ts = now_iso()
    sender_name = row_get(sender_row, "username", "Gast") or "Gast"
    recipient_display = row_get(recipient_row, "username", "Gast") or "Gast"
    msg = (data.get("message") or "").strip()[:100]

    try:
        new_sender_balance = sender_balance - amount
        if sender_type == "account":
            db.execute("UPDATE accounts SET balance = ?, last_update = ? WHERE id = ?", (new_sender_balance, ts, sender_id))
        else:
            db.execute("UPDATE guests SET balance = ?, last_update = ? WHERE id = ?", (new_sender_balance, ts, sender_id))

        new_recipient_balance = row_get(recipient_row, "balance", 0.0) + amount
        if recipient_type == "account":
            db.execute("UPDATE accounts SET balance = ?, last_update = ? WHERE id = ?", (new_recipient_balance, ts, recipient_id))
        else:
            db.execute("UPDATE guests SET balance = ?, last_update = ? WHERE id = ?", (new_recipient_balance, ts, recipient_id))

        send_text = f"an {recipient_display}" + (f" · \"{msg}\"" if msg else "")
        recv_text = f"von {sender_name}" + (f" · \"{msg}\"" if msg else "")

        if sender_type == "account":
            add_history_to_account(db, sender_id, {"time": ts, "game": "💸 Gesendet", "text": send_text, "amount": amount, "win": False})
        else:
            add_history_to_guest(db, sender_id, {"time": ts, "game": "💸 Gesendet", "text": send_text, "amount": amount, "win": False})

        if recipient_type == "account":
            add_history_to_account(db, recipient_id, {"time": ts, "game": "💰 Erhalten", "text": recv_text, "amount": amount, "win": True})
        else:
            add_history_to_guest(db, recipient_id, {"time": ts, "game": "💰 Erhalten", "text": recv_text, "amount": amount, "win": True})

        db.commit()
        print(f"✅ Pay OK: {sender_name} → {recipient_display}: {amount:.2f} €")

        return jsonify({
            "ok": True,
            "sender_balance": new_sender_balance,
            "recipient": recipient_display,
            "recipient_type": recipient_type,
            "amount": amount,
            "last_update": ts
        })

    except Exception as e:
        try: db.rollback()
        except Exception: pass
        print(f"❌ Pay-Fehler: {type(e).__name__}: {e}")
        return jsonify({"error": f"Buchungsfehler: {str(e)}"}), 500

# =================================================
# GUTHABEN-SYNC
# =================================================
def update_account_balance(delta, history_entry=None):
    row = get_current_account()
    if not row:
        print("⚠️ Kein Account in Session")
        return None, None
    db = get_db()
    old_balance = row_get(row, "balance", 0.0)
    new_balance = old_balance + delta
    try:
        history = json.loads(row_get(row, "history", "[]") or "[]")
    except Exception:
        history = []
    if history_entry:
        history.insert(0, history_entry)
        history = history[:50]
    ts = now_iso()
    db.execute("UPDATE accounts SET balance = ?, history = ?, last_update = ? WHERE id = ?",
               (new_balance, json.dumps(history), ts, row_get_int(row, "id")))
    db.commit()
    print(f"✅ Account {row_get(row, 'id')}: {old_balance:.2f} → {new_balance:.2f} €")
    return new_balance, ts

# =================================================
# SPIELE
# =================================================
@app.route("/api/coinflip", methods=["POST"])
def coinflip():
    data = request.get_json(silent=True) or {}
    choice = data.get("choice", "").lower()
    bet = float(data.get("bet", 0) or 0)
    if choice not in ("kopf", "zahl"):
        return jsonify({"error": "Bitte 'kopf' oder 'zahl' wählen."}), 400
    result = secrets.choice(["kopf", "zahl"])
    win = result == choice
    acc_row = get_current_account()
    new_balance = None
    ts = None
    if acc_row and bet > 0:
        delta = bet if win else -bet
        new_balance, ts = update_account_balance(delta, {
            "time": now_iso(), "game": "🪙 Coinflip",
            "text": f"{choice} → {result}", "amount": bet, "win": win,
        })
    return jsonify({"choice": choice, "result": result, "win": win, "new_balance": new_balance, "last_update": ts, "logged_in": bool(acc_row)})

@app.route("/api/wheel", methods=["POST"])
def wheel():
    data = request.get_json(silent=True) or {}
    options = data.get("options", [])
    if not isinstance(options, list):
        return jsonify({"error": "Options müssen eine Liste sein."}), 400
    cleaned = [str(o).strip() for o in options if str(o).strip()]
    if len(cleaned) < 2:
        return jsonify({"error": "Mindestens 2 Optionen nötig."}), 400
    if len(cleaned) > 12:
        return jsonify({"error": "Maximal 12 Optionen erlaubt."}), 400
    index = secrets.randbelow(len(cleaned))
    return jsonify({"index": index, "result": cleaned[index], "options": cleaned})

ROULETTE_RED = {1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36}

@app.route("/api/roulette", methods=["POST"])
def roulette():
    data = request.get_json(silent=True) or {}
    bet_type = data.get("bet_type", "")
    bet_value = data.get("bet_value", None)
    bet = float(data.get("bet", 0) or 0)
    number = secrets.randbelow(37)
    if number == 0:
        color = "green"
    elif number in ROULETTE_RED:
        color = "red"
    else:
        color = "black"
    win = False
    payout = 0
    if bet_type == "color" and bet_value in ("red", "black"):
        if color == bet_value:
            win = True
            payout = 1
    elif bet_type == "parity" and bet_value in ("even", "odd"):
        if number != 0:
            is_even = number % 2 == 0
            if (bet_value == "even" and is_even) or (bet_value == "odd" and not is_even):
                win = True
                payout = 1
    elif bet_type == "range" and bet_value in ("low", "high"):
        if bet_value == "low" and 1 <= number <= 18:
            win = True
            payout = 1
        elif bet_value == "high" and 19 <= number <= 36:
            win = True
            payout = 1
    elif bet_type == "dozen" and bet_value in ("1", "2", "3"):
        d = int(bet_value)
        lo = (d - 1) * 12 + 1
        hi = d * 12
        if lo <= number <= hi:
            win = True
            payout = 2
    elif bet_type == "number":
        try:
            n = int(bet_value)
            if 0 <= n <= 36 and n == number:
                win = True
                payout = 35
        except (TypeError, ValueError):
            return jsonify({"error": "Ungültige Zahl."}), 400
    else:
        return jsonify({"error": "Ungültige Wette."}), 400

    acc_row = get_current_account()
    new_balance = None
    ts = None
    if acc_row and bet > 0:
        if win:
            delta = bet * payout
            text = f"Gewinn ({payout}:1)"
        else:
            delta = -bet
            text = "Verlust"
        new_balance, ts = update_account_balance(delta, {
            "time": now_iso(), "game": "🎰 Roulette",
            "text": f"{number} {color} · {text}", "amount": bet, "win": win,
        })
    return jsonify({"number": number, "color": color, "win": win, "payout": payout, "new_balance": new_balance, "last_update": ts, "logged_in": bool(acc_row)})

@app.route("/api/crossy", methods=["POST"])
def crossy():
    data = request.get_json(silent=True) or {}
    result = data.get("result", "")
    profit = float(data.get("profit", 0) or 0)
    steps = int(data.get("steps", 0) or 0)
    if result not in ("win", "lose"):
        return jsonify({"error": "Ungültiges Ergebnis."}), 400
    acc_row = get_current_account()
    new_balance = None
    ts = None
    if acc_row and profit != 0:
        text = f"{steps} Schritte" if result == "win" else f"Crash bei Schritt {steps}"
        new_balance, ts = update_account_balance(profit, {
            "time": now_iso(), "game": "🐔 Chicken Road",
            "text": text, "amount": abs(profit), "win": result == "win",
        })
    return jsonify({"ok": True, "new_balance": new_balance, "last_update": ts, "logged_in": bool(acc_row)})

@app.route("/api/slots", methods=["POST"])
def slots():
    data = request.get_json(silent=True) or {}
    bet = float(data.get("bet", 0) or 0)
    if bet <= 0:
        return jsonify({"error": "Einsatz muss größer als 0 sein."}), 400
    acc_row = get_current_account()
    if acc_row and bet > row_get(acc_row, "balance", 0.0):
        return jsonify({"error": "Nicht genug Guthaben."}), 400
    symbols = [secrets.choice(SLOT_SYMBOLS) for _ in range(3)]
    ids = [s["id"] for s in symbols]
    multiplier = 0
    result_type = "lose"
    if ids[0] == ids[1] == ids[2]:
        multiplier = symbols[0]["payout3"]
        result_type = "jackpot"
    elif ids[0] == ids[1] or ids[1] == ids[2] or ids[0] == ids[2]:
        multiplier = 1.5
        result_type = "win"
    payout_total = bet * multiplier
    net_profit = payout_total - bet
    new_balance = None
    ts = None
    if acc_row:
        new_balance, ts = update_account_balance(net_profit, {
            "time": now_iso(), "game": "🎰 Slots",
            "text": f"{' × '.join([s['emoji'] for s in symbols])} {'×' + str(multiplier) if multiplier > 0 else ''}".strip(),
            "amount": bet, "win": multiplier > 0,
        })
    return jsonify({
        "symbols": [{"id": s["id"], "emoji": s["emoji"]} for s in symbols],
        "result_type": result_type, "multiplier": multiplier,
        "net_profit": net_profit, "payout_total": payout_total, "bet": bet,
        "new_balance": new_balance, "last_update": ts, "logged_in": bool(acc_row),
    })

@app.route("/api/slider", methods=["POST"])
def slider():
    data = request.get_json(silent=True) or {}
    bet = float(data.get("bet", 0) or 0)
    direction = data.get("direction", "over").lower()
    target = data.get("target", None)
    if bet <= 0:
        return jsonify({"error": "Einsatz muss größer als 0 sein."}), 400
    if direction not in ("over", "under"):
        return jsonify({"error": "Richtung muss 'over' oder 'under' sein."}), 400
    try:
        target = float(target)
    except (TypeError, ValueError):
        return jsonify({"error": "Ungültiges Ziel."}), 400
    if not (0 <= target <= 100):
        return jsonify({"error": "Ziel muss zwischen 0 und 100 liegen."}), 400
    if direction == "over":
        win_chance = 100 - target
    else:
        win_chance = target
    if win_chance < 0.01:
        return jsonify({"error": "Ziel zu extrem."}), 400
    multiplier = 99.0 / win_chance
    roll = secrets.randbelow(10001) / 100.0
    if direction == "over":
        win = roll > target
    else:
        win = roll < target
    acc_row = get_current_account()
    if acc_row and bet > row_get(acc_row, "balance", 0.0):
        return jsonify({"error": "Nicht genug Guthaben."}), 400
    if win:
        net_profit = bet * (multiplier - 1)
    else:
        net_profit = -bet
    text = f"{direction} {target:.2f} → roll {roll:.2f}"
    new_balance = None
    ts = None
    if acc_row:
        new_balance, ts = update_account_balance(net_profit, {
            "time": now_iso(), "game": "🎚️ Slider",
            "text": text, "amount": bet, "win": win,
        })
    return jsonify({
        "roll": roll, "target": target, "direction": direction, "win": win,
        "multiplier": round(multiplier, 2), "win_chance": round(win_chance, 2),
        "net_profit": net_profit, "bet": bet,
        "new_balance": new_balance, "last_update": ts, "logged_in": bool(acc_row),
    })

# =================================================
# START
# =================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
