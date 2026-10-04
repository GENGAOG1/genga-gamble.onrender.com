import os
import re
import json
import secrets
import sqlite3
import string
import socket
import hashlib
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

def hash_password(password):
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    return f"{salt}${pwd_hash}"

def verify_password(password, stored):
    if not stored or '$' not in stored:
        return False
    try:
        salt, pwd_hash = stored.split('$', 1)
        check = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
        return secrets.compare_digest(check, pwd_hash)
    except Exception:
        return False

def get_db():
    if "db" not in g:
        if USE_TURSO:
            g.db = libsql.connect(database=TURSO_URL, auth_token=TURSO_TOKEN)
        else:
            g.db = sqlite3.connect("accounts.db")
        # Kein row_factory bei Turso!
        if not USE_TURSO:
            g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        try: db.close()
        except Exception: pass

def ensure_tables():
    """Legt Tabellen an. Wird bei jedem Request kurz geprüft."""
    db = get_db()
    try:
        db.execute("""
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
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS guests (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                balance REAL NOT NULL DEFAULT 100.0,
                history TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_update TEXT NOT NULL DEFAULT ''
            )
        """)
        db.commit()
    except Exception as e:
        print(f"ensure_tables: {e}")

def now_iso():
    return datetime.utcnow().isoformat()

def generate_code(n=6):
    a = string.ascii_uppercase + string.digits
    a = a.replace("O","").replace("0","").replace("I","").replace("1","")
    return "".join(secrets.choice(a) for _ in range(n))

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-]{3,20}$")

def check_email(email):
    if not EMAIL_RE.match(email):
        return False, "E-Mail-Format ungültig."
    try:
        socket.getaddrinfo(email.split("@")[1], None)
        return True, "OK"
    except Exception:
        return False, "E-Mail-Domain existiert nicht."

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("account_id"):
            return jsonify({"error": "Nicht eingeloggt."}), 401
        return f(*a, **k)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("is_admin"):
            return jsonify({"error": "Admin-Login nötig."}), 401
        return f(*a, **k)
    return w

# =================================================
# ACCOUNT / GUEST - DIREKTE SPALTENZUGRIFFE
# =================================================
def fetch_account_by_id(acc_id):
    """Gibt (id, username, email, balance, history, last_update) zurück oder None."""
    db = get_db()
    row = db.execute(
        "SELECT id, username, email, password_hash, balance, history, last_update FROM accounts WHERE id = ?",
        (acc_id,)
    ).fetchone()
    if not row:
        return None
    return {
        "id": row[0],
        "username": row[1] or "",
        "email": row[2] or "",
        "password_hash": row[3] or "",
        "balance": row[4] if row[4] is not None else 0.0,
        "history": row[5] or "[]",
        "last_update": row[6] or "",
    }

def fetch_account_by_name(username):
    db = get_db()
    row = db.execute(
        "SELECT id, username, email, password_hash, balance, history, last_update FROM accounts WHERE username = ?",
        (username,)
    ).fetchone()
    if not row:
        return None
    return {
        "id": row[0],
        "username": row[1] or "",
        "email": row[2] or "",
        "password_hash": row[3] or "",
        "balance": row[4] if row[4] is not None else 0.0,
        "history": row[5] or "[]",
        "last_update": row[6] or "",
    }

def fetch_guest_by_id(guest_id):
    db = get_db()
    row = db.execute(
        "SELECT id, username, balance, history, created_at, last_seen, last_update FROM guests WHERE id = ?",
        (guest_id,)
    ).fetchone()
    if not row:
        return None
    return {
        "id": row[0],
        "username": row[1],
        "balance": row[2] if row[2] is not None else 0.0,
        "history": row[3] or "[]",
        "created_at": row[4] or "",
        "last_seen": row[5] or "",
        "last_update": row[6] or "",
    }

def account_to_dict(acc):
    if not acc:
        return None
    try:
        history = json.loads(acc["history"] or "[]")
    except Exception:
        history = []
    return {
        "id": acc["id"],
        "username": acc["username"],
        "email": acc["email"],
        "balance": acc["balance"],
        "history": history,
        "last_update": acc["last_update"],
    }

def guest_to_dict(g):
    if not g:
        return None
    try:
        history = json.loads(g["history"] or "[]")
    except Exception:
        history = []
    return {
        "id": g["id"],
        "username": g["username"],
        "balance": g["balance"],
        "history": history,
        "created_at": g["created_at"],
        "last_seen": g["last_seen"],
        "last_update": g["last_update"],
    }

def get_current_account():
    acc_id = session.get("account_id")
    if not acc_id:
        return None
    return fetch_account_by_id(acc_id)

def username_exists(username, exclude_account_id=None, exclude_guest_id=None):
    db = get_db()
    row = db.execute("SELECT id FROM accounts WHERE username = ?", (username,)).fetchone()
    if row:
        if exclude_account_id is None or str(row[0]) != str(exclude_account_id):
            return True
    row = db.execute("SELECT id FROM guests WHERE username = ?", (username,)).fetchone()
    if row:
        if exclude_guest_id is None or str(row[0]) != str(exclude_guest_id):
            return True
    return False

def get_any_user_by_name(username):
    acc = fetch_account_by_name(username)
    if acc:
        return ("account", acc)
    db = get_db()
    row = db.execute(
        "SELECT id, username, balance, history, created_at, last_seen, last_update FROM guests WHERE username = ? COLLATE NOCASE",
        (username,)
    ).fetchone()
    if row:
        return ("guest", {
            "id": row[0], "username": row[1],
            "balance": row[2] if row[2] is not None else 0.0,
            "history": row[3] or "[]",
            "created_at": row[4] or "", "last_seen": row[5] or "",
            "last_update": row[6] or "",
        })
    return (None, None)

def add_history_to_account(acc_id, entry):
    acc = fetch_account_by_id(acc_id)
    if not acc:
        return
    try:
        history = json.loads(acc["history"] or "[]")
    except Exception:
        history = []
    history.insert(0, entry)
    history = history[:50]
    db = get_db()
    db.execute("UPDATE accounts SET history = ? WHERE id = ?", (json.dumps(history), acc_id))

def add_history_to_guest(guest_id, entry):
    g = fetch_guest_by_id(guest_id)
    if not g:
        return
    try:
        history = json.loads(g["history"] or "[]")
    except Exception:
        history = []
    history.insert(0, entry)
    history = history[:50]
    db = get_db()
    db.execute("UPDATE guests SET history = ? WHERE id = ?", (json.dumps(history), guest_id))

# =================================================
# ROUTEN
# =================================================
@app.route("/")
def index():
    ensure_tables()
    return render_template("index.html")

@app.route("/admin")
def admin_page():
    ensure_tables()
    return render_template("admin.html")

@app.route("/service-worker.js")
def service_worker():
    return send_from_directory(app.static_folder, "service-worker.js", mimetype="application/javascript")

@app.route("/manifest.json")
def manifest():
    return send_from_directory(app.static_folder, "manifest.json", mimetype="application/manifest+json")

# ---- DEBUG ----
@app.route("/api/debug/init")
def debug_init():
    ensure_tables()
    return jsonify({"ok": True})

@app.route("/api/debug/inspect")
def debug_inspect():
    ensure_tables()
    db = get_db()
    result = {"tables": [], "accounts": [], "guests": []}
    try:
        rows = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        result["tables"] = [r[0] for r in rows]
    except Exception as e:
        result["tables_error"] = str(e)

    try:
        rows = db.execute("SELECT id, username, email, balance FROM accounts").fetchall()
        result["accounts"] = [{"id": r[0], "username": r[1], "email": r[2], "balance": r[3]} for r in rows]
    except Exception as e:
        result["accounts_error"] = str(e)

    try:
        rows = db.execute("SELECT id, username, balance FROM guests").fetchall()
        result["guests"] = [{"id": r[0], "username": r[1], "balance": r[2]} for r in rows]
    except Exception as e:
        result["guests_error"] = str(e)

    return jsonify(result)

# ---- ADMIN ----
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

@app.route("/api/admin/check")
def admin_check():
    return jsonify({"is_admin": bool(session.get("is_admin"))})

@app.route("/api/admin/data")
@admin_required
def admin_data():
    ensure_tables()
    db = get_db()
    acc_rows = db.execute("SELECT id, username, email, balance, created_at FROM accounts ORDER BY created_at DESC").fetchall()
    guest_rows = db.execute("SELECT id, username, balance, created_at, last_seen FROM guests ORDER BY last_seen DESC").fetchall()

    accounts = [{
        "type": "account",
        "id": r[0],
        "name": r[1] or "Unbekannt",
        "email": r[2] or "-",
        "balance": r[3] if r[3] is not None else 0.0,
        "created_at": r[4] or "",
    } for r in acc_rows]

    guests = [{
        "type": "guest",
        "id": r[0],
        "name": r[1] if r[1] else None,
        "has_name": bool(r[1]),
        "email": "-",
        "balance": r[2] if r[2] is not None else 0.0,
        "created_at": r[3] or "",
        "last_seen": r[4] or "",
    } for r in guest_rows]

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
    elif kind == "guest":
        db.execute("UPDATE guests SET balance = ?, last_update = ? WHERE id = ?", (new_balance, ts, target_id))
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

# ---- AUTH ----
@app.route("/api/register", methods=["POST"])
def register():
    ensure_tables()
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    start_balance = data.get("start_balance")
    start_history = data.get("start_history")

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
    if username_exists(username):
        return jsonify({"error": "Nutzername ist schon vergeben."}), 409

    pwd_hash = hash_password(password)

    try:
        balance = float(start_balance) if start_balance is not None else 100.0
    except (TypeError, ValueError):
        balance = 100.0
    if balance < 0: balance = 100.0

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
    acc_id = None
    try: acc_id = cur.lastrowid
    except Exception: pass
    if not acc_id:
        row = db.execute("SELECT id FROM accounts WHERE username = ?", (username,)).fetchone()
        if row: acc_id = row[0]

    session.clear()
    session["account_id"] = acc_id
    session.permanent = True
    return jsonify({"ok": True, "username": username, "balance": balance, "last_update": ts})

@app.route("/api/login", methods=["POST"])
def login():
    ensure_tables()
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "Nutzername und Passwort nötig."}), 400

    acc = fetch_account_by_name(username)
    if not acc:
        return jsonify({"error": "Nutzername oder Passwort falsch."}), 401
    if not verify_password(password, acc["password_hash"]):
        return jsonify({"error": "Nutzername oder Passwort falsch."}), 401

    session.clear()
    session["account_id"] = acc["id"]
    session.permanent = True
    return jsonify({"ok": True, "account": account_to_dict(acc)})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.pop("account_id", None)
    return jsonify({"ok": True})

@app.route("/api/me")
def me():
    ensure_tables()
    acc = get_current_account()
    if not acc:
        return jsonify({"logged_in": False})
    return jsonify({"logged_in": True, "account": account_to_dict(acc)})

@app.route("/api/update_password", methods=["POST"])
@login_required
def update_password():
    acc = get_current_account()
    db = get_db()
    data = request.get_json(silent=True) or {}
    old_p = data.get("old_password") or ""
    new_p = data.get("new_password") or ""
    if not verify_password(old_p, acc["password_hash"]):
        return jsonify({"error": "Altes Passwort falsch."}), 401
    if not new_p or len(new_p) < 6:
        return jsonify({"error": "Neues Passwort muss mind. 6 Zeichen haben."}), 400
    db.execute("UPDATE accounts SET password_hash = ? WHERE id = ?", (hash_password(new_p), acc["id"]))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/update_email", methods=["POST"])
@login_required
def update_email():
    acc = get_current_account()
    db = get_db()
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    ok, msg = check_email(email)
    if not ok:
        return jsonify({"error": msg}), 400
    db.execute("UPDATE accounts SET email = ? WHERE id = ?", (email, acc["id"]))
    db.commit()
    return jsonify({"ok": True, "email": email})

# ---- GÄSTE ----
@app.route("/api/guest/create", methods=["POST"])
def guest_create():
    ensure_tables()
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
    ensure_tables()
    data = request.get_json(silent=True) or {}
    guest_id = (data.get("guest_id") or "").strip()
    balance = data.get("balance")
    history = data.get("history")
    if not guest_id:
        return jsonify({"error": "guest_id fehlt."}), 400
    try: balance = float(balance)
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
    ensure_tables()
    data = request.get_json(silent=True) or {}
    guest_id = (data.get("guest_id") or "").strip()
    if not guest_id:
        return jsonify({"error": "guest_id fehlt."}), 400
    g = fetch_guest_by_id(guest_id)
    if not g:
        return jsonify({"exists": False})
    return jsonify({"exists": True, "guest": guest_to_dict(g)})

@app.route("/api/guest/set_name", methods=["POST"])
def guest_set_name():
    ensure_tables()
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
    if username_exists(username, exclude_guest_id=guest_id):
        return jsonify({"error": "Name ist schon vergeben."}), 409

    db.execute("UPDATE guests SET username = ? WHERE id = ?", (username, guest_id))
    db.commit()
    return jsonify({"ok": True, "username": username})

# ---- USER SEARCH ----
@app.route("/api/users/search", methods=["POST"])
def users_search():
    ensure_tables()
    data = request.get_json(silent=True) or {}
    query = (data.get("q") or "").strip()
    my_guest_id = (data.get("guest_id") or "").strip()
    my_account_id = session.get("account_id")

    if len(query) < 1:
        return jsonify({"users": []})

    db = get_db()
    like = f"%{query}%"
    users = []

    rows = db.execute(
        "SELECT id, username FROM accounts WHERE username LIKE ? AND id != ? LIMIT 10",
        (like, my_account_id if my_account_id else -1)
    ).fetchall()
    for r in rows:
        users.append({"type": "account", "id": r[0], "username": r[1]})

    rows = db.execute(
        "SELECT id, username FROM guests WHERE username LIKE ? AND username IS NOT NULL AND id != ? LIMIT 10",
        (like, my_guest_id if my_guest_id else "")
    ).fetchall()
    for r in rows:
        users.append({"type": "guest", "id": r[0], "username": r[1]})

    return jsonify({"users": users[:15]})

# ---- PAY ----
@app.route("/api/pay", methods=["POST"])
def pay():
    ensure_tables()
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

    acc = get_current_account()
    sender_type = None
    sender = None

    if acc:
        sender_type = "account"
        sender = acc
    else:
        guest_id = (data.get("guest_id") or "").strip()
        if not guest_id:
            return jsonify({"error": "Nicht eingeloggt."}), 401
        g = fetch_guest_by_id(guest_id)
        if not g:
            return jsonify({"error": "Gast nicht gefunden."}), 404
        if not g["username"]:
            return jsonify({"error": "Du brauchst erst einen Namen."}), 400
        sender_type = "guest"
        sender = g

    rec_type, rec = get_any_user_by_name(recipient_name)
    if not rec_type:
        return jsonify({"error": f"Empfänger '{recipient_name}' nicht gefunden."}), 404

    if str(sender["id"]) == str(rec["id"]) and sender_type == rec_type:
        return jsonify({"error": "Du kannst dir nicht selbst Geld senden."}), 400

    if sender["balance"] < amount:
        return jsonify({"error": f"Nicht genug Guthaben. Du hast {sender['balance']:.2f} €."}), 400

    db = get_db()
    ts = now_iso()
    s_name = sender["username"] or "Gast"
    r_name = rec["username"] or "Gast"
    msg = (data.get("message") or "").strip()[:100]

    try:
        new_sender = sender["balance"] - amount
        if sender_type == "account":
            db.execute("UPDATE accounts SET balance = ?, last_update = ? WHERE id = ?", (new_sender, ts, sender["id"]))
        else:
            db.execute("UPDATE guests SET balance = ?, last_update = ? WHERE id = ?", (new_sender, ts, sender["id"]))

        new_rec = rec["balance"] + amount
        if rec_type == "account":
            db.execute("UPDATE accounts SET balance = ?, last_update = ? WHERE id = ?", (new_rec, ts, rec["id"]))
        else:
            db.execute("UPDATE guests SET balance = ?, last_update = ? WHERE id = ?", (new_rec, ts, rec["id"]))

        send_text = f"an {r_name}" + (f" · \"{msg}\"" if msg else "")
        rec_text = f"von {s_name}" + (f" · \"{msg}\"" if msg else "")

        if sender_type == "account":
            add_history_to_account(sender["id"], {"time": ts, "game": "💸 Gesendet", "text": send_text, "amount": amount, "win": False})
        else:
            add_history_to_guest(sender["id"], {"time": ts, "game": "💸 Gesendet", "text": send_text, "amount": amount, "win": False})

        if rec_type == "account":
            add_history_to_account(rec["id"], {"time": ts, "game": "💰 Erhalten", "text": rec_text, "amount": amount, "win": True})
        else:
            add_history_to_guest(rec["id"], {"time": ts, "game": "💰 Erhalten", "text": rec_text, "amount": amount, "win": True})

        db.commit()
        return jsonify({
            "ok": True, "sender_balance": new_sender,
            "recipient": r_name, "recipient_type": rec_type,
            "amount": amount, "last_update": ts
        })
    except Exception as e:
        try: db.rollback()
        except Exception: pass
        return jsonify({"error": f"Buchungsfehler: {str(e)}"}), 500

# ---- GUTHABEN ----
def update_account_balance(delta, history_entry=None):
    acc = get_current_account()
    if not acc:
        return None, None
    db = get_db()
    new_balance = acc["balance"] + delta
    try:
        history = json.loads(acc["history"] or "[]")
    except Exception:
        history = []
    if history_entry:
        history.insert(0, history_entry)
        history = history[:50]
    ts = now_iso()
    db.execute("UPDATE accounts SET balance = ?, history = ?, last_update = ? WHERE id = ?",
               (new_balance, json.dumps(history), ts, acc["id"]))
    db.commit()
    return new_balance, ts

# ---- SPIELE ----
@app.route("/api/coinflip", methods=["POST"])
def coinflip():
    ensure_tables()
    data = request.get_json(silent=True) or {}
    choice = data.get("choice", "").lower()
    bet = float(data.get("bet", 0) or 0)
    if choice not in ("kopf", "zahl"):
        return jsonify({"error": "Bitte 'kopf' oder 'zahl' wählen."}), 400
    result = secrets.choice(["kopf", "zahl"])
    win = result == choice
    acc = get_current_account()
    new_balance = None; ts = None
    if acc and bet > 0:
        delta = bet if win else -bet
        new_balance, ts = update_account_balance(delta, {
            "time": now_iso(), "game": "🪙 Coinflip",
            "text": f"{choice} → {result}", "amount": bet, "win": win,
        })
    return jsonify({"choice": choice, "result": result, "win": win, "new_balance": new_balance, "last_update": ts, "logged_in": bool(acc)})

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
    ensure_tables()
    data = request.get_json(silent=True) or {}
    bet_type = data.get("bet_type", "")
    bet_value = data.get("bet_value", None)
    bet = float(data.get("bet", 0) or 0)
    number = secrets.randbelow(37)
    if number == 0: color = "green"
    elif number in ROULETTE_RED: color = "red"
    else: color = "black"
    win = False; payout = 0
    if bet_type == "color" and bet_value in ("red", "black"):
        if color == bet_value: win = True; payout = 1
    elif bet_type == "parity" and bet_value in ("even", "odd"):
        if number != 0:
            is_even = number % 2 == 0
            if (bet_value == "even" and is_even) or (bet_value == "odd" and not is_even):
                win = True; payout = 1
    elif bet_type == "range" and bet_value in ("low", "high"):
        if bet_value == "low" and 1 <= number <= 18: win = True; payout = 1
        elif bet_value == "high" and 19 <= number <= 36: win = True; payout = 1
    elif bet_type == "dozen" and bet_value in ("1", "2", "3"):
        d = int(bet_value); lo = (d - 1) * 12 + 1; hi = d * 12
        if lo <= number <= hi: win = True; payout = 2
    elif bet_type == "number":
        try:
            n = int(bet_value)
            if 0 <= n <= 36 and n == number: win = True; payout = 35
        except (TypeError, ValueError):
            return jsonify({"error": "Ungültige Zahl."}), 400
    else:
        return jsonify({"error": "Ungültige Wette."}), 400

    acc = get_current_account()
    new_balance = None; ts = None
    if acc and bet > 0:
        if win: delta = bet * payout; text = f"Gewinn ({payout}:1)"
        else: delta = -bet; text = "Verlust"
        new_balance, ts = update_account_balance(delta, {
            "time": now_iso(), "game": "🎰 Roulette",
            "text": f"{number} {color} · {text}", "amount": bet, "win": win,
        })
    return jsonify({"number": number, "color": color, "win": win, "payout": payout, "new_balance": new_balance, "last_update": ts, "logged_in": bool(acc)})

@app.route("/api/crossy", methods=["POST"])
def crossy():
    ensure_tables()
    data = request.get_json(silent=True) or {}
    result = data.get("result", "")
    profit = float(data.get("profit", 0) or 0)
    steps = int(data.get("steps", 0) or 0)
    if result not in ("win", "lose"):
        return jsonify({"error": "Ungültiges Ergebnis."}), 400
    acc = get_current_account()
    new_balance = None; ts = None
    if acc and profit != 0:
        text = f"{steps} Schritte" if result == "win" else f"Crash bei Schritt {steps}"
        new_balance, ts = update_account_balance(profit, {
            "time": now_iso(), "game": "🐔 Chicken Road",
            "text": text, "amount": abs(profit), "win": result == "win",
        })
    return jsonify({"ok": True, "new_balance": new_balance, "last_update": ts, "logged_in": bool(acc)})

@app.route("/api/slots", methods=["POST"])
def slots():
    ensure_tables()
    data = request.get_json(silent=True) or {}
    bet = float(data.get("bet", 0) or 0)
    if bet <= 0:
        return jsonify({"error": "Einsatz muss größer als 0 sein."}), 400
    acc = get_current_account()
    if acc and bet > acc["balance"]:
        return jsonify({"error": "Nicht genug Guthaben."}), 400
    symbols = [secrets.choice(SLOT_SYMBOLS) for _ in range(3)]
    ids = [s["id"] for s in symbols]
    multiplier = 0; result_type = "lose"
    if ids[0] == ids[1] == ids[2]:
        multiplier = symbols[0]["payout3"]; result_type = "jackpot"
    elif ids[0] == ids[1] or ids[1] == ids[2] or ids[0] == ids[2]:
        multiplier = 1.5; result_type = "win"
    payout_total = bet * multiplier
    net_profit = payout_total - bet
    new_balance = None; ts = None
    if acc:
        new_balance, ts = update_account_balance(net_profit, {
            "time": now_iso(), "game": "🎰 Slots",
            "text": f"{' × '.join([s['emoji'] for s in symbols])} {'×' + str(multiplier) if multiplier > 0 else ''}".strip(),
            "amount": bet, "win": multiplier > 0,
        })
    return jsonify({
        "symbols": [{"id": s["id"], "emoji": s["emoji"]} for s in symbols],
        "result_type": result_type, "multiplier": multiplier,
        "net_profit": net_profit, "payout_total": payout_total, "bet": bet,
        "new_balance": new_balance, "last_update": ts, "logged_in": bool(acc),
    })

@app.route("/api/slider", methods=["POST"])
def slider():
    ensure_tables()
    data = request.get_json(silent=True) or {}
    bet = float(data.get("bet", 0) or 0)
    direction = data.get("direction", "over").lower()
    target = data.get("target", None)
    if bet <= 0:
        return jsonify({"error": "Einsatz muss größer als 0 sein."}), 400
    if direction not in ("over", "under"):
        return jsonify({"error": "Richtung muss 'over' oder 'under' sein."}), 400
    try: target = float(target)
    except (TypeError, ValueError):
        return jsonify({"error": "Ungültiges Ziel."}), 400
    if not (0 <= target <= 100):
        return jsonify({"error": "Ziel muss zwischen 0 und 100 liegen."}), 400
    win_chance = (100 - target) if direction == "over" else target
    if win_chance < 0.01:
        return jsonify({"error": "Ziel zu extrem."}), 400
    multiplier = 99.0 / win_chance
    roll = secrets.randbelow(10001) / 100.0
    win = (roll > target) if direction == "over" else (roll < target)
    acc = get_current_account()
    if acc and bet > acc["balance"]:
        return jsonify({"error": "Nicht genug Guthaben."}), 400
    net_profit = bet * (multiplier - 1) if win else -bet
    text = f"{direction} {target:.2f} → roll {roll:.2f}"
    new_balance = None; ts = None
    if acc:
        new_balance, ts = update_account_balance(net_profit, {
            "time": now_iso(), "game": "🎚️ Slider",
            "text": text, "amount": bet, "win": win,
        })
    return jsonify({
        "roll": roll, "target": target, "direction": direction, "win": win,
        "multiplier": round(multiplier, 2), "win_chance": round(win_chance, 2),
        "net_profit": net_profit, "bet": bet,
        "new_balance": new_balance, "last_update": ts, "logged_in": bool(acc),
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
