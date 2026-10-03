import os
import re
import json
import secrets
import sqlite3
import string
import socket
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

SLOT_SYMBOLS = [
    {"id": "cherry",  "emoji": "🍒", "payout3": 5},
    {"id": "lemon",   "emoji": "🍋", "payout3": 8},
    {"id": "grape",   "emoji": "🍇", "payout3": 12},
    {"id": "star",    "emoji": "⭐", "payout3": 20},
    {"id": "seven",   "emoji": "7️⃣", "payout3": 50},
    {"id": "diamond", "emoji": "💎", "payout3": 100},
]

def get_db():
    if "db" not in g:
        if TURSO_URL and TURSO_TOKEN:
            g.db = libsql.connect(database=TURSO_URL, auth_token=TURSO_TOKEN)
        else:
            g.db = sqlite3.connect("accounts.db")
            print("⚠️ WARNUNG: Nutze lokale SQLite (Accounts gehen bei Deploy verloren!)")
        g.db.row_factory = sqlite3.Row
        try:
            g.db.execute("PRAGMA foreign_keys = ON")
        except Exception:
            pass
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            code TEXT NOT NULL,
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
    try:
        cols = [r[1] for r in db.execute("PRAGMA table_info(guests)").fetchall()]
        if "username" not in cols:
            db.execute("ALTER TABLE guests ADD COLUMN username TEXT")
            print("✅ Migration: guests.username hinzugefügt")
    except Exception as e:
        print(f"Migration guests.username: {e}")

    for table in ("accounts", "guests"):
        try:
            cols = [r[1] for r in db.execute(f"PRAGMA table_info({table})").fetchall()]
            if "last_update" not in cols:
                db.execute(f"ALTER TABLE {table} ADD COLUMN last_update TEXT NOT NULL DEFAULT ''")
        except Exception as e:
            print(f"Migration {table}.last_update: {e}")
    db.commit()
    print("✅ Datenbank initialisiert (Turso)" if TURSO_URL else "✅ Datenbank initialisiert (lokal)")

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
    if row and (exclude_account_id is None or row["id"] != exclude_account_id):
        return True
    row = db.execute("SELECT id FROM guests WHERE username = ?", (username,)).fetchone()
    if row and (exclude_guest_id is None or row["id"] != exclude_guest_id):
        return True
    return False

def account_to_dict(row):
    try:
        history = json.loads(row["history"] or "[]")
    except Exception:
        history = []
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "balance": row["balance"],
        "history": history,
        "last_update": row["last_update"] if "last_update" in row.keys() else "",
    }

def guest_to_dict(row):
    try:
        history = json.loads(row["history"] or "[]")
    except Exception:
        history = []
    return {
        "id": row["id"],
        "username": row["username"] if "username" in row.keys() else None,
        "balance": row["balance"],
        "history": history,
        "created_at": row["created_at"],
        "last_seen": row["last_seen"],
        "last_update": row["last_update"] if "last_update" in row.keys() else "",
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
        history = json.loads(row["history"] or "[]")
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
        history = json.loads(row["history"] or "[]")
    except Exception:
        history = []
    history.insert(0, entry)
    history = history[:50]
    db.execute("UPDATE guests SET history = ? WHERE id = ?", (json.dumps(history), guest_id))

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
    guests_rows = db.execute("""
        SELECT * FROM guests
        ORDER BY
            CASE WHEN username IS NULL THEN 1 ELSE 0 END,
            last_seen DESC
    """).fetchall()

    accounts = [{
        "type": "account",
        "id": r["id"],
        "name": r["username"],
        "email": r["email"],
        "balance": r["balance"],
        "created_at": r["created_at"],
    } for r in accounts_rows]

    guests = [{
        "type": "guest",
        "id": r["id"],
        "name": (r["username"] if "username" in r.keys() and r["username"] else None),
        "has_name": bool(r["username"]) if "username" in r.keys() else False,
        "email": "-",
        "balance": r["balance"],
        "created_at": r["created_at"],
        "last_seen": r["last_seen"],
    } for r in guests_rows]

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

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    start_balance = data.get("start_balance", None)
    start_history = data.get("start_history", None)

    if not username or len(username) < 3:
        return jsonify({"error": "Nutzername muss mind. 3 Zeichen haben."}), 400
    if len(username) > 20:
        return jsonify({"error": "Nutzername darf max. 20 Zeichen haben."}), 400
    if not re.match(r"^[A-Za-z0-9_\-]+$", username):
        return jsonify({"error": "Nur Buchstaben, Zahlen, _ und - erlaubt."}), 400

    ok, msg = check_email(email)
    if not ok:
        return jsonify({"error": msg}), 400

    db = get_db()
    if username_exists(db, username):
        return jsonify({"error": "Nutzername ist schon vergeben."}), 409

    code = generate_code(6)
    while db.execute("SELECT id FROM accounts WHERE code = ?", (code,)).fetchone():
        code = generate_code(6)

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
        "INSERT INTO accounts (username, email, code, balance, history, created_at, last_update) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (username, email, code, balance, json.dumps(history), ts, ts)
    )
    db.commit()
    acc_id = cur.lastrowid
    session.clear()
    session["account_id"] = acc_id
    session.permanent = True
    print(f"✅ Registrierung: {username} (ID {acc_id})")
    return jsonify({"ok": True, "username": username, "code": code, "balance": balance, "last_update": ts})

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    code = (data.get("code") or "").strip().upper()
    if not username or not code:
        return jsonify({"error": "Nutzername und Code nötig."}), 400

    db = get_db()
    row = db.execute("SELECT * FROM accounts WHERE username = ? AND code = ?", (username, code)).fetchone()
    if not row:
        return jsonify({"error": "Nutzername oder Code falsch."}), 401

    session.clear()
    session["account_id"] = row["id"]
    session.permanent = True
    print(f"✅ Login: {row['username']} (ID {row['id']})")
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

@app.route("/api/update_code", methods=["POST"])
@login_required
def update_code():
    row = get_current_account()
    db = get_db()
    data = request.get_json(silent=True) or {}
    new_code = (data.get("new_code") or "").strip().upper()
    if not re.match(r"^[A-Z0-9]{4,12}$", new_code):
        return jsonify({"error": "Code muss 4–12 Zeichen (A-Z, 0-9) haben."}), 400
    if db.execute("SELECT id FROM accounts WHERE code = ? AND id != ?", (new_code, row["id"])).fetchone():
        return jsonify({"error": "Code ist schon vergeben."}), 409
    db.execute("UPDATE accounts SET code = ? WHERE id = ?", (new_code, row["id"]))
    db.commit()
    return jsonify({"ok": True, "code": new_code})

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
    db.execute("UPDATE accounts SET email = ? WHERE id = ?", (email, row["id"]))
    db.commit()
    return jsonify({"ok": True, "email": email})

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
        users.append({"type": "account", "id": r["id"], "username": r["username"]})
    for r in guest_rows:
        users.append({"type": "guest", "id": r["id"], "username": r["username"]})

    return jsonify({"users": users[:15]})

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
        return jsonify({"error": "Betrag zu hoch (max. 1.000.000 €)."}), 400
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
        sender_username = g["username"] if "username" in g.keys() else None
        if not sender_username:
            return jsonify({"error": "Du brauchst erst einen Namen, um Geld zu senden."}), 400
        sender_type = "guest"
        sender_row = g

    recipient_type, recipient_row = get_any_user_by_name(recipient_name)
    if not recipient_type:
        return jsonify({"error": f"Empfänger '{recipient_name}' nicht gefunden."}), 404

    sender_id = sender_row["id"]
    recipient_id = recipient_row["id"]

    if str(sender_id) == str(recipient_id) and sender_type == recipient_type:
        return jsonify({"error": "Du kannst dir nicht selbst Geld senden."}), 400

    if sender_row["balance"] < amount:
        return jsonify({"error": f"Nicht genug Guthaben. Du hast {sender_row['balance']:.2f} €."}), 400

    db = get_db()
    ts = now_iso()
    sender_name = sender_row["username"] if "username" in sender_row.keys() and sender_row["username"] else "Gast"
    recipient_display = recipient_row["username"] if "username" in recipient_row.keys() and recipient_row["username"] else "Gast"
    msg = (data.get("message") or "").strip()[:100]

    try:
        new_sender_balance = sender_row["balance"] - amount
        if sender_type == "account":
            db.execute("UPDATE accounts SET balance = ?, last_update = ? WHERE id = ?",
                       (new_sender_balance, ts, sender_id))
        else:
            db.execute("UPDATE guests SET balance = ?, last_update = ? WHERE id = ?",
                       (new_sender_balance, ts, sender_id))

        new_recipient_balance = recipient_row["balance"] + amount
        if recipient_type == "account":
            db.execute("UPDATE accounts SET balance = ?, last_update = ? WHERE id = ?",
                       (new_recipient_balance, ts, recipient_id))
        else:
            db.execute("UPDATE guests SET balance = ?, last_update = ? WHERE id = ?",
                       (new_recipient_balance, ts, recipient_id))

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
        print(f"✅ Pay OK: {sender_name} ({sender_type}) → {recipient_display} ({recipient_type}): {amount:.2f} €")

        return jsonify({
            "ok": True,
            "sender_balance": new_sender_balance,
            "recipient": recipient_display,
            "recipient_type": recipient_type,
            "amount": amount,
            "last_update": ts
        })

    except Exception as e:
        db.rollback()
        print(f"❌ Pay-Fehler: {type(e).__name__}: {e}")
        return jsonify({"error": f"Buchungsfehler: {str(e)}"}), 500

def update_account_balance(delta, history_entry=None):
    row = get_current_account()
    if not row:
        print("⚠️ Kein Account in Session — Guthaben kann nicht gespeichert werden!")
        return None, None
    db = get_db()
    new_balance = row["balance"] + delta
    try:
        history = json.loads(row["history"] or "[]")
    except Exception:
        history = []
    if history_entry:
        history.insert(0, history_entry)
        history = history[:50]
    ts = now_iso()
    db.execute("UPDATE accounts SET balance = ?, history = ?, last_update = ? WHERE id = ?",
               (new_balance, json.dumps(history), ts, row["id"]))
    db.commit()
    print(f"✅ Account {row['id']} ({row['username']}): {row['balance']:.2f} → {new_balance:.2f} €")
    return new_balance, ts

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
    if acc_row and bet > acc_row["balance"]:
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
    if acc_row and bet > acc_row["balance"]:
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

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
