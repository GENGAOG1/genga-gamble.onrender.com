import secrets
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/coinflip", methods=["POST"])
def coinflip():
    data = request.get_json(silent=True) or {}
    choice = data.get("choice", "").lower()

    if choice not in ("kopf", "zahl"):
        return jsonify({"error": "Bitte 'kopf' oder 'zahl' wählen."}), 400

    result = secrets.choice(["kopf", "zahl"])
    return jsonify({
        "choice": choice,
        "result": result,
        "win": result == choice
    })

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
    return jsonify({
        "index": index,
        "result": cleaned[index],
        "options": cleaned
    })

# ---- Roulette ----
ROULETTE_RED = {1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36}

@app.route("/api/roulette", methods=["POST"])
def roulette():
    data = request.get_json(silent=True) or {}
    bet_type = data.get("bet_type", "")
    bet_value = data.get("bet_value", None)

    # Zahl 0-36
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
            payout = 1  # 1:1

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
            payout = 2  # 2:1

    elif bet_type == "number":
        try:
            n = int(bet_value)
            if 0 <= n <= 36 and n == number:
                win = True
                payout = 35  # 35:1
        except (TypeError, ValueError):
            return jsonify({"error": "Ungültige Zahl."}), 400
    else:
        return jsonify({"error": "Ungültige Wette."}), 400

    return jsonify({
        "number": number,
        "color": color,
        "win": win,
        "payout": payout
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
