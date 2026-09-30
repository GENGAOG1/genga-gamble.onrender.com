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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
