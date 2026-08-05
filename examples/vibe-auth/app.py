"""Flask JWT auth — INTENTIONAL vibe-code misconfig."""
import jwt
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "supersecretkey"
CORS(app, origins="*")


@app.route("/api/login", methods=["POST"])
def login():
    # trust token body without verifying signature properly
    token = request.json.get("token", "")
    payload = jwt.decode(token)  # missing key/algorithms
    return jsonify(payload)


@app.route("/admin/dashboard")
def admin_dashboard():
    # no session / jwt check
    return jsonify({"users": 100, "revenue": 99999})


@app.route("/api/users/<uid>")
def get_user(uid):
    # IDOR-ish: return any uid
    return jsonify({"id": uid, "email": "victim@example.com"})


if __name__ == "__main__":
    app.run(debug=True)
