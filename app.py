import json
import os
import re
import bcrypt
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

USERS_FILE = "users.json"


@app.route("/")
def index():
    return send_file("cpcc_login.html")


def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


@app.route("/api/health")
def health():
    return jsonify({"success": True, "message": "Server is running!"})


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()

    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    confirm = data.get("confirm", "")

    if not name or len(name.strip()) < 2:
        return jsonify({"success": False, "message": "Name is too short"})

    if not email:
        return jsonify({"success": False, "message": "Email is required"})

    # make sure its a real email format
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, email):
        return jsonify({"success": False, "message": "Invalid email"})

    # only let cpcc students register
    if not email.endswith("@cpcc.edu") and not email.endswith("@email.cpcc.edu"):
        return jsonify({"success": False, "message": "You need a cpcc email to register"})

    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters"})

    if password != confirm:
        return jsonify({"success": False, "message": "Passwords dont match"})

    users = load_users()

    if email in users:
        return jsonify({"success": False, "message": "Email already registered", "hint": "login"})

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    users[email] = {
        "name": name,
        "email": email,
        "password": hashed
    }
    save_users(users)

    return jsonify({"success": True, "message": f"Account created! Welcome, {name}.", "name": name, "email": email})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email:
        return jsonify({"success": False, "message": "Email is required"})

    if not email.endswith("@cpcc.edu") and not email.endswith("@email.cpcc.edu"):
        return jsonify({"success": False, "message": "Use your cpcc email"})

    if not password:
        return jsonify({"success": False, "message": "Password is required"})

    users = load_users()

    if email not in users:
        return jsonify({"success": False, "message": "No account found, register first", "hint": "register"})

    user = users[email]

    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return jsonify({"success": False, "message": "Wrong password"})

    return jsonify({"success": True, "message": f"Welcome back, {user['name']}!", "name": user["name"], "email": user["email"]})


if __name__ == "__main__":
    print("Server running at http://127.0.0.1:5000")
    app.run(debug=True, port=5000)