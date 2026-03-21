# ================================================================
#  CPCC Student Portal — Simple Flask Backend
#  File: app.py
#
#  HOW TO RUN:
#    1. pip install flask flask-cors bcrypt
#    2. python app.py
#    3. Open cpcc_login.html in your browser
#
#  Accounts are saved in: users.json  (created automatically)
# ================================================================

import json
import os
import re
import bcrypt
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # allows the HTML file to talk to this server

# ----------------------------------------------------------------
#  users.json  — this is where all accounts are stored
#  Format:
#  {
#    "john@cpcc.edu": {
#      "name": "John Smith",
#      "email": "john@cpcc.edu",
#      "password": "<hashed>"
#    }
#  }
# ----------------------------------------------------------------

USERS_FILE = "users.json"


def load_users():
    """Read all accounts from users.json. Returns empty dict if file doesn't exist."""
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def save_users(users):
    """Write all accounts back to users.json."""
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


# ----------------------------------------------------------------
#  VALIDATION — all rules in one place
# ----------------------------------------------------------------

ALLOWED_DOMAINS = ["@cpcc.edu", "@email.cpcc.edu"]


def is_valid_email(email):
    """Check email has correct format."""
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def is_cpcc_email(email):
    """Only allow @cpcc.edu or @email.cpcc.edu addresses."""
    return any(email.endswith(d) for d in ALLOWED_DOMAINS)


def validate_register(name, email, password, confirm):
    """
    Check all registration fields.
    Returns an error message string, or None if everything is OK.
    """
    if not name or len(name.strip()) < 2:
        return "Please enter your full name (at least 2 characters)."
    if not email:
        return "Please enter your email address."
    if not is_valid_email(email):
        return "Please enter a valid email address."
    if not is_cpcc_email(email):
        return "Only @cpcc.edu or @email.cpcc.edu addresses are allowed."
    if not password or len(password) < 6:
        return "Password must be at least 6 characters."
    if password != confirm:
        return "Passwords do not match."
    return None  # no errors!


def validate_login(email, password):
    """
    Check login fields.
    Returns an error message string, or None if everything is OK.
    """
    if not email:
        return "Please enter your email address."
    if not is_cpcc_email(email):
        return "Please use your @cpcc.edu or @email.cpcc.edu email."
    if not password:
        return "Please enter your password."
    return None  # no errors!


# ----------------------------------------------------------------
#  ROUTES
# ----------------------------------------------------------------

@app.route("/api/health")
def health():
    """Quick check that the server is running."""
    return jsonify({"success": True, "message": "Server is running!"})


@app.route("/api/register", methods=["POST"])
def register():
    """
    Create a new student account.
    Expects JSON: { name, email, password, confirm }
    Saves the account to users.json if everything is valid.
    """
    data     = request.get_json()
    name     = data.get("name", "").strip()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    confirm  = data.get("confirm", "")

    # Step 1 — validate all fields
    error = validate_register(name, email, password, confirm)
    if error:
        return jsonify({"success": False, "message": error}), 400

    # Step 2 — check if account already exists
    users = load_users()
    if email in users:
        return jsonify({
            "success": False,
            "message": "An account with this email already exists. Please sign in.",
            "hint": "login"
        }), 409

    # Step 3 — hash the password (never save plain text!)
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    # Step 4 — save to users.json
    users[email] = {
        "name":     name,
        "email":    email,
        "password": hashed
    }
    save_users(users)

    return jsonify({
        "success": True,
        "message": f"Account created! Welcome, {name}.",
        "name":    name,
        "email":   email
    }), 201


@app.route("/api/login", methods=["POST"])
def login():
    """
    Log in with email and password.
    Expects JSON: { email, password }
    Returns student name and email on success.
    """
    data     = request.get_json()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    # Step 1 — validate fields
    error = validate_login(email, password)
    if error:
        return jsonify({"success": False, "message": error}), 400

    # Step 2 — find the account
    users = load_users()
    if email not in users:
        return jsonify({
            "success": False,
            "message": "No account found for this email. Please create an account first.",
            "hint": "register"
        }), 401

    # Step 3 — check password
    user = users[email]
    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return jsonify({"success": False, "message": "Incorrect password. Please try again."}), 401

    # Step 4 — success!
    return jsonify({
        "success": True,
        "message": f"Welcome back, {user['name']}!",
        "name":    user["name"],
        "email":   user["email"]
    }), 200


# ----------------------------------------------------------------
#  START SERVER
# ----------------------------------------------------------------

if __name__ == "__main__":
    print("🚀 Server running  →  http://localhost:5000")
    print(f"💾 Accounts stored →  {USERS_FILE}")
    app.run(debug=True, port=5000)
