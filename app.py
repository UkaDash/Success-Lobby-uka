# ==============================================================
#  CPCC Student Portal — Python Flask Backend
#  File: app.py
#
#  HOW TO RUN:
#    1. pip install flask flask-sqlalchemy flask-cors pymysql bcrypt pyjwt python-dotenv
#    2. Copy .env.example to .env and fill in your MySQL password
#    3. python app.py
#    4. API runs at http://localhost:5000
# ==============================================================

import os
import re
import jwt
import bcrypt
import functools
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

# Load environment variables from .env file
load_dotenv()

# ==============================================================
#  APP SETUP
# ==============================================================

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})


# ==============================================================
#  CONFIGURATION
# ==============================================================

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://"
    f"{os.getenv('DB_USER', 'root')}:{os.getenv('DB_PASSWORD', '')}@"
    f"{os.getenv('DB_HOST', 'localhost')}:{os.getenv('DB_PORT', '3306')}/"
    f"{os.getenv('DB_NAME', 'cpcc_portal')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change_this_secret")

JWT_SECRET        = os.getenv("JWT_SECRET",       "change_this_jwt_secret")
JWT_EXPIRES_DAYS  = int(os.getenv("JWT_EXPIRES_DAYS", 7))
MAX_ATTEMPTS      = 5    # lock account after 5 failed logins
LOCKOUT_MINUTES   = 15   # lockout window in minutes

# Only these email domains are allowed to register
ALLOWED_DOMAINS = ["@cpcc.edu", "@email.cpcc.edu"]


# ==============================================================
#  DATABASE MODELS
# ==============================================================

db = SQLAlchemy(app)


class Student(db.Model):
    """Stores student accounts."""
    __tablename__ = "students"

    id            = db.Column(db.Integer,     primary_key=True, autoincrement=True)
    full_name     = db.Column(db.String(150), nullable=False)
    email         = db.Column(db.String(255), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    student_id    = db.Column(db.String(20),  unique=True)
    is_active     = db.Column(db.Boolean,     default=True, nullable=False)
    created_at    = db.Column(db.DateTime,    default=datetime.utcnow)

    sessions      = db.relationship("Session",      back_populates="student", cascade="all, delete")
    enrollments   = db.relationship("Enrollment",   back_populates="student", cascade="all, delete")

    def to_dict(self):
        return {
            "id":         self.id,
            "full_name":  self.full_name,
            "email":      self.email,
            "student_id": self.student_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Session(db.Model):
    """Stores JWT sessions so we can revoke them on logout."""
    __tablename__ = "sessions"

    id         = db.Column(db.Integer,     primary_key=True, autoincrement=True)
    student_id = db.Column(db.Integer,     db.ForeignKey("students.id", ondelete="CASCADE"), nullable=False)
    token      = db.Column(db.String(512), nullable=False, unique=True)
    ip_address = db.Column(db.String(45))
    expires_at = db.Column(db.DateTime,   nullable=False)
    is_revoked = db.Column(db.Boolean,    default=False, nullable=False)
    created_at = db.Column(db.DateTime,   default=datetime.utcnow)

    student = db.relationship("Student", back_populates="sessions")


class LoginAttempt(db.Model):
    """Tracks failed logins for brute-force protection."""
    __tablename__ = "login_attempts"

    id           = db.Column(db.Integer,     primary_key=True, autoincrement=True)
    email        = db.Column(db.String(255), nullable=False)
    ip_address   = db.Column(db.String(45))
    success      = db.Column(db.Boolean,     default=False, nullable=False)
    attempted_at = db.Column(db.DateTime,    default=datetime.utcnow)


class Course(db.Model):
    """Available courses at CPCC."""
    __tablename__ = "courses"

    id          = db.Column(db.Integer,      primary_key=True, autoincrement=True)
    course_code = db.Column(db.String(20),   nullable=False, unique=True)
    course_name = db.Column(db.String(200),  nullable=False)
    credits     = db.Column(db.SmallInteger, default=3, nullable=False)
    instructor  = db.Column(db.String(150))
    semester    = db.Column(db.String(20))
    created_at  = db.Column(db.DateTime,     default=datetime.utcnow)

    enrollments = db.relationship("Enrollment", back_populates="course", cascade="all, delete")

    def to_dict(self):
        return {
            "course_code": self.course_code,
            "course_name": self.course_name,
            "credits":     self.credits,
            "instructor":  self.instructor,
            "semester":    self.semester,
        }


class Enrollment(db.Model):
    """Links students to courses (many-to-many)."""
    __tablename__  = "enrollments"
    __table_args__ = (db.UniqueConstraint("student_id", "course_id", name="uq_enrollment"),)

    id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    student_id  = db.Column(db.Integer, db.ForeignKey("students.id",  ondelete="CASCADE"), nullable=False)
    course_id   = db.Column(db.Integer, db.ForeignKey("courses.id",   ondelete="CASCADE"), nullable=False)
    grade       = db.Column(db.String(5))
    enrolled_at = db.Column(db.DateTime, default=datetime.utcnow)

    student = db.relationship("Student", back_populates="enrollments")
    course  = db.relationship("Course",  back_populates="enrollments")

    def to_dict(self):
        return {
            "course_code": self.course.course_code if self.course else None,
            "course_name": self.course.course_name if self.course else None,
            "credits":     self.course.credits     if self.course else None,
            "instructor":  self.course.instructor  if self.course else None,
            "semester":    self.course.semester    if self.course else None,
            "grade":       self.grade,
            "enrolled_at": self.enrolled_at.isoformat() if self.enrolled_at else None,
        }


# ==============================================================
#  ERROR HANDLING — ALL VALIDATION RULES IN ONE PLACE
# ==============================================================

def is_valid_cpcc_email(email: str) -> bool:
    """
    Returns True only if email ends with an allowed CPCC domain.
      Accepted: student@cpcc.edu  OR  student@email.cpcc.edu
      Rejected: student@gmail.com, student@yahoo.com, etc.
    """
    email = email.strip().lower()
    return any(email.endswith(domain) for domain in ALLOWED_DOMAINS)


def is_valid_email_format(email: str) -> bool:
    """Basic email format check (must have @, a dot, valid characters)."""
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email.strip()))


def validate_registration(name: str, email: str, password: str, confirm: str) -> list:
    """
    Validates all registration fields.
    Returns a list of error strings — empty list means everything is OK.

    Rules:
      1. Full name must not be empty
      2. Email must have a valid format
      3. Email must be a @cpcc.edu or @email.cpcc.edu address
      4. Password must be at least 6 characters
      5. Password and confirm must match
    """
    errors = []

    # Rule 1 — Name
    if not name or not name.strip():
        errors.append("Please enter your full name.")
    elif len(name.strip()) < 2:
        errors.append("Name must be at least 2 characters.")

    # Rule 2 — Email format
    if not email or not email.strip():
        errors.append("Please enter your email address.")
    elif not is_valid_email_format(email):
        errors.append("Please enter a valid email address.")
    # Rule 3 — CPCC domain
    elif not is_valid_cpcc_email(email):
        errors.append(
            "Only @cpcc.edu or @email.cpcc.edu addresses are allowed. "
            "Please use your official CPCC student email."
        )

    # Rule 4 — Password length
    if not password:
        errors.append("Please enter a password.")
    elif len(password) < 6:
        errors.append("Password must be at least 6 characters.")

    # Rule 5 — Passwords match
    if password and confirm and password != confirm:
        errors.append("Passwords do not match. Please try again.")
    elif password and not confirm:
        errors.append("Please confirm your password.")

    return errors


def validate_login(email: str, password: str) -> list:
    """
    Validates login fields before touching the database.
    Returns a list of error strings — empty list means everything is OK.

    Rules:
      1. Both fields must be filled in
      2. Email must be a CPCC address
    """
    errors = []

    if not email or not email.strip():
        errors.append("Please enter your email address.")
    if not password:
        errors.append("Please enter your password.")
    if email and not is_valid_cpcc_email(email):
        errors.append(
            "Please use your @cpcc.edu or @email.cpcc.edu student email."
        )

    return errors


# ==============================================================
#  AUTH HELPERS
# ==============================================================

def make_token(student_id: int, email: str, name: str) -> str:
    """Creates a signed JWT token that expires in JWT_EXPIRES_DAYS days."""
    payload = {
        "id":    student_id,
        "email": email,
        "name":  name,
        "exp":   datetime.utcnow() + timedelta(days=JWT_EXPIRES_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def generate_student_id(db_id: int) -> str:
    """Auto-generates a student ID like S-00001."""
    return f"S-{str(db_id).zfill(5)}"


def is_rate_limited(email: str, ip: str) -> bool:
    """Returns True if the email or IP has too many recent failed logins."""
    window = datetime.utcnow() - timedelta(minutes=LOCKOUT_MINUTES)
    count = LoginAttempt.query.filter(
        LoginAttempt.email       == email,
        LoginAttempt.success     == False,
        LoginAttempt.attempted_at >= window,
    ).count()
    return count >= MAX_ATTEMPTS


def log_attempt(email: str, ip: str, success: bool):
    """Records a login attempt in the database."""
    attempt = LoginAttempt(email=email, ip_address=ip, success=success)
    db.session.add(attempt)
    db.session.commit()


# ==============================================================
#  AUTH MIDDLEWARE (decorator for protected routes)
# ==============================================================

def require_auth(f):
    """Decorator — checks the Bearer JWT token before allowing access."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"success": False, "message": "No token provided."}), 401

        token = header.split(" ")[1]

        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "Token expired. Please log in again."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"success": False, "message": "Invalid token."}), 401

        # Make sure session is not revoked
        session = Session.query.filter_by(token=token, is_revoked=False).first()
        if not session or session.expires_at < datetime.utcnow():
            return jsonify({"success": False, "message": "Session expired. Please log in again."}), 401

        request.student_id = decoded["id"]
        request.token      = token
        return f(*args, **kwargs)
    return decorated


# ==============================================================
#  ROUTES — HEALTH CHECK
# ==============================================================

@app.route("/api/health")
def health():
    return jsonify({"success": True, "message": "CPCC Portal API is running!"}), 200


# ==============================================================
#  ROUTES — REGISTER
#  POST /api/auth/register
# ==============================================================

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Invalid request body."}), 400

    name     = data.get("name",     "").strip()
    email    = data.get("email",    "").strip().lower()
    password = data.get("password", "")
    confirm  = data.get("confirm",  "")

    # ── Step 1: Run all validation rules ──────────────────────
    errors = validate_registration(name, email, password, confirm)
    if errors:
        return jsonify({
            "success":    False,
            "message":    errors[0],      # show first error
            "all_errors": errors          # all errors (optional for frontend)
        }), 400

    # ── Step 2: Check for duplicate account ───────────────────
    if Student.query.filter_by(email=email).first():
        return jsonify({
            "success": False,
            "message": f"An account for {email} already exists. Please sign in instead.",
            "hint":    "login"
        }), 409

    # ── Step 3: Hash the password (never store plain text) ────
    password_hash = bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    # ── Step 4: Create student record ─────────────────────────
    new_student = Student(
        full_name=name,
        email=email,
        password_hash=password_hash
    )
    db.session.add(new_student)
    db.session.flush()                                  # get ID before commit
    new_student.student_id = generate_student_id(new_student.id)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": f"Account created successfully! Welcome, {name}.",
        "student": new_student.to_dict()
    }), 201


# ==============================================================
#  ROUTES — LOGIN
#  POST /api/auth/login
# ==============================================================

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Invalid request body."}), 400

    email    = data.get("email",    "").strip().lower()
    password = data.get("password", "")
    ip       = request.remote_addr

    # ── Step 1: Validate fields and email domain ───────────────
    errors = validate_login(email, password)
    if errors:
        return jsonify({"success": False, "message": errors[0]}), 400

    # ── Step 2: Brute-force protection ─────────────────────────
    if is_rate_limited(email, ip):
        return jsonify({
            "success": False,
            "message": f"Too many failed attempts. Please wait {LOCKOUT_MINUTES} minutes and try again."
        }), 429

    # ── Step 3: Look up student in database ───────────────────
    student = Student.query.filter_by(email=email, is_active=True).first()
    if not student:
        log_attempt(email, ip, success=False)
        return jsonify({
            "success": False,
            "message": f"No account found for {email}. Please create an account first.",
            "hint":    "register"
        }), 401

    # ── Step 4: Check password ────────────────────────────────
    password_ok = bcrypt.checkpw(
        password.encode("utf-8"),
        student.password_hash.encode("utf-8")
    )
    if not password_ok:
        log_attempt(email, ip, success=False)
        return jsonify({"success": False, "message": "Incorrect password. Please try again."}), 401

    # ── Step 5: Create JWT token and save session ──────────────
    token      = make_token(student.id, student.email, student.full_name)
    expires_at = datetime.utcnow() + timedelta(days=JWT_EXPIRES_DAYS)

    new_session = Session(
        student_id = student.id,
        token      = token,
        ip_address = ip,
        expires_at = expires_at,
    )
    db.session.add(new_session)
    log_attempt(email, ip, success=True)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Login successful!",
        "token":   token,
        "student": student.to_dict()
    }), 200


# ==============================================================
#  ROUTES — LOGOUT
#  POST /api/auth/logout
# ==============================================================

@app.route("/api/auth/logout", methods=["POST"])
@require_auth
def logout():
    session = Session.query.filter_by(token=request.token, is_revoked=False).first()
    if session:
        session.is_revoked = True
        db.session.commit()
    return jsonify({"success": True, "message": "Logged out successfully."}), 200


# ==============================================================
#  ROUTES — STUDENT PROFILE
#  GET /api/student/me
# ==============================================================

@app.route("/api/student/me", methods=["GET"])
@require_auth
def get_profile():
    student = Student.query.get(request.student_id)
    if not student:
        return jsonify({"success": False, "message": "Student not found."}), 404

    profile = student.to_dict()
    profile["total_courses"] = len(student.enrollments)
    profile["total_credits"] = sum(
        e.course.credits for e in student.enrollments if e.course
    )
    return jsonify({"success": True, "student": profile}), 200


# ==============================================================
#  ROUTES — ENROLLED COURSES
#  GET /api/student/courses
# ==============================================================

@app.route("/api/student/courses", methods=["GET"])
@require_auth
def get_courses():
    enrollments = (
        Enrollment.query
        .filter_by(student_id=request.student_id)
        .order_by(Enrollment.enrolled_at.desc())
        .all()
    )
    return jsonify({
        "success": True,
        "courses": [e.to_dict() for e in enrollments]
    }), 200


# ==============================================================
#  ROUTES — ENROLL IN A COURSE
#  POST /api/student/enroll
# ==============================================================

@app.route("/api/student/enroll", methods=["POST"])
@require_auth
def enroll():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Invalid request body."}), 400

    course_code = data.get("course_code", "").strip().upper()
    if not course_code:
        return jsonify({"success": False, "message": "course_code is required."}), 400

    course = Course.query.filter_by(course_code=course_code).first()
    if not course:
        return jsonify({"success": False, "message": f"Course '{course_code}' not found."}), 404

    already = Enrollment.query.filter_by(
        student_id=request.student_id, course_id=course.id
    ).first()
    if already:
        return jsonify({"success": False, "message": "You are already enrolled in this course."}), 409

    db.session.add(Enrollment(student_id=request.student_id, course_id=course.id))
    db.session.commit()

    return jsonify({
        "success": True,
        "message": f"Enrolled in {course.course_name} successfully!"
    }), 201


# ==============================================================
#  START SERVER
# ==============================================================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()     # creates tables if they don't exist yet
        print("✅ Database tables ready.")
    print("🚀 CPCC Portal API running at http://localhost:5000")
    app.run(debug=True, port=5000)
