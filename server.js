// ============================================================
//  CPCC Student Portal — Node.js + Express Backend
//  File: server.js
// ============================================================

const express    = require('express');
const mysql      = require('mysql2/promise');
const bcrypt     = require('bcrypt');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const helmet     = require('helmet');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 5000;

// ─── Middleware ───────────────────────────────────────────────
app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_URL || 'http://localhost:3000' }));
app.use(express.json());

// ─── MySQL Connection Pool ────────────────────────────────────
const pool = mysql.createPool({
  host:               process.env.DB_HOST     || 'localhost',
  port:               process.env.DB_PORT     || 3306,
  user:               process.env.DB_USER     || 'root',
  password:           process.env.DB_PASSWORD || '',
  database:           process.env.DB_NAME     || 'cpcc_portal',
  waitForConnections: true,
  connectionLimit:    10,
  queueLimit:         0,
  timezone:           '+00:00',
});

// Test DB connection on startup
pool.getConnection()
  .then(conn => { console.log('✅ MySQL connected'); conn.release(); })
  .catch(err  => { console.error('❌ MySQL connection failed:', err.message); process.exit(1); });

// ─── Helpers ─────────────────────────────────────────────────
const JWT_SECRET  = process.env.JWT_SECRET  || 'change_this_secret_in_production';
const JWT_EXPIRES = process.env.JWT_EXPIRES || '7d';
const SALT_ROUNDS = 12;
const MAX_ATTEMPTS = 5;          // lock after 5 failed logins
const WINDOW_MINUTES = 15;       // within 15-minute window

function isCpccEmail(email) {
  return typeof email === 'string' && email.toLowerCase().endsWith('@cpcc.edu');
}

function makeToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

// ─── Auth Middleware ──────────────────────────────────────────
async function requireAuth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ success: false, message: 'No token provided.' });

  const token = header.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Check session is not revoked
    const [rows] = await pool.query(
      'SELECT id FROM sessions WHERE token = ? AND is_revoked = FALSE AND expires_at > NOW()',
      [token]
    );
    if (!rows.length)
      return res.status(401).json({ success: false, message: 'Session expired or revoked.' });

    req.user  = decoded;
    req.token = token;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid token.' });
  }
}

// ─── Brute-force check ────────────────────────────────────────
async function isRateLimited(email, ip) {
  const [rows] = await pool.query(
    `SELECT COUNT(*) AS attempts
     FROM login_attempts
     WHERE (email = ? OR ip_address = ?)
       AND success     = FALSE
       AND attempted_at > DATE_SUB(NOW(), INTERVAL ? MINUTE)`,
    [email, ip, WINDOW_MINUTES]
  );
  return rows[0].attempts >= MAX_ATTEMPTS;
}

async function logAttempt(email, ip, success) {
  await pool.query(
    'INSERT INTO login_attempts (email, ip_address, success) VALUES (?, ?, ?)',
    [email, ip, success]
  );
}

// ============================================================
//  ROUTES
// ============================================================

// ── GET /api/health ──────────────────────────────────────────
app.get('/api/health', (_, res) => {
  res.json({ success: true, message: 'CPCC Portal API is running.' });
});

// ── POST /api/auth/register ──────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { full_name, email, password } = req.body;

    // ── Validation ──
    if (!full_name || !email || !password)
      return res.status(400).json({ success: false, message: 'All fields are required.' });

    const cleanEmail = email.trim().toLowerCase();

    if (!isCpccEmail(cleanEmail))
      return res.status(400).json({
        success: false,
        message: 'Only @cpcc.edu email addresses are allowed to register.',
      });

    if (password.length < 6)
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters.' });

    // ── Check duplicate ──
    const [existing] = await pool.query(
      'SELECT id FROM students WHERE email = ?',
      [cleanEmail]
    );
    if (existing.length)
      return res.status(409).json({ success: false, message: 'An account with this email already exists.' });

    // ── Hash password & insert ──
    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);

    const [result] = await pool.query(
      'INSERT INTO students (full_name, email, password_hash) VALUES (?, ?, ?)',
      [full_name.trim(), cleanEmail, password_hash]
    );

    // Fetch newly created student (trigger will have set student_id)
    const [newStudent] = await pool.query(
      'SELECT id, full_name, email, student_id, created_at FROM students WHERE id = ?',
      [result.insertId]
    );

    return res.status(201).json({
      success: true,
      message: 'Account created successfully! You can now sign in.',
      student: newStudent[0],
    });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  }
});

// ── POST /api/auth/login ─────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const ip = req.ip;
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ success: false, message: 'Email and password are required.' });

    const cleanEmail = email.trim().toLowerCase();

    // ── Rate limiting ──
    if (await isRateLimited(cleanEmail, ip)) {
      return res.status(429).json({
        success: false,
        message: `Too many failed attempts. Please wait ${WINDOW_MINUTES} minutes and try again.`,
      });
    }

    // ── Find student ──
    const [rows] = await pool.query(
      'SELECT * FROM students WHERE email = ? AND is_active = TRUE',
      [cleanEmail]
    );

    if (!rows.length) {
      await logAttempt(cleanEmail, ip, false);
      return res.status(401).json({
        success: false,
        message: 'No account found with this email. Please create an account first.',
        hint: 'register',    // frontend uses this to show the Register tab
      });
    }

    const student = rows[0];

    // ── Check password ──
    const match = await bcrypt.compare(password, student.password_hash);
    if (!match) {
      await logAttempt(cleanEmail, ip, false);
      return res.status(401).json({ success: false, message: 'Incorrect password. Please try again.' });
    }

    // ── Create JWT + session ──
    const payload = { id: student.id, email: student.email, name: student.full_name };
    const token   = makeToken(payload);
    const expires = new Date();
    expires.setDate(expires.getDate() + 7);   // 7 days

    await pool.query(
      'INSERT INTO sessions (student_id, token, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)',
      [student.id, token, ip, req.headers['user-agent'] || '', expires]
    );

    await logAttempt(cleanEmail, ip, true);

    return res.json({
      success: true,
      message: 'Login successful.',
      token,
      student: {
        id:         student.id,
        full_name:  student.full_name,
        email:      student.email,
        student_id: student.student_id,
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  }
});

// ── POST /api/auth/logout ────────────────────────────────────
app.post('/api/auth/logout', requireAuth, async (req, res) => {
  try {
    await pool.query(
      'UPDATE sessions SET is_revoked = TRUE WHERE token = ?',
      [req.token]
    );
    return res.json({ success: true, message: 'Logged out successfully.' });
  } catch (err) {
    console.error('Logout error:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ── GET /api/student/me ──────────────────────────────────────
app.get('/api/student/me', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, full_name, email, student_id, created_at, total_courses, total_credits FROM vw_student_summary WHERE id = ?',
      [req.user.id]
    );
    if (!rows.length)
      return res.status(404).json({ success: false, message: 'Student not found.' });

    return res.json({ success: true, student: rows[0] });
  } catch (err) {
    console.error('Profile error:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ── GET /api/student/courses ─────────────────────────────────
app.get('/api/student/courses', requireAuth, async (req, res) => {
  try {
    const [courses] = await pool.query(
      `SELECT c.course_code, c.course_name, c.credits, c.instructor, c.semester, e.grade, e.enrolled_at
       FROM enrollments e
       JOIN courses c ON c.id = e.course_id
       WHERE e.student_id = ?
       ORDER BY e.enrolled_at DESC`,
      [req.user.id]
    );
    return res.json({ success: true, courses });
  } catch (err) {
    console.error('Courses error:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ── POST /api/student/enroll ─────────────────────────────────
app.post('/api/student/enroll', requireAuth, async (req, res) => {
  try {
    const { course_code } = req.body;
    if (!course_code)
      return res.status(400).json({ success: false, message: 'course_code is required.' });

    const [courseRows] = await pool.query(
      'SELECT id, course_name FROM courses WHERE course_code = ?',
      [course_code.toUpperCase()]
    );
    if (!courseRows.length)
      return res.status(404).json({ success: false, message: 'Course not found.' });

    const course = courseRows[0];
    await pool.query(
      'INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)',
      [req.user.id, course.id]
    );

    return res.status(201).json({
      success: true,
      message: `Enrolled in ${course.course_name} successfully.`,
    });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY')
      return res.status(409).json({ success: false, message: 'You are already enrolled in this course.' });
    console.error('Enroll error:', err);
    return res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ── 404 catch-all ────────────────────────────────────────────
app.use((_, res) => res.status(404).json({ success: false, message: 'Route not found.' }));

// ─── Start Server ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 CPCC Portal API running at http://localhost:${PORT}`);
});
