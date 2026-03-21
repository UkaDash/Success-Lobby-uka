-- ==============================================================
--  CPCC Student Portal — MySQL Database
--  File: database.sql
--
--  HOW TO USE:
--    mysql -u root -p < database.sql
--
--  This will create the database, all tables, seed data,
--  and useful views automatically.
-- ==============================================================


-- ==============================================================
--  1. CREATE DATABASE
-- ==============================================================

CREATE DATABASE IF NOT EXISTS cpcc_portal
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE cpcc_portal;


-- ==============================================================
--  2. STUDENTS TABLE
--     Stores all registered student accounts.
--     Only @cpcc.edu and @email.cpcc.edu emails are accepted
--     (enforced in app.py validation AND here as a CHECK).
-- ==============================================================

CREATE TABLE IF NOT EXISTS students (
  id            INT           AUTO_INCREMENT PRIMARY KEY,
  full_name     VARCHAR(150)  NOT NULL,
  email         VARCHAR(255)  NOT NULL UNIQUE,
  password_hash VARCHAR(255)  NOT NULL,
  student_id    VARCHAR(20)   UNIQUE,
  is_active     BOOLEAN       NOT NULL DEFAULT TRUE,
  created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP
                              ON UPDATE CURRENT_TIMESTAMP,

  CONSTRAINT chk_cpcc_email
    CHECK (email LIKE '%@cpcc.edu' OR email LIKE '%@email.cpcc.edu')
);


-- ==============================================================
--  3. SESSIONS TABLE
--     Stores JWT tokens so we can revoke them on logout.
-- ==============================================================

CREATE TABLE IF NOT EXISTS sessions (
  id         INT          AUTO_INCREMENT PRIMARY KEY,
  student_id INT          NOT NULL,
  token      VARCHAR(512) NOT NULL UNIQUE,
  ip_address VARCHAR(45),
  expires_at DATETIME     NOT NULL,
  is_revoked BOOLEAN      NOT NULL DEFAULT FALSE,
  created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
  INDEX idx_token      (token),
  INDEX idx_student_id (student_id),
  INDEX idx_expires_at (expires_at)
);


-- ==============================================================
--  4. LOGIN_ATTEMPTS TABLE
--     Tracks failed logins for brute-force protection.
--     app.py blocks login after 5 failures within 15 minutes.
-- ==============================================================

CREATE TABLE IF NOT EXISTS login_attempts (
  id           INT          AUTO_INCREMENT PRIMARY KEY,
  email        VARCHAR(255) NOT NULL,
  ip_address   VARCHAR(45),
  success      BOOLEAN      NOT NULL DEFAULT FALSE,
  attempted_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

  INDEX idx_email      (email),
  INDEX idx_ip         (ip_address),
  INDEX idx_attempted  (attempted_at)
);


-- ==============================================================
--  5. COURSES TABLE
--     Stores all available CPCC courses.
-- ==============================================================

CREATE TABLE IF NOT EXISTS courses (
  id          INT          AUTO_INCREMENT PRIMARY KEY,
  course_code VARCHAR(20)  NOT NULL UNIQUE,
  course_name VARCHAR(200) NOT NULL,
  credits     TINYINT      NOT NULL DEFAULT 3,
  instructor  VARCHAR(150),
  semester    VARCHAR(20),
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ==============================================================
--  6. ENROLLMENTS TABLE
--     Links students to courses (many-to-many).
--     A student cannot enroll in the same course twice.
-- ==============================================================

CREATE TABLE IF NOT EXISTS enrollments (
  id          INT        AUTO_INCREMENT PRIMARY KEY,
  student_id  INT        NOT NULL,
  course_id   INT        NOT NULL,
  grade       VARCHAR(5),
  enrolled_at DATETIME   NOT NULL DEFAULT CURRENT_TIMESTAMP,

  UNIQUE KEY uq_enrollment (student_id, course_id),
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
  FOREIGN KEY (course_id)  REFERENCES courses(id)  ON DELETE CASCADE
);


-- ==============================================================
--  7. SEED DATA — Sample courses pre-loaded for testing
-- ==============================================================

INSERT IGNORE INTO courses (course_code, course_name, credits, instructor, semester) VALUES
  ('CSC-151', 'Java Programming',            3, 'Dr. Smith',   'Spring 2026'),
  ('CSC-289', 'Programming Project I',       3, 'Dr. Brown',   'Spring 2026'),
  ('MAT-271', 'Calculus I',                  4, 'Prof. Jones', 'Spring 2026'),
  ('ENG-111', 'Writing & Inquiry',           3, 'Ms. Taylor',  'Spring 2026'),
  ('CIS-110', 'Introduction to Computers',   3, 'Mr. Patel',   'Spring 2026'),
  ('BIO-111', 'General Biology I',           4, 'Dr. Rivera',  'Spring 2026'),
  ('PSY-150', 'General Psychology',          3, 'Dr. Lee',     'Spring 2026'),
  ('BUS-110', 'Introduction to Business',    3, 'Ms. Carter',  'Spring 2026');


-- ==============================================================
--  8. TRIGGER — Auto-generates student ID after insert
--     Example: first student gets S-00001, second gets S-00002
-- ==============================================================

DROP TRIGGER IF EXISTS trg_generate_student_id;

DELIMITER $$
CREATE TRIGGER trg_generate_student_id
AFTER INSERT ON students
FOR EACH ROW
BEGIN
  UPDATE students
  SET student_id = CONCAT('S-', LPAD(NEW.id, 5, '0'))
  WHERE id = NEW.id;
END$$
DELIMITER ;


-- ==============================================================
--  9. VIEWS — Helpful pre-built queries
-- ==============================================================

-- View: dashboard summary per student
CREATE OR REPLACE VIEW vw_student_summary AS
SELECT
  s.id,
  s.full_name,
  s.email,
  s.student_id,
  s.is_active,
  s.created_at,
  COUNT(e.id)      AS total_courses,
  SUM(c.credits)   AS total_credits
FROM students s
LEFT JOIN enrollments e ON e.student_id = s.id
LEFT JOIN courses     c ON c.id         = e.course_id
GROUP BY s.id;


-- View: full enrollment details (student + course info together)
CREATE OR REPLACE VIEW vw_enrollment_details AS
SELECT
  s.full_name   AS student_name,
  s.email       AS student_email,
  s.student_id,
  c.course_code,
  c.course_name,
  c.credits,
  c.instructor,
  c.semester,
  e.grade,
  e.enrolled_at
FROM enrollments e
JOIN students s ON s.id = e.student_id
JOIN courses  c ON c.id = e.course_id;


-- ==============================================================
--  DONE!
--  Tables created : students, sessions, login_attempts,
--                   courses, enrollments
--  Views created  : vw_student_summary, vw_enrollment_details
--  Seed data      : 8 sample courses loaded
-- ==============================================================
