-- ============================================================
--  CPCC Student Portal — MySQL Database Setup
--  Run this file first to initialize the database
-- ============================================================

-- 1. Create and select the database
CREATE DATABASE IF NOT EXISTS cpcc_portal
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE cpcc_portal;

-- ============================================================
-- 2. STUDENTS table
-- ============================================================
CREATE TABLE IF NOT EXISTS students (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  full_name     VARCHAR(150)        NOT NULL,
  email         VARCHAR(255)        NOT NULL UNIQUE,
  password_hash VARCHAR(255)        NOT NULL,          -- bcrypt hash
  student_id    VARCHAR(20)         UNIQUE,            -- e.g. S-00001
  is_active     BOOLEAN             NOT NULL DEFAULT TRUE,
  created_at    DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP
                                    ON UPDATE CURRENT_TIMESTAMP,

  -- Only allow @cpcc.edu emails at the database level too
  CONSTRAINT chk_cpcc_email CHECK (email LIKE '%@cpcc.edu')
);

-- ============================================================
-- 3. SESSIONS table  (server-side session / JWT blocklist)
-- ============================================================
CREATE TABLE IF NOT EXISTS sessions (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  student_id   INT          NOT NULL,
  token        VARCHAR(512) NOT NULL UNIQUE,           -- JWT token
  ip_address   VARCHAR(45),                            -- IPv4 / IPv6
  user_agent   TEXT,
  created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at   DATETIME     NOT NULL,
  is_revoked   BOOLEAN      NOT NULL DEFAULT FALSE,

  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
  INDEX idx_token      (token),
  INDEX idx_student_id (student_id),
  INDEX idx_expires_at (expires_at)
);

-- ============================================================
-- 4. LOGIN_ATTEMPTS table  (brute-force protection)
-- ============================================================
CREATE TABLE IF NOT EXISTS login_attempts (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  email        VARCHAR(255) NOT NULL,
  ip_address   VARCHAR(45),
  attempted_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  success      BOOLEAN      NOT NULL DEFAULT FALSE,

  INDEX idx_email      (email),
  INDEX idx_ip         (ip_address),
  INDEX idx_attempted  (attempted_at)
);

-- ============================================================
-- 5. COURSES table
-- ============================================================
CREATE TABLE IF NOT EXISTS courses (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  course_code  VARCHAR(20)  NOT NULL UNIQUE,           -- e.g. CSC-151
  course_name  VARCHAR(200) NOT NULL,
  credits      TINYINT      NOT NULL DEFAULT 3,
  instructor   VARCHAR(150),
  semester     VARCHAR(20),                            -- e.g. Fall 2025
  created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- 6. ENROLLMENTS table  (students ↔ courses, many-to-many)
-- ============================================================
CREATE TABLE IF NOT EXISTS enrollments (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  student_id   INT          NOT NULL,
  course_id    INT          NOT NULL,
  grade        VARCHAR(5),                             -- A, B+, etc.
  enrolled_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

  UNIQUE KEY uq_enrollment (student_id, course_id),
  FOREIGN KEY (student_id) REFERENCES students(id)  ON DELETE CASCADE,
  FOREIGN KEY (course_id)  REFERENCES courses(id)   ON DELETE CASCADE
);

-- ============================================================
-- 7. Seed: sample courses
-- ============================================================
INSERT IGNORE INTO courses (course_code, course_name, credits, instructor, semester) VALUES
  ('CSC-151', 'Java Programming',           3, 'Dr. Smith',   'Spring 2026'),
  ('MAT-271', 'Calculus I',                 4, 'Prof. Jones',  'Spring 2026'),
  ('ENG-111', 'Writing & Inquiry',          3, 'Ms. Taylor',   'Spring 2026'),
  ('CIS-110', 'Introduction to Computers',  3, 'Mr. Patel',    'Spring 2026'),
  ('BIO-111', 'General Biology I',          4, 'Dr. Rivera',   'Spring 2026');

-- ============================================================
-- 8. Useful views
-- ============================================================

-- View: student dashboard summary
CREATE OR REPLACE VIEW vw_student_summary AS
SELECT
  s.id,
  s.full_name,
  s.email,
  s.student_id,
  s.is_active,
  s.created_at,
  COUNT(e.id)                    AS total_courses,
  SUM(c.credits)                 AS total_credits
FROM students s
LEFT JOIN enrollments e ON e.student_id = s.id
LEFT JOIN courses     c ON c.id         = e.course_id
GROUP BY s.id;

-- View: full enrollment details
CREATE OR REPLACE VIEW vw_enrollment_details AS
SELECT
  s.full_name     AS student_name,
  s.email         AS student_email,
  c.course_code,
  c.course_name,
  c.credits,
  c.instructor,
  e.grade,
  e.enrolled_at
FROM enrollments e
JOIN students s ON s.id = e.student_id
JOIN courses  c ON c.id = e.course_id;

-- ============================================================
-- 9. Stored Procedure: auto-generate student ID on insert
-- ============================================================
DELIMITER $$

CREATE PROCEDURE IF NOT EXISTS sp_generate_student_id(IN p_student_id INT)
BEGIN
  DECLARE new_sid VARCHAR(20);
  SET new_sid = CONCAT('S-', LPAD(p_student_id, 5, '0'));
  UPDATE students SET student_id = new_sid WHERE id = p_student_id;
END$$

DELIMITER ;

-- Trigger to call the procedure after insert
DROP TRIGGER IF EXISTS trg_after_student_insert;
DELIMITER $$
CREATE TRIGGER trg_after_student_insert
AFTER INSERT ON students
FOR EACH ROW
BEGIN
  CALL sp_generate_student_id(NEW.id);
END$$
DELIMITER ;

-- ============================================================
-- Done! Tables created:
--   students, sessions, login_attempts, courses, enrollments
-- Views:
--   vw_student_summary, vw_enrollment_details
-- ============================================================
