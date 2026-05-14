-- AttendX v2 schema: Secure QR Attendance System
PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS attendance_records;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS subjects;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS auth_tokens;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  student_id  TEXT UNIQUE,
  email       TEXT UNIQUE NOT NULL,
  password    TEXT NOT NULL,
  role        TEXT NOT NULL CHECK(role IN ('teacher','student')),
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE auth_tokens (
  token       TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL
);

CREATE TABLE subjects (
  id           TEXT PRIMARY KEY,
  teacher_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subject_name TEXT NOT NULL,
  section      TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(teacher_id, subject_name, section)
);

CREATE TABLE sessions (
  id             TEXT PRIMARY KEY,
  subject_id     TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
  teacher_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_date   TEXT NOT NULL,
  start_time     TEXT NOT NULL,
  end_time       TEXT NOT NULL,
  qr_token       TEXT NOT NULL,
  classroom_lat  REAL NOT NULL,
  classroom_lng  REAL NOT NULL,
  allowed_radius INTEGER NOT NULL,
  created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE attendance_records (
  id              TEXT PRIMARY KEY,
  session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  student_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  submit_time     TEXT NOT NULL,
  latitude        REAL,
  longitude       REAL,
  distance_meters REAL,
  status          TEXT NOT NULL,
  warning_message TEXT NOT NULL,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(session_id, student_id)
);

CREATE TABLE audit_logs (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  subject_id TEXT,
  session_id TEXT,
  action     TEXT NOT NULL,
  details    TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_tokens_user ON auth_tokens(user_id);
CREATE INDEX idx_subjects_teacher ON subjects(teacher_id);
CREATE INDEX idx_sessions_subject ON sessions(subject_id);
CREATE INDEX idx_sessions_teacher ON sessions(teacher_id);
CREATE INDEX idx_records_session ON attendance_records(session_id);
CREATE INDEX idx_records_student ON attendance_records(student_id);
CREATE INDEX idx_logs_user ON audit_logs(user_id);
CREATE INDEX idx_logs_subject ON audit_logs(subject_id);
CREATE INDEX idx_logs_session ON audit_logs(session_id);

PRAGMA user_version = 2;
