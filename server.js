/**
 * AttendX — Secure QR Attendance System
 * Backend: Node.js + Express + SQLite (better-sqlite3)
 *
 * Run:
 *   npm install
 *   npm start
 */

const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const db = new Database('attendx.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

const SCHEMA_VERSION = 2;
const currentVersion = db.pragma('user_version', { simple: true });
if (currentVersion < SCHEMA_VERSION) {
  db.exec(`
    DROP TABLE IF EXISTS attendance_records;
    DROP TABLE IF EXISTS sessions;
    DROP TABLE IF EXISTS subjects;
    DROP TABLE IF EXISTS audit_logs;
    DROP TABLE IF EXISTS auth_tokens;
    DROP TABLE IF EXISTS users;
  `);
}

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    student_id  TEXT UNIQUE,
    email       TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    role        TEXT NOT NULL CHECK(role IN ('teacher','student')),
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS auth_tokens (
    token       TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS subjects (
    id           TEXT PRIMARY KEY,
    teacher_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject_name TEXT NOT NULL,
    section      TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(teacher_id, subject_name, section)
  );

  CREATE TABLE IF NOT EXISTS sessions (
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

  CREATE TABLE IF NOT EXISTS attendance_records (
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

  CREATE TABLE IF NOT EXISTS audit_logs (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    subject_id TEXT,
    session_id TEXT,
    action     TEXT NOT NULL,
    details    TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_tokens_user ON auth_tokens(user_id);
  CREATE INDEX IF NOT EXISTS idx_subjects_teacher ON subjects(teacher_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_subject ON sessions(subject_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_teacher ON sessions(teacher_id);
  CREATE INDEX IF NOT EXISTS idx_records_session ON attendance_records(session_id);
  CREATE INDEX IF NOT EXISTS idx_records_student ON attendance_records(student_id);
  CREATE INDEX IF NOT EXISTS idx_logs_user ON audit_logs(user_id);
  CREATE INDEX IF NOT EXISTS idx_logs_subject ON audit_logs(subject_id);
  CREATE INDEX IF NOT EXISTS idx_logs_session ON audit_logs(session_id);
`);

db.pragma(`user_version = ${SCHEMA_VERSION}`);

const SECRET_KEY = process.env.HMAC_SECRET || 'SUPER_SECRET_KEY_PROTOTYPE_CHANGE_ME';
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

function id(prefix) {
  return `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

function seedUsers() {
  const count = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  if (count > 0) return;

  const insertUser = db.prepare(`
    INSERT INTO users (id, name, student_id, email, password, role)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const users = [
    ['u_teacher', 'Professor Minerva McGonagall', null, 'teacher@example.com', 'teacher123', 'teacher'],
    ['u_harry', 'Harry Potter', '6622701845', '6622701845@g.siit.tu.ac.th', 'student123', 'student'],
    ['u_hermione', 'Hermione Granger', '6622703928', '6622703928@g.siit.tu.ac.th', 'student123', 'student'],
    ['u_ron', 'Ron Weasley', '6622707461', '6622707461@g.siit.tu.ac.th', 'student123', 'student'],
    ['u_draco', 'Draco Malfoy', '6622705139', '6622705139@g.siit.tu.ac.th', 'student123', 'student'],
    ['u_luna', 'Luna Lovegood', '6622708256', '6622708256@g.siit.tu.ac.th', 'student123', 'student']
  ];

  const seed = db.transaction(() => {
    users.forEach(([userId, name, studentId, email, password, role]) => {
      insertUser.run(userId, name, studentId, email, bcrypt.hashSync(password, 10), role);
    });
  });
  seed();
  console.log('✅ Seeded teacher and 5 Harry Potter student accounts.');
}
seedUsers();

function logAudit(userId, subjectId, sessionId, action, details) {
  db.prepare(`
    INSERT INTO audit_logs (id, user_id, subject_id, session_id, action, details)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id('log'), userId || 'system', subjectId || null, sessionId || null, action, details || '');
}

function generateQRToken(sessionId, subjectId) {
  const payload = {
    sessionId,
    subjectId,
    created: Date.now(),
    nonce: crypto.randomBytes(10).toString('hex')
  };
  const payloadStr = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', SECRET_KEY).update(payloadStr).digest('hex');
  return `${payloadStr}.${signature}`;
}

function verifyQRToken(token) {
  try {
    const [payloadStr, signature] = String(token || '').split('.');
    if (!payloadStr || !signature) return null;
    const expected = crypto.createHmac('sha256', SECRET_KEY).update(payloadStr).digest('hex');
    const sigBuf = Buffer.from(signature, 'hex');
    const expBuf = Buffer.from(expected, 'hex');
    if (sigBuf.length !== expBuf.length) return null;
    if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;
    return JSON.parse(Buffer.from(payloadStr, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

function getDistance(lat1, lon1, lat2, lon2) {
  const R = 6371e3;
  const rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad;
  const dLon = (lon2 - lon1) * rad;
  const a = Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    studentId: user.student_id,
    email: user.email,
    role: user.role
  };
}

const authenticate = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const row = db.prepare(`
    SELECT u.*, t.created_at AS token_created_at
    FROM auth_tokens t
    JOIN users u ON u.id = t.user_id
    WHERE t.token = ?
  `).get(token);

  if (!row) return res.status(401).json({ error: 'Unauthorized' });
  if (Date.now() - row.token_created_at > TOKEN_TTL_MS) {
    db.prepare('DELETE FROM auth_tokens WHERE token = ?').run(token);
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }

  req.user = row;
  next();
};

const requireRole = (role) => (req, res, next) => {
  if (req.user.role !== role) {
    logAudit(req.user.id, null, null, 'Unauthorized Access', `Tried to access ${role} route`);
    return res.status(403).json({ error: 'Access denied.' });
  }
  next();
};

function requireTeacherSubject(req, res, next) {
  const subjectId = req.params.subjectId || req.body.subjectId;
  const subject = db.prepare('SELECT * FROM subjects WHERE id = ? AND teacher_id = ?').get(subjectId, req.user.id);
  if (!subject) return res.status(404).json({ error: 'Subject not found or access denied.' });
  req.subject = subject;
  next();
}

function requireTeacherSession(req, res, next) {
  const sessionId = req.params.sessionId || req.body.sessionId;
  const session = db.prepare(`
    SELECT se.*, su.subject_name, su.section
    FROM sessions se
    JOIN subjects su ON su.id = se.subject_id
    WHERE se.id = ? AND se.teacher_id = ?
  `).get(sessionId, req.user.id);
  if (!session) return res.status(404).json({ error: 'Session not found or access denied.' });
  req.sessionRow = session;
  next();
}

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password || '', user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO auth_tokens (token, user_id, created_at) VALUES (?, ?, ?)').run(token, user.id, Date.now());
  logAudit(user.id, null, null, 'Login', `${user.name} logged in as ${user.role}`);
  res.json({ token, role: user.role, name: user.name, user: publicUser(user) });
});

app.post('/api/logout', authenticate, (req, res) => {
  db.prepare('DELETE FROM auth_tokens WHERE token = ?').run(req.headers.authorization);
  logAudit(req.user.id, null, null, 'Logout', `${req.user.name} logged out`);
  res.json({ message: 'Logged out successfully.' });
});

app.get('/api/me', authenticate, (req, res) => res.json(publicUser(req.user)));
app.get('/api/teacher/profile', authenticate, requireRole('teacher'), (req, res) => res.json(publicUser(req.user)));
app.get('/api/student/profile', authenticate, requireRole('student'), (req, res) => res.json(publicUser(req.user)));

// Self-registration is intentionally disabled for this prototype.
app.post('/api/register', (req, res) => {
  res.status(403).json({ error: 'Student self-registration is disabled. Accounts are created by the institution.' });
});

app.get('/api/teacher/subjects', authenticate, requireRole('teacher'), (req, res) => {
  const subjects = db.prepare(`
    SELECT s.*,
      (SELECT COUNT(*) FROM sessions WHERE subject_id = s.id) AS session_count
    FROM subjects s
    WHERE s.teacher_id = ?
    ORDER BY s.created_at DESC
  `).all(req.user.id);
  res.json({ subjects });
});

app.post('/api/teacher/subjects', authenticate, requireRole('teacher'), (req, res) => {
  const subjectName = String(req.body.subjectName || '').trim();
  const section = String(req.body.section || '').trim();
  if (!subjectName || !section) return res.status(400).json({ error: 'Subject name and section are required.' });

  const subjectId = id('subj');
  try {
    db.prepare(`
      INSERT INTO subjects (id, teacher_id, subject_name, section)
      VALUES (?, ?, ?, ?)
    `).run(subjectId, req.user.id, subjectName, section);
    logAudit(req.user.id, subjectId, null, 'Create Subject', `Created ${subjectName} Section ${section}`);
    res.status(201).json({ id: subjectId, teacher_id: req.user.id, subject_name: subjectName, section });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'This subject and section already exists.' });
    res.status(500).json({ error: 'Could not create subject.' });
  }
});

app.get('/api/teacher/subjects/:subjectId/sessions', authenticate, requireRole('teacher'), requireTeacherSubject, (req, res) => {
  const sessions = db.prepare(`
    SELECT * FROM sessions WHERE subject_id = ? AND teacher_id = ? ORDER BY session_date DESC, start_time DESC
  `).all(req.subject.id, req.user.id);
  res.json({ subject: req.subject, sessions });
});

app.post('/api/teacher/subjects/:subjectId/sessions', authenticate, requireRole('teacher'), requireTeacherSubject, (req, res) => {
  const { sessionDate, startTime, endTime, classroomLat, classroomLng, allowedRadius } = req.body;
  if (!sessionDate || !startTime || !endTime || classroomLat == null || classroomLng == null || !allowedRadius) {
    return res.status(400).json({ error: 'Date, start time, end time, location, and allowed radius are required.' });
  }
  const start = new Date(`${sessionDate}T${startTime}`);
  const end = new Date(`${sessionDate}T${endTime}`);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || end <= start) {
    return res.status(400).json({ error: 'Invalid date/time. End time must be after start time.' });
  }
  const radius = parseInt(allowedRadius, 10);
  if (!Number.isFinite(radius) || radius <= 0) return res.status(400).json({ error: 'Allowed radius must be a positive number.' });

  const sessionId = id('sess');
  const qrToken = generateQRToken(sessionId, req.subject.id);
  db.prepare(`
    INSERT INTO sessions
      (id, subject_id, teacher_id, session_date, start_time, end_time, qr_token, classroom_lat, classroom_lng, allowed_radius)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    sessionId, req.subject.id, req.user.id, sessionDate, startTime, endTime, qrToken,
    parseFloat(classroomLat), parseFloat(classroomLng), radius
  );
  logAudit(req.user.id, req.subject.id, sessionId, 'Create QR Session', `Created QR session for ${req.subject.subject_name} Section ${req.subject.section} on ${sessionDate}`);
  res.status(201).json({ id: sessionId, subjectId: req.subject.id, qrToken, sessionDate, startTime, endTime });
});

app.get('/api/teacher/sessions/:sessionId/attendance', authenticate, requireRole('teacher'), requireTeacherSession, (req, res) => {
  const rows = db.prepare(`
    SELECT
      u.id AS user_id,
      u.student_id,
      u.name,
      u.email,
      ar.submit_time,
      ar.distance_meters,
      ar.status,
      ar.warning_message
    FROM users u
    LEFT JOIN attendance_records ar
      ON ar.student_id = u.id AND ar.session_id = ?
    WHERE u.role = 'student'
    ORDER BY u.student_id ASC
  `).all(req.sessionRow.id).map(r => ({
    userId: r.user_id,
    studentId: r.student_id,
    name: r.name,
    email: r.email,
    status: r.submit_time ? 'Checked' : 'Not Checked',
    submitTime: r.submit_time,
    distanceMeters: r.distance_meters,
    warning: r.warning_message || 'No'
  }));
  res.json({ session: req.sessionRow, attendance: rows });
});

app.get('/api/teacher/audit-logs', authenticate, requireRole('teacher'), (req, res) => {
  const logs = db.prepare(`
    SELECT l.*, u.name AS user_name, u.role, su.subject_name, su.section
    FROM audit_logs l
    LEFT JOIN users u ON u.id = l.user_id
    LEFT JOIN subjects su ON su.id = l.subject_id
    WHERE
      l.user_id = ?
      OR l.subject_id IN (SELECT id FROM subjects WHERE teacher_id = ?)
      OR l.session_id IN (SELECT id FROM sessions WHERE teacher_id = ?)
    ORDER BY l.created_at DESC
    LIMIT 200
  `).all(req.user.id, req.user.id, req.user.id);
  res.json({ logs });
});

app.post('/api/student/submit-attendance', authenticate, requireRole('student'), (req, res) => {
  const { qrToken, latitude, longitude } = req.body;
  const payload = verifyQRToken(qrToken);
  if (!payload) {
    logAudit(req.user.id, null, null, 'Submit Attendance Rejected', 'Invalid or fake QR token');
    return res.status(400).json({ status: 'Rejected', message: 'Invalid QR token.' });
  }

  const session = db.prepare(`
    SELECT se.*, su.subject_name, su.section
    FROM sessions se
    JOIN subjects su ON su.id = se.subject_id
    WHERE se.id = ? AND se.subject_id = ?
  `).get(payload.sessionId, payload.subjectId);
  if (!session) return res.status(400).json({ status: 'Rejected', message: 'Session not found.' });

  const now = new Date();
  const start = new Date(`${session.session_date}T${session.start_time}`);
  const end = new Date(`${session.session_date}T${session.end_time}`);
  if (now < start || now > end) {
    logAudit(req.user.id, session.subject_id, session.id, 'Submit Attendance Rejected', 'Attendance session is closed or expired');
    return res.status(400).json({ status: 'Rejected', message: 'Attendance session is not open now.' });
  }

  const duplicate = db.prepare('SELECT id FROM attendance_records WHERE session_id = ? AND student_id = ?').get(session.id, req.user.id);
  if (duplicate) {
    logAudit(req.user.id, session.subject_id, session.id, 'Duplicate Attendance Attempt', `${req.user.name} tried to submit again`);
    return res.status(400).json({ status: 'Rejected', message: 'You already checked attendance for this session.' });
  }

  const lat = parseFloat(latitude);
  const lng = parseFloat(longitude);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
    return res.status(400).json({ status: 'Rejected', message: 'Location permission is required for attendance verification.' });
  }

  const distance = getDistance(session.classroom_lat, session.classroom_lng, lat, lng);
  let status = 'Checked';
  let warning = 'No';
  if (distance > session.allowed_radius) {
    status = 'Checked with Warning';
    warning = `Far location (${Math.round(distance)}m away)`;
    logAudit(req.user.id, session.subject_id, session.id, 'Far Location Warning', `${req.user.name} checked in ${Math.round(distance)}m away`);
  } else {
    logAudit(req.user.id, session.subject_id, session.id, 'Submit Attendance', `${req.user.name} checked in successfully`);
  }

  const recordId = id('rec');
  db.prepare(`
    INSERT INTO attendance_records (id, session_id, student_id, submit_time, latitude, longitude, distance_meters, status, warning_message)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(recordId, session.id, req.user.id, new Date().toISOString(), lat, lng, Math.round(distance), status, warning);

  res.json({
    id: recordId,
    subjectName: session.subject_name,
    section: session.section,
    status,
    warningMessage: warning,
    distanceMeters: Math.round(distance)
  });
});

app.get('/api/student/my-attendance', authenticate, requireRole('student'), (req, res) => {
  const records = db.prepare(`
    SELECT ar.*, se.session_date, se.start_time, se.end_time, su.subject_name, su.section
    FROM attendance_records ar
    JOIN sessions se ON se.id = ar.session_id
    JOIN subjects su ON su.id = se.subject_id
    WHERE ar.student_id = ?
    ORDER BY ar.submit_time DESC
  `).all(req.user.id);
  res.json({ records });
});

// Backward compatible aliases for old pages/tools.
app.get('/api/student/dashboard', authenticate, requireRole('student'), (req, res) => {
  const records = db.prepare(`
    SELECT ar.*, su.subject_name, su.section
    FROM attendance_records ar
    JOIN sessions se ON se.id = ar.session_id
    JOIN subjects su ON su.id = se.subject_id
    WHERE ar.student_id = ?
    ORDER BY ar.submit_time DESC
  `).all(req.user.id);
  res.json({ records });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🎓 AttendX server running → http://localhost:${PORT}`);
  console.log('🔐 Demo teacher: teacher@example.com / teacher123');
  console.log('🧑‍🎓 Demo student: 6622701845@g.siit.tu.ac.th / student123\n');
});
