/**
 * AttendX — Secure QR Attendance System
 * Backend: Node.js + Express + PostgreSQL (pg / Supabase)
 *
 * Environment variables required:
 *   SUPABASE_DB_URL   — PostgreSQL connection string
 *   HMAC_SECRET       — Secret for QR token signing (optional, has default)
 *   PORT              — Port to listen on (optional, defaults to 3000)
 *
 * Run:
 *   npm install
 *   npm start
 */

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Database ──────────────────────────────────────────────────────────────────
const db = new Pool({
  connectionString: process.env.SUPABASE_DB_URL,
  ssl: { rejectUnauthorized: false }
});

// ── Schema ────────────────────────────────────────────────────────────────────
async function initSchema() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL,
      student_id  TEXT UNIQUE,
      email       TEXT UNIQUE NOT NULL,
      password    TEXT NOT NULL,
      role        TEXT NOT NULL CHECK(role IN ('teacher','student')),
      created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS auth_tokens (
      token       TEXT PRIMARY KEY,
      user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at  BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS subjects (
      id           TEXT PRIMARY KEY,
      teacher_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      subject_name TEXT NOT NULL,
      section      TEXT NOT NULL,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
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
      classroom_lat  DOUBLE PRECISION NOT NULL,
      classroom_lng  DOUBLE PRECISION NOT NULL,
      allowed_radius INTEGER NOT NULL,
      created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS attendance_records (
      id              TEXT PRIMARY KEY,
      session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
      student_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      submit_time     TIMESTAMPTZ NOT NULL,
      latitude        DOUBLE PRECISION,
      longitude       DOUBLE PRECISION,
      distance_meters DOUBLE PRECISION,
      status          TEXT NOT NULL,
      warning_message TEXT NOT NULL,
      created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(session_id, student_id)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id         TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL,
      subject_id TEXT,
      session_id TEXT,
      action     TEXT NOT NULL,
      details    TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_tokens_user    ON auth_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_subjects_teacher ON subjects(teacher_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_subject ON sessions(subject_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_teacher ON sessions(teacher_id);
    CREATE INDEX IF NOT EXISTS idx_records_session  ON attendance_records(session_id);
    CREATE INDEX IF NOT EXISTS idx_records_student  ON attendance_records(student_id);
    CREATE INDEX IF NOT EXISTS idx_logs_user        ON audit_logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_logs_subject     ON audit_logs(subject_id);
    CREATE INDEX IF NOT EXISTS idx_logs_session     ON audit_logs(session_id);
  `);
  console.log('✅ Database schema ready.');
}

// ── Seed ──────────────────────────────────────────────────────────────────────
async function seedUsers() {
  const { rows } = await db.query('SELECT COUNT(*) AS n FROM users');
  if (parseInt(rows[0].n, 10) > 0) return;

  const users = [
    ['u_teacher',  'Professor Minerva McGonagall', null,         'teacher@example.com',              'teacher123', 'teacher'],
    ['u_harry',    'Harry Potter',                 '6622701845', '6622701845@g.siit.tu.ac.th',       'student123', 'student'],
    ['u_hermione', 'Hermione Granger',             '6622703928', '6622703928@g.siit.tu.ac.th',       'student123', 'student'],
    ['u_ron',      'Ron Weasley',                  '6622707461', '6622707461@g.siit.tu.ac.th',       'student123', 'student'],
    ['u_draco',    'Draco Malfoy',                 '6622705139', '6622705139@g.siit.tu.ac.th',       'student123', 'student'],
    ['u_luna',     'Luna Lovegood',                '6622708256', '6622708256@g.siit.tu.ac.th',       'student123', 'student'],
  ];

  for (const [userId, name, studentId, email, password, role] of users) {
    await db.query(
      `INSERT INTO users (id, name, student_id, email, password, role)
       VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
      [userId, name, studentId, email, bcrypt.hashSync(password, 10), role]
    );
  }
  console.log('✅ Seeded teacher and 5 Harry Potter student accounts.');
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const SECRET_KEY  = process.env.HMAC_SECRET || 'SUPER_SECRET_KEY_PROTOTYPE_CHANGE_ME';
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

function uid(prefix) {
  return `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

async function logAudit(userId, subjectId, sessionId, action, details) {
  try {
    await db.query(
      `INSERT INTO audit_logs (id, user_id, subject_id, session_id, action, details)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [uid('log'), userId || 'system', subjectId || null, sessionId || null, action, details || '']
    );
  } catch (e) {
    console.error('Audit log error:', e.message);
  }
}

function generateQRToken(sessionId, subjectId) {
  const payload = {
    sid: sessionId,
    sub: subjectId,
    iat: Date.now(),
    n: crypto.randomBytes(5).toString('hex')
  };
  const payloadStr = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature  = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(payloadStr)
    .digest('base64url')
    .slice(0, 32);
  return `${payloadStr}.${signature}`;
}

function verifyQRToken(token) {
  try {
    const [payloadStr, signature] = String(token || '').split('.');
    if (!payloadStr || !signature) return null;

    const expectedShort = crypto
      .createHmac('sha256', SECRET_KEY)
      .update(payloadStr)
      .digest('base64url')
      .slice(0, 32);

    const expectedOldHex = crypto
      .createHmac('sha256', SECRET_KEY)
      .update(payloadStr)
      .digest('hex');

    if (signature !== expectedShort && signature !== expectedOldHex) return null;

    const payload = JSON.parse(Buffer.from(payloadStr, 'base64url').toString('utf8'));
    return {
      sessionId: payload.sessionId || payload.sid,
      subjectId: payload.subjectId || payload.sub,
      created:   payload.created   || payload.iat,
      nonce:     payload.nonce     || payload.n
    };
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
  return { id: user.id, name: user.name, studentId: user.student_id, email: user.email, role: user.role };
}

// ── Middleware ────────────────────────────────────────────────────────────────
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const { rows } = await db.query(`
    SELECT u.*, t.created_at AS token_created_at
    FROM auth_tokens t
    JOIN users u ON u.id = t.user_id
    WHERE t.token = $1
  `, [token]);

  const row = rows[0];
  if (!row) return res.status(401).json({ error: 'Unauthorized' });
  if (Date.now() - Number(row.token_created_at) > TOKEN_TTL_MS) {
    await db.query('DELETE FROM auth_tokens WHERE token = $1', [token]);
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

const requireTeacherSubject = async (req, res, next) => {
  const subjectId = req.params.subjectId || req.body.subjectId;
  const { rows } = await db.query(
    'SELECT * FROM subjects WHERE id = $1 AND teacher_id = $2',
    [subjectId, req.user.id]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Subject not found or access denied.' });
  req.subject = rows[0];
  next();
};

const requireTeacherSession = async (req, res, next) => {
  const sessionId = req.params.sessionId || req.body.sessionId;
  const { rows } = await db.query(`
    SELECT se.*, su.subject_name, su.section
    FROM sessions se
    JOIN subjects su ON su.id = se.subject_id
    WHERE se.id = $1 AND se.teacher_id = $2
  `, [sessionId, req.user.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Session not found or access denied.' });
  req.sessionRow = rows[0];
  next();
};

// ── Routes ────────────────────────────────────────────────────────────────────

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { rows } = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = rows[0];
    if (!user || !bcrypt.compareSync(password || '', user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = crypto.randomBytes(24).toString('hex');
    await db.query(
      'INSERT INTO auth_tokens (token, user_id, created_at) VALUES ($1, $2, $3)',
      [token, user.id, Date.now()]
    );
    await logAudit(user.id, null, null, 'Login', `${user.name} logged in as ${user.role}`);
    res.json({ token, role: user.role, name: user.name, user: publicUser(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Login failed.' });
  }
});

app.post('/api/logout', authenticate, async (req, res) => {
  await db.query('DELETE FROM auth_tokens WHERE token = $1', [req.headers.authorization]);
  await logAudit(req.user.id, null, null, 'Logout', `${req.user.name} logged out`);
  res.json({ message: 'Logged out successfully.' });
});

app.get('/api/me',               authenticate,                          (req, res) => res.json(publicUser(req.user)));
app.get('/api/teacher/profile',  authenticate, requireRole('teacher'), (req, res) => res.json(publicUser(req.user)));
app.get('/api/student/profile',  authenticate, requireRole('student'), (req, res) => res.json(publicUser(req.user)));

app.post('/api/register', (req, res) => {
  res.status(403).json({ error: 'Student self-registration is disabled. Accounts are created by the institution.' });
});

// Teacher — subjects
app.get('/api/teacher/subjects', authenticate, requireRole('teacher'), async (req, res) => {
  const { rows } = await db.query(`
    SELECT s.*,
      (SELECT COUNT(*) FROM sessions WHERE subject_id = s.id) AS session_count
    FROM subjects s
    WHERE s.teacher_id = $1
    ORDER BY s.created_at DESC
  `, [req.user.id]);
  res.json({ subjects: rows });
});

app.post('/api/teacher/subjects', authenticate, requireRole('teacher'), async (req, res) => {
  const subjectName = String(req.body.subjectName || '').trim();
  const section     = String(req.body.section     || '').trim();
  if (!subjectName || !section) return res.status(400).json({ error: 'Subject name and section are required.' });

  const subjectId = uid('subj');
  try {
    await db.query(
      'INSERT INTO subjects (id, teacher_id, subject_name, section) VALUES ($1, $2, $3, $4)',
      [subjectId, req.user.id, subjectName, section]
    );
    await logAudit(req.user.id, subjectId, null, 'Create Subject', `Created ${subjectName} Section ${section}`);
    res.status(201).json({ id: subjectId, teacher_id: req.user.id, subject_name: subjectName, section });
  } catch (e) {
    if (String(e.message).includes('unique') || String(e.code) === '23505') {
      return res.status(409).json({ error: 'This subject and section already exists.' });
    }
    console.error(e);
    res.status(500).json({ error: 'Could not create subject.' });
  }
});

// Teacher — sessions
app.get('/api/teacher/subjects/:subjectId/sessions', authenticate, requireRole('teacher'), requireTeacherSubject, async (req, res) => {
  const { rows } = await db.query(
    'SELECT * FROM sessions WHERE subject_id = $1 AND teacher_id = $2 ORDER BY session_date DESC, start_time DESC',
    [req.subject.id, req.user.id]
  );
  res.json({ subject: req.subject, sessions: rows });
});

app.post('/api/teacher/subjects/:subjectId/sessions', authenticate, requireRole('teacher'), requireTeacherSubject, async (req, res) => {
  const { sessionDate, startTime, endTime, classroomLat, classroomLng, allowedRadius } = req.body;
  if (!sessionDate || !startTime || !endTime || classroomLat == null || classroomLng == null || !allowedRadius) {
    return res.status(400).json({ error: 'Date, start time, end time, location, and allowed radius are required.' });
  }
  const start = new Date(`${sessionDate}T${startTime}`);
  const end   = new Date(`${sessionDate}T${endTime}`);
  if (isNaN(start) || isNaN(end) || end <= start) {
    return res.status(400).json({ error: 'Invalid date/time. End time must be after start time.' });
  }
  const radius = parseInt(allowedRadius, 10);
  if (!Number.isFinite(radius) || radius <= 0) return res.status(400).json({ error: 'Allowed radius must be a positive number.' });

  const sessionId = uid('sess');
  const qrToken   = generateQRToken(sessionId, req.subject.id);
  await db.query(`
    INSERT INTO sessions
      (id, subject_id, teacher_id, session_date, start_time, end_time, qr_token, classroom_lat, classroom_lng, allowed_radius)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
  `, [sessionId, req.subject.id, req.user.id, sessionDate, startTime, endTime, qrToken,
      parseFloat(classroomLat), parseFloat(classroomLng), radius]);
  await logAudit(req.user.id, req.subject.id, sessionId, 'Create QR Session',
    `Created QR session for ${req.subject.subject_name} Section ${req.subject.section} on ${sessionDate}`);
  res.status(201).json({ id: sessionId, subjectId: req.subject.id, qrToken, sessionDate, startTime, endTime });
});

// Teacher — attendance view
app.get('/api/teacher/sessions/:sessionId/attendance', authenticate, requireRole('teacher'), requireTeacherSession, async (req, res) => {
  const { rows } = await db.query(`
    SELECT
      u.id AS user_id, u.student_id, u.name, u.email,
      ar.submit_time, ar.distance_meters, ar.status, ar.warning_message
    FROM users u
    LEFT JOIN attendance_records ar ON ar.student_id = u.id AND ar.session_id = $1
    WHERE u.role = 'student'
    ORDER BY u.student_id ASC
  `, [req.sessionRow.id]);

  const attendance = rows.map(r => ({
    userId:         r.user_id,
    studentId:      r.student_id,
    name:           r.name,
    email:          r.email,
    status:         r.submit_time ? 'Checked' : 'Not Checked',
    submitTime:     r.submit_time,
    distanceMeters: r.distance_meters,
    warning:        r.warning_message || 'No'
  }));
  res.json({ session: req.sessionRow, attendance });
});

// Teacher — audit logs
app.get('/api/teacher/audit-logs', authenticate, requireRole('teacher'), async (req, res) => {
  const { rows } = await db.query(`
    SELECT l.*, u.name AS user_name, u.role, su.subject_name, su.section
    FROM audit_logs l
    LEFT JOIN users u  ON u.id  = l.user_id
    LEFT JOIN subjects su ON su.id = l.subject_id
    WHERE
      l.user_id    = $1
      OR l.subject_id IN (SELECT id FROM subjects WHERE teacher_id = $2)
      OR l.session_id IN (SELECT id FROM sessions WHERE teacher_id = $3)
    ORDER BY l.created_at DESC
    LIMIT 200
  `, [req.user.id, req.user.id, req.user.id]);
  res.json({ logs: rows });
});

// Student — submit attendance
app.post('/api/student/submit-attendance', authenticate, requireRole('student'), async (req, res) => {
  const { qrToken, latitude, longitude } = req.body;
  const payload = verifyQRToken(qrToken);
  if (!payload) {
    await logAudit(req.user.id, null, null, 'Submit Attendance Rejected', 'Invalid or fake QR token');
    return res.status(400).json({ status: 'Rejected', message: 'Invalid QR token.' });
  }

  const { rows: sessionRows } = await db.query(`
    SELECT se.*, su.subject_name, su.section
    FROM sessions se
    JOIN subjects su ON su.id = se.subject_id
    WHERE se.id = $1 AND se.subject_id = $2
  `, [payload.sessionId, payload.subjectId]);
  const session = sessionRows[0];
  if (!session) return res.status(400).json({ status: 'Rejected', message: 'Session not found.' });

  const now   = new Date();
  const start = new Date(`${session.session_date}T${session.start_time}`);
  const end   = new Date(`${session.session_date}T${session.end_time}`);
  if (now < start || now > end) {
    await logAudit(req.user.id, session.subject_id, session.id, 'Submit Attendance Rejected', 'Attendance session is closed or expired');
    return res.status(400).json({ status: 'Rejected', message: 'Attendance session is not open now.' });
  }

  const { rows: dupRows } = await db.query(
    'SELECT id FROM attendance_records WHERE session_id = $1 AND student_id = $2',
    [session.id, req.user.id]
  );
  if (dupRows[0]) {
    await logAudit(req.user.id, session.subject_id, session.id, 'Duplicate Attendance Attempt', `${req.user.name} tried to submit again`);
    return res.status(400).json({ status: 'Rejected', message: 'You already checked attendance for this session.' });
  }

  const lat = parseFloat(latitude);
  const lng = parseFloat(longitude);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
    return res.status(400).json({ status: 'Rejected', message: 'Location permission is required for attendance verification.' });
  }

  const distance = getDistance(session.classroom_lat, session.classroom_lng, lat, lng);
  let status  = 'Checked';
  let warning = 'No';
  if (distance > session.allowed_radius) {
    status  = 'Checked with Warning';
    warning = `Far location (${Math.round(distance)}m away)`;
    await logAudit(req.user.id, session.subject_id, session.id, 'Far Location Warning', `${req.user.name} checked in ${Math.round(distance)}m away`);
  } else {
    await logAudit(req.user.id, session.subject_id, session.id, 'Submit Attendance', `${req.user.name} checked in successfully`);
  }

  const recordId = uid('rec');
  await db.query(`
    INSERT INTO attendance_records
      (id, session_id, student_id, submit_time, latitude, longitude, distance_meters, status, warning_message)
    VALUES ($1, $2, $3, NOW(), $4, $5, $6, $7, $8)
  `, [recordId, session.id, req.user.id, lat, lng, Math.round(distance), status, warning]);

  res.json({
    id:             recordId,
    subjectName:    session.subject_name,
    section:        session.section,
    status,
    warningMessage: warning,
    distanceMeters: Math.round(distance)
  });
});

// Student — my attendance
app.get('/api/student/my-attendance', authenticate, requireRole('student'), async (req, res) => {
  const { rows } = await db.query(`
    SELECT ar.*, se.session_date, se.start_time, se.end_time, su.subject_name, su.section
    FROM attendance_records ar
    JOIN sessions se ON se.id = ar.session_id
    JOIN subjects su ON su.id = se.subject_id
    WHERE ar.student_id = $1
    ORDER BY ar.submit_time DESC
  `, [req.user.id]);
  res.json({ records: rows });
});

// Backward compatible alias
app.get('/api/student/dashboard', authenticate, requireRole('student'), async (req, res) => {
  const { rows } = await db.query(`
    SELECT ar.*, su.subject_name, su.section
    FROM attendance_records ar
    JOIN sessions se ON se.id = ar.session_id
    JOIN subjects su ON su.id = se.subject_id
    WHERE ar.student_id = $1
    ORDER BY ar.submit_time DESC
  `, [req.user.id]);
  res.json({ records: rows });
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;

(async () => {
  try {
    await initSchema();
    await seedUsers();
    app.listen(PORT, () => {
      console.log(`\n🎓 AttendX server running → http://localhost:${PORT}`);
      console.log('🔐 Demo teacher: teacher@example.com / teacher123');
      console.log('🧑‍🎓 Demo student: 6622701845@g.siit.tu.ac.th / student123\n');
    });
  } catch (e) {
    console.error('❌ Startup failed:', e);
    process.exit(1);
  }
})();
