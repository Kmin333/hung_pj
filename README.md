# AttendX — Secure QR Code Attendance System

A university mini-project prototype using Node.js, Express, SQLite, HMAC-signed QR tokens, role-based access control, GPS distance checking, duplicate attendance prevention, and audit logging.

## How to run

```bash
npm install
npm start
```

Open:

```text
http://localhost:3000
```

If you are replacing an older version and the database becomes inconsistent, delete these files and restart:

```text
attendx.db
attendx.db-shm
attendx.db-wal
```

The server will recreate and seed the database automatically.

## Demo accounts

Teacher:

```text
teacher@example.com / teacher123
```

Students:

```text
6622701845@g.siit.tu.ac.th / student123  (Harry Potter)
6622703928@g.siit.tu.ac.th / student123  (Hermione Granger)
6622707461@g.siit.tu.ac.th / student123  (Ron Weasley)
6622705139@g.siit.tu.ac.th / student123  (Draco Malfoy)
6622708256@g.siit.tu.ac.th / student123  (Luna Lovegood)
```

## Main completed features

- Student self-registration disabled to reduce fake accounts.
- Teacher and 5 student seed accounts.
- Teacher profile and student profile tabs.
- Teacher can create subjects and sections.
- Teacher can create QR sessions under each subject.
- Teacher can use current location as classroom reference location.
- QR token is signed using HMAC and contains session ID, subject ID, timestamp, and nonce.
- Teacher can save/download QR as PNG.
- Student scans QR using camera via html5-qrcode.
- Student location is checked against classroom location.
- Duplicate attendance is prevented using UNIQUE(session_id, student_id).
- Teacher attendance list shows all students, including Not Checked students.
- Audit log is separated into its own tab and filtered for the teacher’s own subjects/sessions.

## Limitations

- GPS can be inaccurate or spoofed, so location is used as a warning indicator, not absolute proof.
- Camera QR scanning uses the html5-qrcode CDN, so the browser needs internet access to load that library.
- This is a prototype, so HTTPS deployment and stronger production security settings should be added for real use.
