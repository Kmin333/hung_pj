const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const db = new Database('attendx.db');

db.pragma('foreign_keys = ON');

db.exec(`DELETE FROM attendance_records; DELETE FROM sessions; DELETE FROM subjects; DELETE FROM audit_logs; DELETE FROM auth_tokens; DELETE FROM users;`);

const insert = db.prepare(`INSERT INTO users (id, name, student_id, email, password, role) VALUES (?, ?, ?, ?, ?, ?)`);
const users = [
  ['u_teacher', 'Professor Minerva McGonagall', null, 'teacher@example.com', 'teacher123', 'teacher'],
  ['u_harry', 'Harry Potter', '6622701845', '6622701845@g.siit.tu.ac.th', 'student123', 'student'],
  ['u_hermione', 'Hermione Granger', '6622703928', '6622703928@g.siit.tu.ac.th', 'student123', 'student'],
  ['u_ron', 'Ron Weasley', '6622707461', '6622707461@g.siit.tu.ac.th', 'student123', 'student'],
  ['u_draco', 'Draco Malfoy', '6622705139', '6622705139@g.siit.tu.ac.th', 'student123', 'student'],
  ['u_luna', 'Luna Lovegood', '6622708256', '6622708256@g.siit.tu.ac.th', 'student123', 'student']
];

const tx = db.transaction(() => {
  users.forEach(([id, name, sid, email, pass, role]) => insert.run(id, name, sid, email, bcrypt.hashSync(pass, 10), role));
});
tx();
console.log('Seed complete: teacher@example.com / teacher123 and 5 student accounts / student123');
