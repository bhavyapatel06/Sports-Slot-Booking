const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.resolve(__dirname, 'sports_facility.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('Error opening database:', err.message);
    else console.log('Connected to the Sports Facility SQLite database.');
});

db.serialize(() => {
    db.run('PRAGMA foreign_keys = ON');
    db.run('PRAGMA busy_timeout = 5000');

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT CHECK(role IN ('admin', 'helpdesk')) NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS sports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS courts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sport_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        FOREIGN KEY(sport_id) REFERENCES sports(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        roll_number TEXT,
        name TEXT,
        email TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE,
        student_name TEXT,
        roll_number TEXT,
        primary_student_id INTEGER,
        court_id INTEGER,
        booking_date TEXT,
        start_time TEXT,
        end_time TEXT,
        status TEXT,
        bulk_group_id TEXT,
        booking_type TEXT DEFAULT 'student',
        reason TEXT,
        admin_name TEXT,
        cancelled_by TEXT,
        cancellation_reason TEXT,
        FOREIGN KEY(court_id) REFERENCES courts(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS booking_participants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        booking_id INTEGER NOT NULL,
        student_id INTEGER NOT NULL,
        role TEXT NOT NULL DEFAULT 'additional' CHECK(role IN ('additional')),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(booking_id, student_id),
        FOREIGN KEY(booking_id) REFERENCES bookings(id) ON DELETE CASCADE,
        FOREIGN KEY(student_id) REFERENCES students(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        admin_name TEXT,
        date_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        booking_id INTEGER,
        reason TEXT,
        old_status TEXT,
        new_status TEXT,
        ip_address TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        roll_number TEXT NOT NULL,
        student_name TEXT,
        sport_id INTEGER NOT NULL,
        sport_name TEXT,
        start_datetime TEXT NOT NULL,
        end_datetime TEXT NOT NULL,
        duration_value INTEGER,
        duration_unit TEXT,
        status TEXT CHECK(status IN ('active', 'removed')) DEFAULT 'active',
        created_by TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        removed_by TEXT,
        removed_at DATETIME,
        reason TEXT,
        FOREIGN KEY(sport_id) REFERENCES sports(id)
    )`);

    db.run(`CREATE INDEX IF NOT EXISTS idx_bookings_court_schedule ON bookings(court_id, booking_date, status, start_time, end_time)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_booking_participants_student ON booking_participants(student_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_students_roll_number ON students(roll_number)`);
    db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_students_roll_number_unique_ci ON students(UPPER(TRIM(roll_number))) WHERE roll_number IS NOT NULL AND TRIM(roll_number) <> ''`);
});

module.exports = db;