const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto'); // Built-in for Bulk ID Generation
require('dotenv').config();
const XLSX = require('xlsx');

const app = express();
const PORT = Number(process.env.PORT) || 3005;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// ============================================================================
// SESSION / AUTH LAYER
// Lightweight in-memory token store. Login issues a random token; every
// protected route below requires that token in the "x-auth-token" header.
// This closes the gap where any API route could previously be called
// directly (e.g. via curl) with no login at all, and it means the server
// - not the browser - is the source of truth for "who is doing this
// action", so audit fields like admin_name/cancelled_by/created_by can no
// longer be spoofed by simply editing a request body.
// ============================================================================
const sessions = new Map(); // token -> { username, role, expires }
const DUMMY_PASSWORD_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 10);
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

const passwordResetTokens = new Map(); // resetToken -> { otpId, userId, expires }
const accountDeletionTokens = new Map(); // deleteToken -> { otpId, targetUserId, requesterUserId, expires }
const forgotPasswordIpRate = new Map(); // ip -> { count, windowStart }
const FORGOT_OTP_TTL_MS = 2 * 60 * 1000; // 2-minute password-reset OTP validity
const FORGOT_COOLDOWN_MS = 60 * 1000;
const FORGOT_IP_WINDOW_MS = 60 * 60 * 1000;
const FORGOT_IP_MAX_REQUESTS = 10;

// Expired sessions were only ever removed when their own token was reused, so
// abandoned sessions stayed in memory forever. Sweep them periodically.
setInterval(() => {
    const now = Date.now();
    for (const [token, session] of sessions.entries()) {
        if (session.expires < now) sessions.delete(token);
    }
    for (const [key, rec] of loginAttempts.entries()) {
        if (rec.lockedUntil < now && now - rec.windowStart > LOGIN_WINDOW_MS) loginAttempts.delete(key);
    }
}, 10 * 60 * 1000).unref();

// Brute-force protection for /api/auth/login (per IP + username).
const loginAttempts = new Map(); // key -> { count, windowStart, lockedUntil }
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILURES = 8;
const LOGIN_LOCK_MS = 15 * 60 * 1000;
function loginKey(ip, username) { return `${ip || 'unknown'}|${String(username).toLowerCase()}`; }
function isLoginLocked(key) {
    const rec = loginAttempts.get(key);
    return !!rec && rec.lockedUntil > Date.now();
}
function recordLoginFailure(key) {
    const now = Date.now();
    let rec = loginAttempts.get(key);
    if (!rec || now - rec.windowStart > LOGIN_WINDOW_MS) rec = { count: 0, windowStart: now, lockedUntil: 0 };
    rec.count += 1;
    if (rec.count >= LOGIN_MAX_FAILURES) rec.lockedUntil = now + LOGIN_LOCK_MS;
    loginAttempts.set(key, rec);
}

function issueSessionToken(user) {
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { userId: user.id, username: user.username, role: user.role, email: user.email || '', expires: Date.now() + SESSION_TTL_MS });
    return token;
}

function invalidateUserSessions(userId) {
    if (!Number.isInteger(Number(userId))) return;
    for (const [token, session] of sessions.entries()) {
        if (Number(session.userId) === Number(userId)) sessions.delete(token);
    }
}

// ============================================================================
// WRITE-TRANSACTION SERIALIZATION
// node-sqlite3 does not serialize commands from concurrent async request
// handlers on a single shared connection unless the app queues them itself.
// Without this, two requests that each open a BEGIN IMMEDIATE TRANSACTION at
// close to the same instant (e.g. two helpdesk terminals booking at once, or
// a booking landing alongside a student-details edit) can interleave, and
// whichever one calls BEGIN while the other's transaction is still open
// fails outright with "cannot start a transaction within a transaction" -
// even though the slot it wanted was completely free. runExclusive() makes
// every transactional request wait its turn instead of colliding.
// ============================================================================
let transactionQueue = Promise.resolve();
function runExclusive(task) {
    const turn = transactionQueue.then(() => new Promise((resolve) => task(resolve)));
    transactionQueue = turn.catch(() => {}); // one request's failure must never jam the queue for the next
    return turn;
}

function requireAuth(req, res, next) {
    const token = req.headers['x-auth-token'];
    const session = token ? sessions.get(token) : null;
    if (!session || session.expires < Date.now()) {
        if (session) sessions.delete(token);
        return res.status(401).json({ error: "Session expired or invalid. Please log in again." });
    }
    req.authUser = session; // { username, role }
    next();
}

function requireAdmin(req, res, next) {
    requireAuth(req, res, () => {
        if (req.authUser.role !== 'admin') {
            return res.status(403).json({ error: "Admin privileges are required for this action." });
        }
        next();
    });
}

// ============================================================================
// IST (Asia/Kolkata) TIME HELPERS
// Mirrors the exact conversion approach already used on the frontend
// (new Date(new Date().toLocaleString("en-US", {timeZone:"Asia/Kolkata"})))
// so backend validation stays consistent with existing client-side logic.
// ============================================================================
function getISTNow() {
    return new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Kolkata' }));
}

function formatISTDateTime(d) {
    const y = d.getFullYear();
    const mo = String(d.getMonth() + 1).padStart(2, '0');
    const da = String(d.getDate()).padStart(2, '0');
    const h = String(d.getHours()).padStart(2, '0');
    const mi = String(d.getMinutes()).padStart(2, '0');
    const s = String(d.getSeconds()).padStart(2, '0');
    return `${y}-${mo}-${da} ${h}:${mi}:${s}`;
}

function formatISTDateOnly(d) {
    return formatISTDateTime(d).split(' ')[0];
}

function parseStoredTimestamp(value) {
    const raw = String(value || '').trim();
    if (!raw) return NaN;
    return Date.parse(raw.includes('T') ? raw : `${raw.replace(' ', 'T')}Z`);
}

// ROLL_NUMBER_PATTERN backs the Enrollment Number field -- the primary
// user-facing student identifier for lookup/autofill/search (see
// findOrCreateStudent and /api/students/full-profile). The underlying
// database/column name (roll_number) is left as-is to avoid an invasive
// rename across every query; "enrollment number" and "roll number" refer to
// the same value throughout this file.
const ROLL_NUMBER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/-]{1,49}$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const EMAIL_LOCAL_PART_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,149}$/;
const UNIVERSITY_EMAIL_DOMAIN = '@ahduni.edu.in';
const TIME_PATTERN = /^([01]\d|2[0-3]):[0-5]\d$/;
const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

function cleanStudentInput(value) {
    return typeof value === 'string' ? value.trim().replace(/\s+/g, ' ') : '';
}

// Centralized university email shortcut: complete addresses are preserved;
// only a local part receives @ahduni.edu.in.
function normalizeUniversityEmail(value) {
    const cleaned = typeof value === 'string' ? value.trim() : '';
    if (!cleaned) return '';
    if (cleaned.includes('@')) return cleaned;
    if (!EMAIL_LOCAL_PART_PATTERN.test(cleaned)) return cleaned;
    return `${cleaned}${UNIVERSITY_EMAIL_DOMAIN}`;
}

function validateStudentDetails(student) {
    const roll_number = cleanStudentInput(student.roll_number || student.enrollment_number);
    const name = cleanStudentInput(student.name || student.student_name);
    const email = normalizeUniversityEmail(student.email);
    if (!ROLL_NUMBER_PATTERN.test(roll_number)) return { error: 'Enter a valid enrollment number.' };
    if (!name || name.length > 100) return { error: 'Enter a valid student name.' };
    if (!EMAIL_PATTERN.test(email) || email.length > 150) return { error: 'Enter a valid email address.' };
    return { roll_number, name, email };
}

function validateEnrollmentNumber(value) {
    const roll_number = cleanStudentInput(value);
    if (!ROLL_NUMBER_PATTERN.test(roll_number)) return { error: 'Enter a valid enrollment number.' };
    return { roll_number };
}

function validatePasswordValue(value, label = 'Password') {
    if (typeof value !== 'string' || value.length < 8) return `${label} must be at least 8 characters.`;
    if (value.length > 128) return `${label} must not exceed 128 characters.`;
    return null;
}

function validateBookingDetails({ court_id, booking_date, start_time, end_time }) {
    if (!Number.isInteger(Number(court_id)) || Number(court_id) <= 0) return 'A valid court is required.';
    if (!DATE_PATTERN.test(booking_date || '') || !TIME_PATTERN.test(start_time || '') || !TIME_PATTERN.test(end_time || '')) return 'Enter a valid date and time range.';
    if (end_time <= start_time) return 'End time must be later than start time.';
    const now = getISTNow();
    const today = formatISTDateOnly(now);
    const nowTime = formatISTDateTime(now).slice(11, 16);
    if (booking_date < today || (booking_date === today && end_time <= nowTime)) return 'Cannot create a booking for a time slot that has already ended (IST).';
    return null;
}

// Turns "YYYY-MM-DD" into a readable "14 February 2027" style string for UI messages
function formatHumanReadableDate(ymd) {
    if (!ymd) return 'Unknown';
    const [y, m, d] = ymd.split('-').map(Number);
    if (!y || !m || !d) return ymd;
    const months = ['January','February','March','April','May','June','July','August','September','October','November','December'];
    return `${d} ${months[m - 1]} ${y}`;
}

// Parses a "YYYY-MM-DD" string as a local calendar date (midnight local time).
// Plain `new Date("YYYY-MM-DD")` parses as UTC midnight, which can silently
// shift the date backward by a day once you read it back with local getters
// (getFullYear/getMonth/getDate) on a server whose timezone is behind UTC.
// This keeps date-range generation (e.g. bulk booking) stable regardless of
// the host server's timezone setting.
function parseYMDLocal(ymd) {
    const [y, m, d] = ymd.split('-').map(Number);
    return new Date(y, (m || 1) - 1, d || 1);
}

// Computes an IST expiry Date given a start Date + duration value/unit ('days'|'months'|'years')
function addDurationIST(startDate, value, unit) {
    const end = new Date(startDate.getTime());
    const n = parseInt(value, 10);
    if (unit === 'days') end.setDate(end.getDate() + n);
    else if (unit === 'months') end.setMonth(end.getMonth() + n);
    else if (unit === 'years') end.setFullYear(end.getFullYear() + n);
    return end;
}

// Middleware configurations
app.disable('x-powered-by');
app.use((req, res, next) => {
    res.set({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'same-origin'
    });
    if (req.path.startsWith('/api/')) res.set('Cache-Control', 'no-store');
    next();
});
app.use(express.json({ limit: '5mb' }));
if (process.env.CORS_ORIGIN) {
    app.use(cors({ origin: process.env.CORS_ORIGIN }));
}

// ============================================================================
// STATIC ASSET SERVING - SECURITY CRITICAL
// Only the ./public folder (index.html, logo.png, etc.) is ever exposed over
// HTTP. Serving express.static(__dirname) here previously exposed this
// entire project folder - including server.js (full source), package.json,
// .env, and - most seriously - sports_facility.db itself (every student's
// student names/roll numbers, plus the bcrypt password hashes for every
// admin/helpdesk account) - to any unauthenticated visitor who simply
// requested e.g. GET /sports_facility.db. Never widen this back to __dirname.
// ============================================================================
const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

// Root Route Interface
app.get('/', (req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

function getTableColumns(tableName) {
    return new Promise((resolve, reject) => {
        db.all(`PRAGMA table_info(${tableName})`, (err, rows) => {
            if (err && /no such table/i.test(err.message || '')) return resolve([]);
            return err ? reject(err) : resolve(rows || []);
        });
    });
}

function runDb(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) { err ? reject(err) : resolve(this); });
    });
}

function allDb(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows || []));
    });
}

async function migrateLegacyStudentAndBookingSchema() {
    const ensureColumn = async (tableName, columnName, definition) => {
        const columns = await getTableColumns(tableName);
        if (!columns.some(c => c.name === columnName)) {
            await runDb(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
        }
    };

    // Add all non-destructive columns first. No student data is removed here.
    await ensureColumn('students', 'email', 'TEXT');
    await ensureColumn('users', 'email', 'TEXT');
    await ensureColumn('bookings', 'bulk_group_id', 'TEXT');
    await ensureColumn('bookings', 'cancelled_at', 'TEXT');
    await ensureColumn('audit_logs', 'bulk_group_id', 'TEXT');
    await ensureColumn('bookings', 'booking_type', "TEXT DEFAULT 'student'");
    await ensureColumn('bookings', 'reason', 'TEXT');
    await ensureColumn('bookings', 'admin_name', 'TEXT');
    await ensureColumn('bookings', 'cancelled_by', 'TEXT');
    await ensureColumn('bookings', 'cancellation_reason', 'TEXT');
    await ensureColumn('bookings', 'primary_student_id', 'INTEGER');
    await ensureColumn('blacklist', 'reason', 'TEXT');

    // Backfill the relational primary-student link for legacy bookings using
    // their preserved enrollment snapshot. Historical booking rows remain intact.
    await runDb(`UPDATE bookings
        SET primary_student_id = (
            SELECT st.id FROM students st
            WHERE UPPER(TRIM(st.roll_number)) = UPPER(TRIM(bookings.roll_number))
            ORDER BY st.id ASC LIMIT 1
        )
        WHERE primary_student_id IS NULL AND roll_number IS NOT NULL`);

    // Legacy installations can contain duplicate enrollment numbers. Keep the
    // oldest student record and remap all participant/booking relationships to it.
    // This is done before the unique index is created.
    const duplicateGroups = await allDb(`
        SELECT UPPER(TRIM(roll_number)) AS normalized_roll, COUNT(*) AS count
        FROM students
        WHERE roll_number IS NOT NULL AND TRIM(roll_number) <> ''
        GROUP BY UPPER(TRIM(roll_number))
        HAVING COUNT(*) > 1
    `);

    for (const group of duplicateGroups) {
        const students = await allDb(`
            SELECT id FROM students
            WHERE UPPER(TRIM(roll_number)) = ?
            ORDER BY id ASC
        `, [group.normalized_roll]);

        const canonicalId = students[0].id;
        for (const duplicate of students.slice(1)) {
            // If both records occur in the same booking, remove only the duplicate
            // participant row; otherwise move it to the canonical student.
            await runDb(`
                DELETE FROM booking_participants
                WHERE student_id = ?
                  AND EXISTS (
                      SELECT 1 FROM booking_participants bp2
                      WHERE bp2.booking_id = booking_participants.booking_id
                        AND bp2.student_id = ?
                  )
            `, [duplicate.id, canonicalId]);

            await runDb(`UPDATE booking_participants SET student_id = ? WHERE student_id = ?`, [canonicalId, duplicate.id]);
            await runDb(`UPDATE bookings SET primary_student_id = ? WHERE primary_student_id = ?`, [canonicalId, duplicate.id]);
            await runDb(`DELETE FROM students WHERE id = ?`, [duplicate.id]);
        }
    }

    // Complete legacy email values that are clearly local-parts. Complete
    // addresses remain untouched.
    await runDb(`UPDATE students
        SET email = TRIM(email) || '${UNIVERSITY_EMAIL_DOMAIN}'
        WHERE email IS NOT NULL AND TRIM(email) <> ''
          AND INSTR(TRIM(email), '@') = 0
          AND TRIM(email) NOT GLOB '*[^A-Za-z0-9._+-]*'
          AND LENGTH(TRIM(email)) <= 150`);

    await runDb(`CREATE TABLE IF NOT EXISTS student_master (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        roll_number TEXT NOT NULL,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    await runDb(`CREATE UNIQUE INDEX IF NOT EXISTS idx_student_master_roll_unique_ci ON student_master(UPPER(TRIM(roll_number)))`);
    await runDb(`CREATE INDEX IF NOT EXISTS idx_student_master_roll ON student_master(UPPER(TRIM(roll_number)))`);

    await runDb(`CREATE TABLE IF NOT EXISTS password_reset_otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        email TEXT NOT NULL,
        otp_hash TEXT NOT NULL,
        requested_at DATETIME NOT NULL,
        expires_at DATETIME NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        used_at DATETIME,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);
    await runDb(`CREATE TABLE IF NOT EXISTS account_deletion_otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_user_id INTEGER NOT NULL,
        requester_user_id INTEGER NOT NULL,
        email TEXT NOT NULL,
        otp_hash TEXT NOT NULL,
        requested_at DATETIME NOT NULL,
        expires_at DATETIME NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        used_at DATETIME,
        FOREIGN KEY(target_user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(requester_user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);
    await runDb(`CREATE INDEX IF NOT EXISTS idx_password_reset_otps_email ON password_reset_otps(LOWER(email), requested_at)`);
    await runDb(`UPDATE users SET email = LOWER(TRIM(username)) WHERE (email IS NULL OR TRIM(email) = '') AND INSTR(username, '@') > 0`);

    const studentColumns = await getTableColumns('students');
    if (studentColumns.some(c => c.name === 'mobile_number')) {
        /*
         * IMPORTANT: PRAGMA foreign_keys cannot be switched off while SQLite is
         * inside a transaction. The previous migration attempted to do that and
         * then dropped students while booking_participants still referenced it,
         * which caused SQLITE_CONSTRAINT: FOREIGN KEY constraint failed.
         *
         * Rebuild the two related tables in dependency order instead. This keeps
         * foreign-key enforcement ON throughout the migration and preserves all
         * IDs/data while removing the legacy mobile_number column and its UNIQUE
         * constraint.
         */
        const participantColumns = await getTableColumns('booking_participants');
        const hasParticipants = participantColumns.length > 0;

        if (hasParticipants) {
            await runDb('ALTER TABLE booking_participants RENAME TO booking_participants__legacy');
        }

        await runDb('ALTER TABLE students RENAME TO students__legacy');

        await runDb(`CREATE TABLE students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            roll_number TEXT,
            name TEXT,
            email TEXT
        )`);

        await runDb(`
            INSERT INTO students (id, roll_number, name, email)
            SELECT id, roll_number, name, email
            FROM students__legacy
        `);

        if (hasParticipants) {
            await runDb(`CREATE TABLE booking_participants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                booking_id INTEGER NOT NULL,
                student_id INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT 'additional' CHECK(role IN ('additional')),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(booking_id, student_id),
                FOREIGN KEY(booking_id) REFERENCES bookings(id) ON DELETE CASCADE,
                FOREIGN KEY(student_id) REFERENCES students(id)
            )`);

            await runDb(`
                INSERT INTO booking_participants (id, booking_id, student_id, role, created_at)
                SELECT id, booking_id, student_id, role, created_at
                FROM booking_participants__legacy
            `);

            await runDb('DROP TABLE booking_participants__legacy');
        }

        await runDb('DROP TABLE students__legacy');
    }

    // Legacy contact-number fields in other tables can be dropped directly when
    // SQLite permits it. These fields are no longer read or written anywhere.
    for (const [tableName, columnName] of [
        ['bookings', 'mobile_number'],
        ['blacklist', 'mobile_number'],
        ['sms_logs', 'mobile_number']
    ]) {
        const columns = await getTableColumns(tableName);
        if (columns.some(c => c.name === columnName)) {
            await runDb(`ALTER TABLE ${tableName} DROP COLUMN ${columnName}`);
        }
    }

    await runDb(`CREATE INDEX IF NOT EXISTS idx_bookings_court_schedule ON bookings(court_id, booking_date, status, start_time, end_time)`);
    await runDb(`CREATE INDEX IF NOT EXISTS idx_booking_participants_student ON booking_participants(student_id)`);
    await runDb(`CREATE INDEX IF NOT EXISTS idx_students_roll_number ON students(roll_number)`);
    await runDb(`CREATE UNIQUE INDEX IF NOT EXISTS idx_students_roll_number_unique_ci ON students(UPPER(TRIM(roll_number))) WHERE roll_number IS NOT NULL AND TRIM(roll_number) <> ''`);
}

// Initialize relational SQLite database instance
const db = new sqlite3.Database(path.join(__dirname, 'sports_facility.db'), (err) => {
    if (err) console.error('Database connection failure:', err.message);
    else console.log('Connected smoothly to SQLite structural file engine.');
});

// Create schema structures and seed initial data sets cleanly
db.serialize(() => {
    db.run('PRAGMA foreign_keys = ON');
    // Without this, two near-simultaneous writes (e.g. two helpdesk terminals
    // booking at once, or a booking landing at the same instant as a bulk
    // admin operation) can make SQLite return SQLITE_BUSY immediately instead
    // of briefly waiting its turn - surfacing as a false "system busy, please
    // retry" error to a user whose request would otherwise have succeeded a
    // few milliseconds later. This makes SQLite wait up to 5s before giving up.
    db.run('PRAGMA busy_timeout = 5000');
    // Legacy Tables
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, role TEXT CHECK(role IN ('admin', 'helpdesk')), email TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS student_master (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        roll_number TEXT NOT NULL,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS password_reset_otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        email TEXT NOT NULL,
        otp_hash TEXT NOT NULL,
        requested_at DATETIME NOT NULL,
        expires_at DATETIME NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        used_at DATETIME,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS account_deletion_otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_user_id INTEGER NOT NULL,
        requester_user_id INTEGER NOT NULL,
        email TEXT NOT NULL,
        otp_hash TEXT NOT NULL,
        requested_at DATETIME NOT NULL,
        expires_at DATETIME NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        used_at DATETIME,
        FOREIGN KEY(target_user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(requester_user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);
    db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_student_master_roll_unique_ci ON student_master(UPPER(TRIM(roll_number)))`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_student_master_roll ON student_master(UPPER(TRIM(roll_number)))`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_password_reset_otps_email ON password_reset_otps(LOWER(email), requested_at)`);
    db.run(`CREATE TABLE IF NOT EXISTS sports (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)`);
    db.run(`CREATE TABLE IF NOT EXISTS courts (id INTEGER PRIMARY KEY AUTOINCREMENT, sport_id INTEGER, name TEXT, FOREIGN KEY(sport_id) REFERENCES sports(id))`);
    db.run(`CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY AUTOINCREMENT, roll_number TEXT, name TEXT, email TEXT)`);
    
    // Upgraded Facility Bookings Ledger
    db.run(`CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT UNIQUE, student_name TEXT, roll_number TEXT,
        court_id INTEGER, booking_date TEXT, start_time TEXT, end_time TEXT, status TEXT,
        bulk_group_id TEXT, booking_type TEXT DEFAULT 'student', reason TEXT, admin_name TEXT, cancelled_by TEXT, cancelled_at TEXT, cancellation_reason TEXT,
        FOREIGN KEY(court_id) REFERENCES courts(id)
    )`);

    // Additional players are normalized records: a student is stored once and
    // can participate in many bookings. Existing bookings remain valid because
    // this table is additive.
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

    // New audit logging tables
    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, admin_name TEXT, date_time DATETIME DEFAULT CURRENT_TIMESTAMP, booking_id INTEGER, bulk_group_id TEXT, reason TEXT, old_status TEXT, new_status TEXT, ip_address TEXT)`);

    // NEW: Student Blacklist Table (one row per sport per blacklist action, for simple per-sport enforcement/removal)
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
        FOREIGN KEY (sport_id) REFERENCES sports (id)
    )`);

    // Seed default administrative users
    // Development retains the original starter accounts. Production never
    // creates predictable credentials: configure INITIAL_ADMIN_PASSWORD
    // before first launch, then create helpdesk accounts from the admin panel.
    const initialAdminPassword = process.env.INITIAL_ADMIN_PASSWORD || (!IS_PRODUCTION ? 'admin123' : null);
    db.get('SELECT COUNT(*) AS count FROM users', (userCountErr, userCount) => {
        if (userCountErr || userCount.count > 0) return;
        if (!initialAdminPassword) {
            console.warn('Production startup: INITIAL_ADMIN_PASSWORD is not set; no administrator account was created.');
            return;
        }
        const salt = bcrypt.genSaltSync(10);
        db.run("INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)", ['admin', bcrypt.hashSync(initialAdminPassword, salt), 'admin', normalizeUniversityEmail(process.env.INITIAL_ADMIN_EMAIL || '') || null]);
        if (!IS_PRODUCTION) db.run("INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)", ['helpdesk', bcrypt.hashSync('helpdesk123', salt), 'helpdesk', normalizeUniversityEmail(process.env.INITIAL_HELPDESK_EMAIL || '') || null]);
    });

    // If an existing installation later supplies recovery email environment
    // variables, safely backfill only missing account email values.
    if (process.env.INITIAL_ADMIN_EMAIL) db.run(`UPDATE users SET email = ? WHERE username = 'admin' AND (email IS NULL OR TRIM(email) = '')`, [normalizeUniversityEmail(process.env.INITIAL_ADMIN_EMAIL)]);
    if (process.env.INITIAL_HELPDESK_EMAIL) db.run(`UPDATE users SET email = ? WHERE username = 'helpdesk' AND (email IS NULL OR TRIM(email) = '')`, [normalizeUniversityEmail(process.env.INITIAL_HELPDESK_EMAIL)]);

    // Default sports/courts are seeded deterministically after schema creation
    // and before the server accepts requests (see ensureDefaultSportsAndCourts).
});

async function ensureDefaultSportsAndCourts() {
    const defaultSports = [
        { name: 'Badminton', courts: 5 },
        { name: 'Volleyball', courts: 2 },
        { name: 'Basket Ball', courts: 1 },
        { name: 'Tennis', courts: 1 },
        { name: 'Table Tennis', courts: 1 },
        { name: 'Squash', courts: 2 },
        { name: 'Football', courts: 1 }
    ];

    let sports = await allDb('SELECT id, name FROM sports ORDER BY id');
    if (sports.length === 0) {
        for (const sport of defaultSports) {
            await runDb('INSERT OR IGNORE INTO sports (name) VALUES (?)', [sport.name]);
        }
        sports = await allDb('SELECT id, name FROM sports ORDER BY id');
    }

    // Some installations may already have sports records but no court records
    // (for example, if the first-run seed was interrupted). Restore the default
    // court layout only when the entire courts table is empty; never duplicate
    // or overwrite an administrator's existing court configuration.
    const courtCountRows = await allDb('SELECT COUNT(*) AS count FROM courts');
    if (Number(courtCountRows[0] && courtCountRows[0].count) === 0) {
        const defaultCourtCounts = new Map(defaultSports.map(s => [s.name.toLowerCase(), s.courts]));
        for (const sport of sports) {
            const count = defaultCourtCounts.get(String(sport.name || '').trim().toLowerCase()) || 1;
            for (let i = 1; i <= count; i += 1) {
                await runDb('INSERT INTO courts (sport_id, name) VALUES (?, ?)', [sport.id, `Court ${i}`]);
            }
        }
    }
}

const dbReady = new Promise((resolve, reject) => {
    db.run('SELECT 1', async (readyErr) => {
        if (readyErr) return reject(readyErr);
        try {
            // Ensure the resource selectors always have a valid initial data set.
            // This is awaited so /api/sports-layout cannot race the first-run seed.
            await ensureDefaultSportsAndCourts();

            // Keep the legacy-schema migration atomic. If any ALTER/UPDATE/index
            // operation fails, none of the migration changes are left partially
            // applied. The application refuses requests until this completes.
            await runDb('BEGIN IMMEDIATE TRANSACTION');
            try {
                await migrateLegacyStudentAndBookingSchema();
                await runDb('COMMIT');
            } catch (migrationErr) {
                try { await runDb('ROLLBACK'); } catch (rollbackErr) {
                    console.error('Database migration rollback failed:', rollbackErr.message);
                }
                throw migrationErr;
            }
            resolve();
        } catch (migrationErr) {
            reject(migrationErr);
        }
    });
});

app.use(async (req, res, next) => {
    try {
        await dbReady;
        next();
    } catch (err) {
        console.error('Database initialization failed:', err.message);
        res.status(500).json({ error: 'Database initialization failed.' });
    }
});

// ============================================================================
// EMAIL GATEWAY
// EMAIL_PROVIDER=mock (default) logs messages for development/testing.
// Set EMAIL_PROVIDER=smtp plus SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS/
// SMTP_FROM in .env to send real email through SMTP.
// ============================================================================
let smtpTransport = null;
function getSmtpTransport() {
    if (smtpTransport) return smtpTransport;
    const nodemailer = require('nodemailer');
    smtpTransport = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT) || 587,
        secure: Number(process.env.SMTP_PORT) === 465,
        auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
    });
    return smtpTransport;
}

async function dispatchEmail({ to, subject, text }) {
    if (!to) {
        console.warn(`Email skipped: no email address on file.`);
        return false;
    }
    const provider = process.env.EMAIL_PROVIDER || (IS_PRODUCTION ? 'smtp' : 'mock');
    try {
        if (provider === 'mock') {
            console.log(`\n===== EMAIL DISPATCH =====\nTO: ${to}\nSUBJECT: ${subject}\nBODY:\n${text}\n==========================\n`);
        } else {
            await getSmtpTransport().sendMail({
                from: process.env.SMTP_FROM || process.env.SMTP_USER,
                to,
                subject,
                text
            });
        }
        return true;
    } catch (error) {
        console.error('Email Gateway Error:', error.message);
        return false;
    }
}

async function sendBookingConfirmationEmail({ studentName, rollNumber, email, sport, court, bookingDate, startTime, endTime, token }) {
    return dispatchEmail({
        to: email,
        subject: 'Sports Session Booking Confirmation',
        text: `Dear ${studentName},\n\nYour sports session booking has been confirmed.\n\nEnrollment Number: ${rollNumber}\nSport: ${sport}\nCourt/Slot: ${court}\nBooking Date: ${bookingDate}\nTime: ${startTime} - ${endTime}\nBooking Token: ${token}\n\nPlease retain your booking token for reference.\n\nRegards,\nUniversity Sports Facility`
    });
}

async function sendBookingCancellationEmail({ studentName, rollNumber, email, sport, court, bookingDate, startTime, endTime, token, reason, cancelledBy }) {
    return dispatchEmail({
        to: normalizeUniversityEmail(email),
        subject: 'Sports Session Booking Terminated',
        text: `Dear ${studentName},\n\nYour sports session booking has been terminated by the University Sports Facility team.\n\nEnrollment Number: ${rollNumber}\nSport: ${sport}\nCourt/Slot: ${court}\nBooking Date: ${bookingDate}\nTime: ${startTime} - ${endTime}\nBooking Token: ${token}\nCancelled By: ${cancelledBy}\nReason: ${reason}\n\nIf you believe this was done in error, please contact the sports facility helpdesk.\n\nRegards,\nUniversity Sports Facility`
    });
}

async function sendAdditionalParticipantEmail({ studentName, rollNumber, email, primaryName, sport, court, bookingDate, startTime, endTime }) {
    return dispatchEmail({
        to: email,
        subject: 'Sports Session Booking — You Have Been Added as a Participant',
        text: `Dear ${studentName},\n\nYou have been booked for a sports session by ${primaryName}.\n\nYour booking details are:\n\nEnrollment Number: ${rollNumber}\nPrimary Booker: ${primaryName}\nSport: ${sport}\nCourt/Slot: ${court}\nDate: ${bookingDate}\nTime: ${startTime} - ${endTime}\n\nPlease note that you are listed as an additional participant in this booking.\n\nRegards,\nUniversity Sports Facility`
    });
}

async function sendRestrictionEmail({ type, studentName, rollNumber, email, reason, sportsList, whenStr }) {
    if (!email) {
        console.warn(`Restriction email skipped: no email on file for enrollment number ${rollNumber}.`);
        return false;
    }
    const subject = type === 'imposed' ? 'Booking Restriction Imposed' : 'Booking Privileges Restored';
    const body = type === 'imposed'
        ? `Dear ${studentName},\n\nA booking restriction has been imposed on your sports booking account.\n\nEnrollment Number: ${rollNumber}\nSport(s): ${sportsList}\n\nReason for Restriction:\n${reason}\n\nRestriction Date: ${whenStr}\n\nYour sports booking privileges are currently restricted.\n\nRegards,\nUniversity Sports Facility`
        : `Dear ${studentName},\n\nYour sports booking restriction has been removed.\n\nEnrollment Number: ${rollNumber}\nSport(s): ${sportsList}\n\nYour sports booking privileges have now been restored. You may make bookings according to the normal university sports booking rules.\n\nRestoration Date: ${whenStr}\n\nRegards,\nUniversity Sports Facility`;
    return dispatchEmail({ to: email, subject, text: body });
}

// ============================================================================
// PARTY-WIDE SCHEDULE VALIDATION HELPERS (used by /api/bookings/create)
// See the large comment at the call site for why these check every player
// in a booking party (primary + additional), not just the primary booker.
// ============================================================================

// Resolves to the blacklist row for the first person in `people` who is
// currently blacklisted for `sport_id`, or null if the whole party is clear.
function findBlacklistedParticipant(people, sport_id, nowStr) {
    return new Promise((resolve, reject) => {
        const rolls = people.map(p => p.roll_number.toUpperCase());
        const placeholders = rolls.map(() => '?').join(',');
        db.get(
            `SELECT roll_number, end_datetime FROM blacklist WHERE UPPER(roll_number) IN (${placeholders}) AND sport_id = ? AND status = 'active' AND end_datetime > ? LIMIT 1`,
            [...rolls, sport_id, nowStr],
            (err, row) => err ? reject(err) : resolve(row || null)
        );
    });
}

// Resolves to { roll } for the first person in `people` who already has
// another ACTIVE booking - as primary or as an additional player, in ANY
// sport - whose time range overlaps [start_time, end_time) on this date.
// Deliberately not scoped to one sport: a student cannot physically occupy
// two courts at the same time no matter which sports are involved.
function findTimeConflictParticipant(people, booking_date, start_time, end_time) {
    return new Promise((resolve, reject) => {
        const rolls = people.map(p => p.roll_number.toUpperCase());
        const placeholders = rolls.map(() => '?').join(',');
        const query = `
            SELECT UPPER(b.roll_number) AS roll FROM bookings b
            WHERE UPPER(b.roll_number) IN (${placeholders}) AND b.booking_date = ? AND b.status = 'active' AND b.start_time < ? AND b.end_time > ?
            UNION
            SELECT UPPER(st.roll_number) AS roll FROM booking_participants bp
            JOIN students st ON st.id = bp.student_id
            JOIN bookings b ON b.id = bp.booking_id
            WHERE UPPER(st.roll_number) IN (${placeholders}) AND b.booking_date = ? AND b.status = 'active' AND b.start_time < ? AND b.end_time > ?
            LIMIT 1`;
        const params = [...rolls, booking_date, end_time, start_time, ...rolls, booking_date, end_time, start_time];
        db.get(query, params, (err, row) => err ? reject(err) : resolve(row || null));
    });
}

// Resolves to an existing ACTIVE NORMAL student booking when the PRIMARY
// student already has the same sport on the same booking date. Additional
// participants are intentionally NOT inspected here: being an additional
// player never consumes the primary-booking allowance.
function findPrimarySameSportSameDayBooking(primaryStudentId, primaryRollNumber, sport_id, booking_date) {
    return new Promise((resolve, reject) => {
        const query = `
            SELECT b.id
            FROM bookings b
            JOIN courts c ON c.id = b.court_id
            WHERE c.sport_id = ?
              AND b.booking_date = ?
              AND b.status = 'active'
              AND COALESCE(b.booking_type, 'student') != 'bulk'
              AND (
                    b.primary_student_id = ?
                    OR (
                        b.primary_student_id IS NULL
                        AND UPPER(TRIM(b.roll_number)) = UPPER(TRIM(?))
                    )
                  )
            LIMIT 1`;
        db.get(query, [sport_id, booking_date, primaryStudentId, primaryRollNumber],
            (err, row) => err ? reject(err) : resolve(row || null));
    });
}

function getMasterStudentByRoll(rollNumber) {
    return new Promise((resolve, reject) => {
        db.get(`SELECT id, roll_number, name, email FROM student_master WHERE UPPER(TRIM(roll_number)) = UPPER(TRIM(?)) LIMIT 1`, [rollNumber], (err, row) => {
            if (err) return reject(err);
            resolve(row || null);
        });
    });
}

function hashResetOtp(otp) {
    return crypto.createHash('sha256').update(String(otp)).digest('hex');
}

function issuePasswordResetToken(otpId, userId) {
    const token = crypto.randomBytes(32).toString('hex');
    passwordResetTokens.set(token, { otpId, userId, expires: Date.now() + FORGOT_OTP_TTL_MS });
    return token;
}

function cleanupPasswordResetTokens() {
    const now = Date.now();
    for (const [token, record] of passwordResetTokens.entries()) {
        if (record.expires <= now) passwordResetTokens.delete(token);
    }
}

function consumeForgotIpRate(ip) {
    const key = String(ip || 'unknown');
    const now = Date.now();
    const current = forgotPasswordIpRate.get(key);
    if (!current || now - current.windowStart >= FORGOT_IP_WINDOW_MS) {
        forgotPasswordIpRate.set(key, { count: 1, windowStart: now });
        return true;
    }
    if (current.count >= FORGOT_IP_MAX_REQUESTS) return false;
    current.count += 1;
    return true;
}

// ============================================================================
// SYSTEM API ROUTE DEFINITIONS & ENDPOINTS
// ============================================================================

app.post('/api/auth/login', (req, res) => {
    const username = cleanStudentInput(req.body.username);
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });
    const attemptKey = loginKey(req.ip, username);
    if (isLoginLocked(attemptKey)) return res.status(429).json({ error: 'Too many failed login attempts. Please try again in 15 minutes.' });
    db.get("SELECT * FROM users WHERE LOWER(TRIM(username)) = LOWER(TRIM(?)) LIMIT 1", [username], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Unable to authenticate at this time.' });
        try {
            const hashToCheck = user && typeof user.password_hash === 'string' ? user.password_hash : DUMMY_PASSWORD_HASH;
            const passwordOk = await bcrypt.compare(password, hashToCheck);
            if (!user || !passwordOk) {
                recordLoginFailure(attemptKey);
                return res.status(401).json({ error: 'Invalid username or password.' });
            }
            loginAttempts.delete(attemptKey);
            const token = issueSessionToken(user);
            res.json({ id: user.id, username: user.username, role: user.role, email: user.email || '', token: token });
        } catch (compareErr) {
            console.error('Login verification failed:', compareErr.message);
            res.status(500).json({ error: 'Unable to authenticate at this time.' });
        }
    });
});

app.post('/api/auth/forgot-password', async (req, res) => {
    const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
    const genericMessage = 'If the account exists, a password reset OTP has been sent to its registered email address.';
    const genericNow = Date.now();

    // Always return the same public response shape so the endpoint does not
    // reveal whether a username exists.
    const genericResponse = (expiresAtMs = genericNow + FORGOT_OTP_TTL_MS, resendAtMs = genericNow + FORGOT_COOLDOWN_MS, registeredEmail = '') => ({
        success: true,
        message: registeredEmail ? `OTP has been sent to: ${registeredEmail}` : genericMessage,
        registered_email: registeredEmail || null,
        otp_expires_at: new Date(expiresAtMs).toISOString(),
        resend_available_at: new Date(resendAtMs).toISOString()
    });

    if (!username || username.length > 100) return res.json(genericResponse());
    if (!consumeForgotIpRate(req.ip)) return res.json(genericResponse());

    try {
        const user = await allDb(
            `SELECT id, username, email FROM users WHERE LOWER(TRIM(username)) = LOWER(TRIM(?)) LIMIT 1`,
            [username]
        ).then(rows => rows[0] || null);

        // Existing accounts without a recovery email remain valid accounts, but
        // cannot complete an email-based password reset until an email is added.
        if (!user || !user.email || !EMAIL_PATTERN.test(String(user.email).trim())) {
            return res.json(genericResponse());
        }

        const registeredEmail = String(user.email).trim().toLowerCase();
        const recent = await allDb(
            `SELECT id, requested_at, expires_at
             FROM password_reset_otps
             WHERE user_id = ? AND used_at IS NULL
             ORDER BY id DESC LIMIT 1`,
            [user.id]
        );

        if (recent[0] && recent[0].requested_at) {
            const requestedMs = parseStoredTimestamp(recent[0].requested_at);
            if (Number.isFinite(requestedMs) && Date.now() - requestedMs < FORGOT_COOLDOWN_MS) {
                const existingExpiresMs = parseStoredTimestamp(recent[0].expires_at);
                const expiresAtMs = Number.isFinite(existingExpiresMs)
                    ? existingExpiresMs
                    : Date.now() + FORGOT_OTP_TTL_MS;
                return res.json(genericResponse(expiresAtMs, requestedMs + FORGOT_COOLDOWN_MS, registeredEmail));
            }
        }

        const otp = String(crypto.randomInt(100000, 1000000));
        const now = new Date();
        const expires = new Date(now.getTime() + FORGOT_OTP_TTL_MS);

        // A new OTP invalidates every older unused OTP for this account.
        await runDb(
            `UPDATE password_reset_otps
             SET used_at = COALESCE(used_at, CURRENT_TIMESTAMP)
             WHERE user_id = ? AND used_at IS NULL`,
            [user.id]
        );

        const result = await runDb(
            `INSERT INTO password_reset_otps
             (user_id, email, otp_hash, requested_at, expires_at)
             VALUES (?, ?, ?, ?, ?)`,
            [user.id, registeredEmail, hashResetOtp(otp), now.toISOString(), expires.toISOString()]
        );

        const sent = await dispatchEmail({
            to: registeredEmail,
            subject: 'Sports Facility Password Reset OTP',
            text: `A password reset was requested for your University Sports Facility account.

OTP: ${otp}

This OTP expires in 2 minutes and can be used only once. If you did not request this reset, please ignore this email and contact your administrator.

Regards,
University Sports Facility`
        });

        if (!sent) console.error(`Password reset OTP email delivery failed for reset record ${result.lastID}.`);
        return res.json(genericResponse(expires.getTime(), now.getTime() + FORGOT_COOLDOWN_MS, registeredEmail));
    } catch (err) {
        console.error('Forgot password request failed:', err.message);
        return res.json(genericResponse());
    }
});

app.post('/api/auth/verify-reset-otp', async (req, res) => {
    cleanupPasswordResetTokens();
    const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
    const otp = typeof req.body.otp === 'string' ? req.body.otp.trim() : '';

    if (!username || username.length > 100 || !/^\d{6}$/.test(otp)) {
        return res.status(400).json({ error: 'Invalid OTP.' });
    }

    try {
        // The username remains the recovery identity throughout the entire flow.
        // The email is never supplied by or trusted from the browser.
        const row = await allDb(
            `SELECT pr.id, pr.user_id, pr.otp_hash, pr.expires_at, pr.attempts, pr.used_at
             FROM password_reset_otps pr
             JOIN users u ON u.id = pr.user_id
             WHERE LOWER(TRIM(u.username)) = LOWER(TRIM(?))
             ORDER BY pr.id DESC LIMIT 1`,
            [username]
        ).then(rows => rows[0] || null);

        if (!row || row.used_at) return res.status(400).json({ error: 'Invalid OTP.' });

        const expiresMs = parseStoredTimestamp(row.expires_at);
        if (!Number.isFinite(expiresMs) || expiresMs <= Date.now()) {
            return res.status(400).json({ error: 'OTP expired. Please request a new OTP.' });
        }

        if (Number(row.attempts || 0) >= 5) {
            return res.status(429).json({ error: 'Too many OTP attempts. Please request a new OTP.' });
        }

        const suppliedHash = hashResetOtp(otp);
        const expected = Buffer.from(String(row.otp_hash), 'hex');
        const actual = Buffer.from(suppliedHash, 'hex');
        const valid = expected.length === actual.length && crypto.timingSafeEqual(expected, actual);

        if (!valid) {
            await runDb(`UPDATE password_reset_otps SET attempts = attempts + 1 WHERE id = ?`, [row.id]);
            return res.status(400).json({ error: 'Invalid OTP.' });
        }

        const resetToken = issuePasswordResetToken(row.id, row.user_id);
        return res.json({
            success: true,
            reset_token: resetToken,
            otp_expires_at: new Date(expiresMs).toISOString()
        });
    } catch (err) {
        console.error('Reset OTP verification failed:', err.message);
        return res.status(500).json({ error: 'Unable to verify the OTP right now.' });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    cleanupPasswordResetTokens();
    const resetToken = typeof req.body.reset_token === 'string' ? req.body.reset_token.trim() : '';
    const newPassword = typeof req.body.new_password === 'string' ? req.body.new_password : '';
    const confirmPassword = typeof req.body.confirm_password === 'string' ? req.body.confirm_password : '';
    if (!resetToken) return res.status(400).json({ error: 'Password reset session is invalid. Please request a new OTP.' });
    const passwordError = validatePasswordValue(newPassword, 'New password');
    if (passwordError) return res.status(400).json({ error: passwordError });
    if (newPassword !== confirmPassword) return res.status(400).json({ error: 'New password and confirmation password do not match.' });

    const tokenRecord = passwordResetTokens.get(resetToken);
    if (!tokenRecord || tokenRecord.expires <= Date.now()) {
        passwordResetTokens.delete(resetToken);
        return res.status(400).json({ error: 'Password reset session has expired. Please request a new OTP.' });
    }

    try {
        const row = await allDb(`SELECT id, user_id, expires_at, used_at FROM password_reset_otps WHERE id = ? LIMIT 1`, [tokenRecord.otpId]).then(rows => rows[0] || null);
        if (!row || row.user_id !== tokenRecord.userId || row.used_at) return res.status(400).json({ error: 'Password reset session is invalid. Please request a new OTP.' });
        const expiresMs = parseStoredTimestamp(row.expires_at);
        if (!Number.isFinite(expiresMs) || expiresMs <= Date.now()) return res.status(400).json({ error: 'OTP expired. Please request a new OTP.' });
        const salt = bcrypt.genSaltSync(10);
        const newHash = bcrypt.hashSync(newPassword, salt);
        await runExclusive((releaseLock) => {
            db.run('BEGIN IMMEDIATE TRANSACTION', (beginErr) => {
                if (beginErr) { releaseLock(); return res.status(503).json({ error: 'The password service is busy. Please try again.' }); }
                const rollback = (message) => db.run('ROLLBACK', () => { releaseLock(); res.status(500).json({ error: message }); });
                db.run(`UPDATE users SET password_hash = ? WHERE id = ?`, [newHash, tokenRecord.userId], (updateErr) => {
                    if (updateErr) return rollback('Unable to update the account password.');
                    db.run(`UPDATE password_reset_otps SET used_at = CURRENT_TIMESTAMP WHERE id = ? AND used_at IS NULL`, [tokenRecord.otpId], function(markErr) {
                        if (markErr) return rollback('Unable to finalize password reset.');
                        if (this.changes !== 1) return rollback('Password reset session is no longer valid.');
                        db.run('COMMIT', (commitErr) => {
                            if (commitErr) return rollback('Password reset could not be finalized.');
                            passwordResetTokens.delete(resetToken);
                            invalidateUserSessions(tokenRecord.userId);
                            releaseLock();
                            res.json({ success: true, message: 'Password reset successfully. You can now return to the login screen.' });
                        });
                    });
                });
            });
        });
    } catch (err) {
        console.error('Password reset failed:', err.message);
        return res.status(500).json({ error: 'Unable to reset the password right now.' });
    }
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
    const token = req.headers['x-auth-token'];
    sessions.delete(token);
    res.json({ success: true });
});

app.get('/api/sports-layout', requireAuth, (req, res) => {
    db.all("SELECT id, name FROM sports", [], (err, sportsList) => {
        if (err) { console.error('Sports layout query failed:', err.message); return res.status(500).json({ error: 'Unable to load the sports and court layout.' }); }
        db.all("SELECT id, sport_id, name FROM courts", [], (err, courtsList) => {
            if (err) { console.error('Courts layout query failed:', err.message); return res.status(500).json({ error: 'Unable to load the sports and court layout.' }); }
            const schema = sportsList.map(sport => ({
                id: sport.id,
                name: sport.name,
                courts: courtsList.filter(c => c.sport_id === sport.id)
            }));
            res.json(schema);
        });
    });
});

// Booking student lookup: uses only the current Student Master Database.
// Historical Search Student / restriction features continue to use historical student records.
app.get('/api/students/lookup', requireAuth, (req, res) => {
    const { roll_number } = req.query;
    if (!roll_number || !roll_number.trim()) return res.status(400).json({ error: 'Roll number is required.' });
    db.get(`SELECT id, name, roll_number, email FROM student_master WHERE UPPER(TRIM(roll_number)) = UPPER(TRIM(?)) LIMIT 1`, [roll_number.trim()], (err, row) => {
        if (err) return res.status(500).json({ error: 'Unable to look up the current Student Master Database.' });
        if (row) return res.json({ found: true, id: row.id, name: row.name, roll_number: row.roll_number, email: normalizeUniversityEmail(row.email || '') || null });
        res.json({ found: false });
    });
});

// NEW API: Dynamic Court Availability (Date + Time + Sport -> only currently-free courts)
// Reuses the exact same clash-detection logic as booking creation.
app.get('/api/courts/available', requireAuth, (req, res) => {
    const { sport_id, date, start_time, end_time } = req.query;
    if (!sport_id || !date || !start_time || !end_time) {
        return res.status(400).json({ error: "sport_id, date, start_time and end_time are all required." });
    }
    db.all(`SELECT id, name FROM courts WHERE sport_id = ?`, [sport_id], (err, courts) => {
        if (err) { console.error('Court availability query failed:', err.message); return res.status(500).json({ error: 'Unable to check court availability.' }); }
        if (courts.length === 0) return res.json({ courts: [] });

        const clashQuery = `SELECT id FROM bookings WHERE court_id = ? AND booking_date = ? AND status = 'active' AND ((start_time < ? AND end_time > ?) OR (start_time < ? AND end_time > ?) OR (start_time >= ? AND end_time <= ?))`;
        const checks = courts.map(court => new Promise((resolve) => {
            db.get(clashQuery, [court.id, date, end_time, start_time, end_time, start_time, start_time, end_time], (clashErr, row) => {
                resolve({ court, clashed: !!row });
            });
        }));

        Promise.all(checks).then(results => {
            const available = results.filter(r => !r.clashed).map(r => r.court);
            res.json({ courts: available });
        });
    });
});

// NEW API: Get current active blacklist restrictions for a student
app.get('/api/blacklist/status', requireAuth, (req, res) => {
    const { roll_number } = req.query;
    if (!roll_number || !roll_number.trim()) return res.status(400).json({ error: "Roll number is required." });
    const nowStr = formatISTDateTime(getISTNow());
    db.all(`SELECT * FROM blacklist WHERE UPPER(roll_number) = UPPER(?) AND status = 'active' AND end_datetime > ? ORDER BY end_datetime ASC`, [roll_number.trim(), nowStr], (err, rows) => {
        if (err) { console.error('Blacklist status query failed:', err.message); return res.status(500).json({ error: 'Unable to load booking restrictions.' }); }
        res.json({ restrictions: rows || [] });
    });
});

// NEW API: Apply a blacklist to a student for one or more sports
app.post('/api/blacklist/create', requireAuth, (req, res) => {
    const { roll_number, student_name, sport_ids, duration_value, duration_unit } = req.body;
    const rawReason = typeof req.body.reason === 'string' ? req.body.reason : '';
    const reason = rawReason.trim() || 'No reason provided.';
    const created_by = req.authUser.username;
    const normalizedRoll = (roll_number || '').trim();
    const allowedUnits = ['days', 'months', 'years'];

    if (!normalizedRoll) return res.status(400).json({ error: "Enrollment number is required." });
    if (!Array.isArray(sport_ids) || sport_ids.length === 0) return res.status(400).json({ error: "At least one sport must be selected." });
    if (!duration_value || isNaN(parseInt(duration_value, 10)) || parseInt(duration_value, 10) <= 0) return res.status(400).json({ error: "A valid duration value is required." });
    if (!allowedUnits.includes(duration_unit)) return res.status(400).json({ error: "Duration unit must be Days, Months, or Years." });
    const maxDuration = { days: 3650, months: 120, years: 10 }[duration_unit];
    if (parseInt(duration_value, 10) > maxDuration) return res.status(400).json({ error: `Duration cannot exceed ${maxDuration} ${duration_unit}.` });
    if (!sport_ids.every(id => Number.isInteger(Number(id)) && Number(id) > 0)) return res.status(400).json({ error: "Invalid sport selection." });

    const placeholders = sport_ids.map(() => '?').join(',');
    db.all(`SELECT id, name FROM sports WHERE id IN (${placeholders})`, sport_ids, (err, sportRows) => {
        if (err) { console.error('Blacklist sport lookup failed:', err.message); return res.status(500).json({ error: 'Unable to validate the selected sports.' }); }
        if (sportRows.length === 0) return res.status(400).json({ error: "Selected sports could not be found." });

        const nowIST = getISTNow();
        const startStr = formatISTDateTime(nowIST);
        const endStr = formatISTDateTime(addDurationIST(nowIST, duration_value, duration_unit));

        const stmt = db.prepare(`INSERT INTO blacklist (roll_number, student_name, sport_id, sport_name, start_datetime, end_datetime, duration_value, duration_unit, status, created_by, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`);
        sportRows.forEach(sport => {
            stmt.run([normalizedRoll, student_name || null, sport.id, sport.name, startStr, endStr, parseInt(duration_value, 10), duration_unit, created_by || null, reason]);
        });
        stmt.finalize((finalizeErr) => {
            if (finalizeErr) return res.status(500).json({ error: "Failed to save restriction record." });

            db.run(`INSERT INTO audit_logs (action, admin_name, reason, new_status, ip_address) VALUES ('BLACKLIST_ADDED', ?, ?, 'active', ?)`,
                [created_by || null, `Roll: ${normalizedRoll} | Sports: ${sportRows.map(s => s.name).join(', ')} | Until: ${endStr} | Reason: ${reason}`, req.ip]);

            // Restriction notification goes by email only -- there is no student portal.
            db.get(`SELECT name, email FROM students WHERE UPPER(roll_number) = UPPER(?) ORDER BY id ASC LIMIT 1`, [normalizedRoll], (lookupErr, studentRow) => {
                sendRestrictionEmail({
                    type: 'imposed',
                    studentName: (studentRow && studentRow.name) || student_name || 'Student',
                    rollNumber: normalizedRoll,
                    email: studentRow && studentRow.email,
                    reason,
                    sportsList: sportRows.map(s => s.name).join(', '),
                    whenStr: startStr
                });
            });

            res.json({
                success: true,
                message: `${sportRows.map(s => s.name).join(', ')} restricted until ${formatHumanReadableDate(endStr.split(' ')[0])}.`,
                start_datetime: startStr,
                end_datetime: endStr,
                sports: sportRows.map(s => s.name)
            });
        });
    });
});

// NEW API: Remove an active blacklist (one or more sports at once) for a student
app.post('/api/blacklist/remove', requireAuth, (req, res) => {
    const { roll_number, sport_ids } = req.body;
    const removed_by = req.authUser.username;
    const normalizedRoll = (roll_number || '').trim();

    if (!normalizedRoll) return res.status(400).json({ error: "Enrollment number is required." });
    if (!Array.isArray(sport_ids) || sport_ids.length === 0) return res.status(400).json({ error: "No sports specified for removal." });

    const placeholders = sport_ids.map(() => '?').join(',');
    db.all(`SELECT sport_name FROM blacklist WHERE UPPER(roll_number) = UPPER(?) AND sport_id IN (${placeholders}) AND status = 'active'`, [normalizedRoll, ...sport_ids], (lookupErr, activeRows) => {
        const removedSportNames = (activeRows || []).map(r => r.sport_name);
        db.run(`UPDATE blacklist SET status = 'removed', removed_by = ?, removed_at = CURRENT_TIMESTAMP WHERE UPPER(roll_number) = UPPER(?) AND sport_id IN (${placeholders}) AND status = 'active'`,
            [removed_by || null, normalizedRoll, ...sport_ids], function(err) {
                if (err) return res.status(500).json({ error: "Failed to remove restriction." });

                db.run(`INSERT INTO audit_logs (action, admin_name, reason, ip_address) VALUES ('BLACKLIST_REMOVED', ?, ?, ?)`, [removed_by || null, `Roll: ${normalizedRoll} | Sport IDs: ${sport_ids.join(', ')}`, req.ip]);

                if (this.changes > 0) {
                    db.get(`SELECT name, email FROM students WHERE UPPER(roll_number) = UPPER(?) ORDER BY id ASC LIMIT 1`, [normalizedRoll], (studentErr, studentRow) => {
                        sendRestrictionEmail({
                            type: 'removed',
                            studentName: (studentRow && studentRow.name) || 'Student',
                            rollNumber: normalizedRoll,
                            email: studentRow && studentRow.email,
                            reason: '',
                            sportsList: removedSportNames.join(', ') || 'the selected sport(s)',
                            whenStr: formatISTDateTime(getISTNow())
                        });
                    });
                }

                res.json({ success: true, message: "Restriction removed successfully.", updated: this.changes });
            });
    });
});

// Existing Student Booking Engine
app.post('/api/bookings/create', requireAuth, (req, res) => {
    const { court_id, booking_date, start_time, end_time } = req.body;
    const admin_name = req.authUser.username;
    const primary = validateEnrollmentNumber(req.body.roll_number || req.body.enrollment_number);
    const bookingError = validateBookingDetails({ court_id, booking_date, start_time, end_time });
    if (primary.error) return res.status(400).json({ error: primary.error });
    if (bookingError) return res.status(400).json({ error: bookingError });

    const submittedParticipants = Array.isArray(req.body.additional_players) ? req.body.additional_players : [];
    if (submittedParticipants.length > 20) return res.status(400).json({ error: 'No more than 20 additional players can be added to one booking.' });
    const participants = [];
    const seenRolls = new Set([primary.roll_number.toUpperCase()]);
    for (const rawParticipant of submittedParticipants) {
        const participant = validateEnrollmentNumber(rawParticipant && (rawParticipant.roll_number || rawParticipant.enrollment_number));
        if (participant.error) return res.status(400).json({ error: `Additional player: ${participant.error}` });
        const key = participant.roll_number.toUpperCase();
        if (seenRolls.has(key)) return res.status(400).json({ error: 'The primary student or an additional player was added more than once.' });
        seenRolls.add(key);
        participants.push(participant);
    }

    // Resolve the sport for the requested court first -- needed for both the
    // one-booking-per-sport-per-day rule and the blacklist check below.
    db.get(`SELECT c.id as court_id, c.name as court_name, s.id as sport_id, s.name as sport_name FROM courts c JOIN sports s ON c.sport_id = s.id WHERE c.id = ?`, [court_id], (courtErr, courtInfo) => {
        if (courtErr) return res.status(500).json({ error: "Database error while resolving court/sport information." });
        if (!courtInfo) return res.status(400).json({ error: "Selected court could not be found." });

        const proceedToClashCheck = () => {
            const token = "TKN-" + crypto.randomBytes(5).toString("hex").toUpperCase();
            // A transaction makes student registration, booking creation, and
            // all participant links all-or-nothing. runExclusive() ensures this
            // request's transaction fully finishes before the next one starts.
            runExclusive((releaseLock) => {
            db.run('BEGIN IMMEDIATE TRANSACTION', (beginErr) => {
                if (beginErr) { releaseLock(); return res.status(503).json({ error: 'The booking system is busy. Please try again.' }); }
                const rollback = (message, status = 500) => db.run('ROLLBACK', () => { releaseLock(); res.status(status).json({ error: message }); });
                // Authoritative party-wide schedule validation runs inside the
                // serialized BEGIN IMMEDIATE transaction. This closes the race window
                // where two simultaneous requests could both pass a pre-check before
                // either booking was committed.
                const allPeople = [primary, ...participants];
                const nowStr = formatISTDateTime(getISTNow());
                const findPerson = (rollNumber) => {
                    const match = allPeople.find(p => p.roll_number.toUpperCase() === (rollNumber || '').toUpperCase());
                    return match ? match.roll_number : rollNumber;
                };

                Promise.all([
                    findBlacklistedParticipant(allPeople, courtInfo.sport_id, nowStr),
                    findTimeConflictParticipant(allPeople, booking_date, start_time, end_time)
                ]).then(([blacklisted, timeConflict]) => {
                    if (blacklisted) {
                        return rollback(`Booking Restricted: ${findPerson(blacklisted.roll_number)} is currently restricted from booking ${courtInfo.sport_name} until ${formatHumanReadableDate(blacklisted.end_datetime.split(' ')[0])}.`, 400);
                    }
                    if (timeConflict) {
                        return rollback(`Schedule Conflict: ${findPerson(timeConflict.roll)} already has another active booking that overlaps this time slot on ${formatHumanReadableDate(booking_date)}.`, 400);
                    }

                // Maintains ONE canonical student record per enrollment number.
                // Existing records are reused; their stored name/email remain authoritative.
                const findOrCreateStudent = (student, callback) => {
                    db.get(`SELECT id, roll_number, name, email FROM student_master WHERE UPPER(TRIM(roll_number)) = UPPER(TRIM(?)) LIMIT 1`, [student.roll_number], (masterErr, masterStudent) => {
                        if (masterErr) return callback(masterErr);
                        if (!masterStudent) return callback(new Error('MASTER_NOT_FOUND'));

                        db.all(`SELECT id, roll_number FROM students WHERE UPPER(roll_number) = UPPER(?) ORDER BY id ASC`, [masterStudent.roll_number], (studentErr, rows) => {
                            if (studentErr) return callback(studentErr);
                            if (rows.length > 1) return callback(new Error('DUPLICATE_ROLL'));
                            if (rows.length === 1) {
                                return callback(null, {
                                    id: rows[0].id,
                                    roll_number: masterStudent.roll_number,
                                    name: masterStudent.name,
                                    email: normalizeUniversityEmail(masterStudent.email || '') || null
                                });
                            }
                            db.run(`INSERT INTO students (roll_number, name, email) VALUES (?, ?, ?)`, [masterStudent.roll_number, masterStudent.name, masterStudent.email], function(insertErr) {
                                if (insertErr) return callback(insertErr);
                                callback(null, { id: this.lastID, roll_number: masterStudent.roll_number, name: masterStudent.name, email: masterStudent.email });
                            });
                        });
                    });
                };
                findOrCreateStudent(primary, (primaryErr, primaryStudent) => {
                    if (primaryErr) return rollback(primaryErr.message === 'MASTER_NOT_FOUND' ? 'Student not found in the current Student Master Database. Please contact the administrator.' : (primaryErr.message === 'DUPLICATE_ROLL' ? 'Duplicate legacy records exist for this primary enrollment number. Resolve them in the database before booking.' : 'Failed to save the primary student.'), 400);

                    // AUTHORITATIVE PRIMARY-ONLY DAILY SPORT RESTRICTION.
                    // This runs inside BEGIN IMMEDIATE after the canonical primary
                    // student has been resolved, so additional-player records are
                    // never considered and a rejected booking creates no partial
                    // participant links or confirmation emails.
                    findPrimarySameSportSameDayBooking(
                        primaryStudent.id,
                        primaryStudent.roll_number,
                        courtInfo.sport_id,
                        booking_date
                    ).then((existingPrimaryBooking) => {
                        if (existingPrimaryBooking) {
                            return rollback(
                                `Booking Limit Exceeded: ${primaryStudent.roll_number} already has a primary ${courtInfo.sport_name} booking on ${formatHumanReadableDate(booking_date)}.`,
                                400
                            );
                        }

                    const insertBooking = `INSERT INTO bookings (token, student_name, roll_number, primary_student_id, court_id, booking_date, start_time, end_time, status, booking_type, admin_name)
                        SELECT ?, ?, ?, ?, ?, ?, ?, ?, 'active', 'student', ? WHERE NOT EXISTS (
                          SELECT 1 FROM bookings WHERE court_id = ? AND booking_date = ? AND status = 'active' AND start_time < ? AND end_time > ?)`;
                    db.run(insertBooking, [token, primaryStudent.name, primaryStudent.roll_number, primaryStudent.id, court_id, booking_date, start_time, end_time, admin_name, court_id, booking_date, end_time, start_time], function(bookingErr) {
                        if (bookingErr) return rollback('Failed to allocate court slot in the database.');
                        if (!this.changes) return rollback('Slot No Longer Available. Please select another available court.', 409);
                        const bookingId = this.lastID;
                        const savedParticipants = [];
                        let index = 0;
                        const addNextParticipant = () => {
                            if (index === participants.length) return db.run('COMMIT', async (commitErr) => {
                                if (commitErr) return rollback('Booking could not be finalized.');
                                releaseLock();
                                await sendBookingConfirmationEmail({
                                    studentName: primaryStudent.name,
                                    rollNumber: primaryStudent.roll_number,
                                    email: primaryStudent.email,
                                    sport: courtInfo.sport_name,
                                    court: courtInfo.court_name,
                                    bookingDate: booking_date,
                                    startTime: start_time,
                                    endTime: end_time,
                                    token
                                });
                                await Promise.all(savedParticipants.map(p => sendAdditionalParticipantEmail({
                                    studentName: p.name,
                                    rollNumber: p.roll_number,
                                    email: p.email,
                                    primaryName: primaryStudent.name,
                                    sport: courtInfo.sport_name,
                                    court: courtInfo.court_name,
                                    bookingDate: booking_date,
                                    startTime: start_time,
                                    endTime: end_time
                                })));
                                res.json({ success: true, token, participant_count: participants.length, message: 'Slot successfully booked.' });
                            });
                            const participant = participants[index++];
                            findOrCreateStudent(participant, (participantErr, participantStudent) => {
                                if (participantErr) return rollback(participantErr.message === 'MASTER_NOT_FOUND' ? `Additional player ${participant.roll_number} is not present in the current Student Master Database. Please contact the administrator.` : (participantErr.message === 'DUPLICATE_ROLL' ? `Duplicate legacy records exist for ${participant.roll_number}. Resolve them in the database before booking.` : `Failed to save an additional player.`), 400);
                                db.run(`INSERT INTO booking_participants (booking_id, student_id, role) VALUES (?, ?, 'additional')`, [bookingId, participantStudent.id], (linkErr) => {
                                    if (linkErr) return rollback('Failed to associate an additional player with this booking.');
                                    savedParticipants.push(participantStudent);
                                    addNextParticipant();
                                });
                            });
                        };
                        addNextParticipant();
                    });
                    }).catch(() => rollback('Database error while checking the primary booking limit.'));
                });
                }).catch(() => rollback('Database error during party schedule validation.'));
            });
            });
        };

        proceedToClashCheck();
    });
});

// UPGRADED API: Cancel Booking with Logging & Reasons
app.post('/api/bookings/cancel', requireAuth, (req, res) => {
    const bookingId = Number(req.body.booking_id);
    const finalCanceller = req.authUser.username;
    const finalReason = typeof req.body.cancellation_reason === 'string' ? req.body.cancellation_reason.trim() : '';

    if (!Number.isInteger(bookingId) || bookingId <= 0) return res.status(400).json({ error: 'A valid booking is required.' });
    if (!finalReason) return res.status(400).json({ error: 'Cancellation reason is mandatory.' });
    if (finalReason.length > 1000) return res.status(400).json({ error: 'Cancellation reason is too long.' });

    db.get(`SELECT b.*, c.name AS court_name, s.name AS sport_name,
        COALESCE(pst.name, b.student_name) AS primary_name,
        COALESCE(pst.roll_number, b.roll_number) AS primary_roll_number,
        pst.email AS primary_email
        FROM bookings b
        LEFT JOIN courts c ON b.court_id = c.id
        LEFT JOIN sports s ON c.sport_id = s.id
        LEFT JOIN students pst ON pst.id = b.primary_student_id
        WHERE b.id = ?`, [bookingId], (err, booking) => {
        if (err) return res.status(500).json({ error: 'Unable to load booking.' });
        if (!booking) return res.status(404).json({ error: 'Booking not found.' });
        if (booking.status !== 'active') return res.status(409).json({ error: `This booking is already ${booking.status || 'not active'}.` });

        db.all(`SELECT st.name, st.roll_number, st.email
            FROM booking_participants bp JOIN students st ON st.id = bp.student_id
            WHERE bp.booking_id = ? ORDER BY bp.id ASC`, [bookingId], (playersErr, players) => {
            if (playersErr) return res.status(500).json({ error: 'Unable to load booking participants.' });

            db.run(`UPDATE bookings SET status = 'cancelled', cancelled_by = ?, cancelled_at = ?, cancellation_reason = ?
                WHERE id = ? AND status = 'active'`, [finalCanceller, formatISTDateTime(getISTNow()), finalReason, bookingId], function(updateErr) {
                if (updateErr) return res.status(500).json({ error: 'Cancellation DB failure.' });
                if (this.changes !== 1) return res.status(409).json({ error: 'The booking was already changed by another request.' });

                db.run(`INSERT INTO audit_logs
                    (action, admin_name, booking_id, reason, old_status, new_status, ip_address)
                    VALUES ('CANCEL_BOOKING', ?, ?, ?, 'active', 'cancelled', ?)`,
                    [finalCanceller, bookingId, finalReason, req.ip], (auditErr) => {
                        if (auditErr) console.error('Cancellation audit logging failed:', auditErr.message);

                        const recipients = [];
                        if (booking.primary_email) recipients.push({
                            name: booking.primary_name || 'Student',
                            roll: booking.primary_roll_number || booking.roll_number || 'Unknown',
                            email: booking.primary_email
                        });
                        (players || []).forEach(p => recipients.push({
                            name: p.name || 'Student', roll: p.roll_number || 'Unknown', email: p.email
                        }));

                        Promise.all(recipients.map(p => sendBookingCancellationEmail({
                            studentName: p.name, rollNumber: p.roll, email: p.email,
                            sport: booking.sport_name || 'Sports Facility',
                            court: booking.court_name || 'Allocated Court',
                            bookingDate: booking.booking_date, startTime: booking.start_time,
                            endTime: booking.end_time, token: booking.token,
                            reason: finalReason, cancelledBy: finalCanceller
                        }))).catch(emailErr => console.error('Cancellation notification failure:', emailErr.message));

                        res.json({ success: true, message: 'Booking cancelled successfully.' });
                    });
            });
        });
    });
});

// NEW API: Admin Bulk Slot Booking Engine (Corrected with Detailed Conflict Parsing)
app.post('/api/admin/bookings/bulk', requireAdmin, (req, res) => {
    const { court_ids, start_date, end_date, start_time, end_time, days, reason, skip_conflicts } = req.body;
    const admin_name = req.authUser.username;

    if (!Array.isArray(court_ids) || court_ids.length === 0) return res.status(400).json({ error: "At least one court must be selected." });
    if (!court_ids.every(id => Number.isInteger(Number(id)) && Number(id) > 0)) return res.status(400).json({ error: "Invalid court selection." });
    if (!Array.isArray(days) || days.length === 0) return res.status(400).json({ error: "At least one day of the week must be selected." });
    if (!DATE_PATTERN.test(start_date || '') || !DATE_PATTERN.test(end_date || '') || !TIME_PATTERN.test(start_time || '') || !TIME_PATTERN.test(end_time || '')) return res.status(400).json({ error: "Enter valid start/end dates and times." });
    if (end_date < start_date) return res.status(400).json({ error: "End date must not be before start date." });
    if (end_time <= start_time) return res.status(400).json({ error: "End time must be later than start time." });
    const istToday = formatISTDateOnly(getISTNow());
    if (start_date < istToday) return res.status(400).json({ error: "Bulk bookings cannot begin in the past (IST)." });

    let targetSlots = [];
    let curr = parseYMDLocal(start_date);
    let end = parseYMDLocal(end_date);
    
    // Generate dates based on selected days
    while (curr <= end) {
        let dayName = curr.toLocaleDateString('en-US', { weekday: 'long' });
        if (days.includes(dayName)) {
            const y = curr.getFullYear();
            const m = String(curr.getMonth() + 1).padStart(2, '0');
            const d = String(curr.getDate()).padStart(2, '0');
            let dateStr = `${y}-${m}-${d}`;
            
            court_ids.forEach(court_id => {
                targetSlots.push({ date: dateStr, court_id });
            });
        }
        curr.setDate(curr.getDate() + 1);
    }

    if(targetSlots.length === 0) return res.status(400).json({ error: "No matching dates found for selected days." });
    if(targetSlots.length > 5000) return res.status(400).json({ error: "This bulk booking would create too many slots (maximum 5000). Please use a shorter date range or fewer courts." });

    // Detailed Conflict Check Engine
    const conflictChecks = targetSlots.map(slot => new Promise((resolve) => {
        const query = `
            SELECT b.booking_type, b.student_name, b.roll_number, b.reason, b.booking_date, b.start_time, b.end_time,
                   c.name as court_name, s.name as sport_name
            FROM bookings b 
            JOIN courts c ON b.court_id = c.id 
            JOIN sports s ON c.sport_id = s.id 
            WHERE b.court_id = ? AND b.booking_date = ? AND b.status = 'active' 
            AND ((b.start_time < ? AND b.end_time > ?) OR (b.start_time < ? AND b.end_time > ?) OR (b.start_time >= ? AND b.end_time <= ?))
        `;
        
        db.get(query, [slot.court_id, slot.date, end_time, start_time, end_time, start_time, start_time, end_time], (err, row) => {
            if (row) {
                // Attach the full clash row details to be sent to the frontend modal
                resolve({ ...slot, conflict: true, details: row });
            } else {
                resolve({ ...slot, conflict: false });
            }
        });
    }));

    Promise.all(conflictChecks).then(results => {
        // Map out just the detailed rows to send to the UI
        const conflicts = results.filter(r => r.conflict).map(r => r.details);
        
        // If conflicts exist and the admin didn't explicitly check the skip box, throw 409
        if (conflicts.length > 0 && !skip_conflicts) {
            return res.status(409).json({ error: 'Conflicts detected', conflicts: conflicts });
        }

        const validSlots = results.filter(r => !r.conflict);
        if (validSlots.length === 0) return res.status(400).json({ error: "No valid slots available to book." });

        const bulkGroupId = crypto.randomUUID();

        const insertPromises = validSlots.map(slot => new Promise((resolve) => {
            const token = "BLK-" + crypto.randomBytes(5).toString("hex").toUpperCase();
            const insertSql = `
                INSERT INTO bookings (token, court_id, booking_date, start_time, end_time, status, booking_type, reason, admin_name, bulk_group_id)
                SELECT ?, ?, ?, ?, ?, 'active', 'bulk', ?, ?, ?
                WHERE NOT EXISTS (
                    SELECT 1 FROM bookings
                    WHERE court_id = ? AND booking_date = ? AND status = 'active'
                    AND ((start_time < ? AND end_time > ?) OR (start_time < ? AND end_time > ?) OR (start_time >= ? AND end_time <= ?))
                )`;
            db.run(insertSql, [
                token, slot.court_id, slot.date, start_time, end_time, reason, admin_name, bulkGroupId,
                slot.court_id, slot.date, end_time, start_time, end_time, start_time, start_time, end_time
            ], function(insertErr) {
                resolve(!insertErr && this.changes > 0);
            });
        }));

        Promise.all(insertPromises).then(results => {
            const bookedCount = results.filter(Boolean).length;

            db.run(`INSERT INTO audit_logs (action, admin_name, bulk_group_id, reason, new_status, ip_address) VALUES ('BULK_BOOK_CREATED', ?, ?, ?, ?, ?)`,
                [admin_name, bulkGroupId, reason, `Generated ${bookedCount} slots`, req.ip]);

            if (bookedCount === 0) {
                return res.status(400).json({ error: "No slots could be reserved - all target slots were taken just before booking completed." });
            }
            const message = bookedCount === validSlots.length
                ? `Successfully reserved ${bookedCount} slots for University Events.`
                : `Reserved ${bookedCount} of ${validSlots.length} slots - the rest were taken by another booking just before this completed.`;
            res.json({ success: true, message });
        });
    });
});

// NEW API: Bulk Cancellation Target
app.post('/api/admin/bookings/bulk/cancel', requireAdmin, (req, res) => {
    const { bulk_group_id } = req.body;
    const admin_name = req.authUser.username;
    db.run(`UPDATE bookings SET status = 'cancelled', cancelled_by = ?, cancelled_at = ?, cancellation_reason = 'Bulk Event Cancelled' WHERE bulk_group_id = ? AND status = 'active'`, [admin_name, formatISTDateTime(getISTNow()), bulk_group_id], function(err) {
        if (err) return res.status(500).json({ error: "Failed to cancel bulk group." });
        db.run(`INSERT INTO audit_logs (action, admin_name, bulk_group_id, reason, ip_address) VALUES ('BULK_CANCEL', ?, ?, ?, ?)`, [admin_name, bulk_group_id, `Cancelled Group: ${bulk_group_id}`, req.ip]);
        res.json({ success: true, message: "Entire bulk event has been cancelled and slots released." });
    });
});

app.get('/api/bookings/active', requireAuth, (req, res) => {
    const now = getISTNow();
    const today = formatISTDateOnly(now);
    const nowTime = formatISTDateTime(now).slice(11, 16);

    db.all(`SELECT b.*, c.name as court_name, s.name as sport_name,
        COALESCE(pst.name, b.student_name) AS display_student_name,
        COALESCE(pst.roll_number, b.roll_number) AS display_roll_number,
        (SELECT COUNT(*) FROM booking_participants bp WHERE bp.booking_id = b.id) AS additional_player_count,
        COALESCE((SELECT GROUP_CONCAT(st.name || ' (' || st.roll_number || ')', ', ')
            FROM booking_participants bp JOIN students st ON st.id = bp.student_id
            WHERE bp.booking_id = b.id), '') AS additional_players
        FROM bookings b JOIN courts c ON b.court_id = c.id
        JOIN sports s ON c.sport_id = s.id
        LEFT JOIN students pst ON pst.id = b.primary_student_id
        WHERE b.status = 'active'
        ORDER BY b.booking_date ASC, b.start_time ASC, b.id ASC`, [], (err, rows) => {
        if (err) { console.error('Active bookings query failed:', err.message); return res.status(500).json({ error: 'Unable to load active bookings.' }); }

        const bookings = (rows || []).map(row => {
            const isToday = row.booking_date === today;
            const isFuture = row.booking_date > today || (isToday && row.start_time > nowTime);
            const isCurrentlyActive = isToday && row.start_time <= nowTime && row.end_time > nowTime;
            const isOver = row.booking_date < today || (isToday && row.end_time <= nowTime);
            return {
                ...row,
                runtime_status: isCurrentlyActive ? 'active' : (isFuture ? 'future' : 'over'),
                is_currently_active: isCurrentlyActive,
                is_future: isFuture,
                is_over: isOver
            };
        });

        res.json({ now_ist: formatISTDateTime(now), bookings });
    });
});

app.get('/api/bookings/history', requireAuth, (req, res) => {
    db.all(`SELECT b.*, c.name as court_name, s.name as sport_name,
        COALESCE(pst.name, b.student_name) AS display_student_name, COALESCE(pst.roll_number, b.roll_number) AS display_roll_number,
        (SELECT COUNT(*) FROM booking_participants bp WHERE bp.booking_id = b.id) AS additional_player_count,
        COALESCE((SELECT GROUP_CONCAT(st.name || ' (' || st.roll_number || ')', ', ') FROM booking_participants bp JOIN students st ON st.id = bp.student_id WHERE bp.booking_id = b.id), '') AS additional_players
        FROM bookings b JOIN courts c ON b.court_id = c.id JOIN sports s ON c.sport_id = s.id LEFT JOIN students pst ON pst.id = b.primary_student_id ORDER BY b.id DESC`, [], (err, rows) => {
        if (err) { console.error('Booking history query failed:', err.message); return res.status(500).json({ error: 'Unable to load booking history.' }); }
        res.json(rows);
    });
});

// ============================================================================
// STUDENT MASTER DATABASE — CURRENT LOOKUP/REGISTRY ONLY
// Historical booking/student tables are deliberately not touched by these routes.
// ============================================================================
function parseCsvContent(csvText) {
    if (typeof csvText !== 'string') throw new Error('CSV content is required.');
    const text = csvText.replace(/^\uFEFF/, '');
    const rows = [];
    let row = [];
    let field = '';
    let inQuotes = false;
    let i = 0;

    while (i < text.length) {
        const ch = text[i];
        if (inQuotes) {
            if (ch === '"') {
                if (text[i + 1] === '"') {
                    field += '"';
                    i += 2;
                    continue;
                }
                inQuotes = false;
                i += 1;
                continue;
            }
            field += ch;
            i += 1;
            continue;
        }
        if (ch === '"' && field.length === 0) {
            inQuotes = true;
            i += 1;
            continue;
        }
        if (ch === ',') {
            row.push(field);
            field = '';
            i += 1;
            continue;
        }
        if (ch === '\n' || ch === '\r') {
            row.push(field);
            field = '';
            if (row.some(value => String(value).trim() !== '')) rows.push(row);
            row = [];
            if (ch === '\r' && text[i + 1] === '\n') i += 2;
            else i += 1;
            continue;
        }
        field += ch;
        i += 1;
    }
    if (inQuotes) throw new Error('Malformed CSV: an opening quote was not closed.');
    if (field.length || row.length) {
        row.push(field);
        if (row.some(value => String(value).trim() !== '')) rows.push(row);
    }
    return rows;
}

function normalizeCsvHeader(value) {
    return String(value || '').trim().replace(/\s+/g, ' ').toLowerCase();
}

app.get('/api/admin/student-master/status', requireAdmin, (req, res) => {
    db.get(`SELECT COUNT(*) AS count FROM student_master`, [], (err, row) => {
        if (err) return res.status(500).json({ error: 'Unable to load Student Master Database status.' });
        res.json({ count: row ? Number(row.count) : 0 });
    });
});

app.post('/api/admin/student-master/import-csv', requireAdmin, async (req, res) => {
    const filename = typeof req.body.filename === 'string' ? req.body.filename.trim() : '';
    const csvText = typeof req.body.content === 'string' ? req.body.content : '';
    if (!filename || !/\.csv$/i.test(filename)) return res.status(400).json({ error: 'Please upload a CSV file.' });
    if (!csvText) return res.status(400).json({ error: 'The uploaded CSV file is empty.' });
    if (Buffer.byteLength(csvText, 'utf8') > 5 * 1024 * 1024) return res.status(413).json({ error: 'CSV file is too large. Maximum supported size is 5 MB.' });

    let rows;
    try {
        rows = parseCsvContent(csvText);
    } catch (err) {
        return res.status(400).json({ error: err.message || 'Malformed CSV file.' });
    }
    if (!rows.length) return res.status(400).json({ error: 'The CSV file contains no data rows.' });

    const headers = rows[0].map(normalizeCsvHeader);
    const requiredHeaders = ['email id', 'enrollment no', 'student name'];
    const headerSet = new Set(headers);
    if (headers.length !== requiredHeaders.length || requiredHeaders.some(h => !headerSet.has(h)) || headerSet.size !== requiredHeaders.length) {
        return res.status(400).json({ error: 'Invalid CSV headers. Required headers are exactly: Email ID, Enrollment No, Student Name.' });
    }
    const emailIndex = headers.indexOf('email id');
    const rollIndex = headers.indexOf('enrollment no');
    const nameIndex = headers.indexOf('student name');

    const summary = {
        total_rows: Math.max(0, rows.length - 1),
        successfully_imported: 0,
        newly_added: 0,
        existing_records_detected: 0,
        updated: 0,
        duplicate_rows: 0,
        invalid_rows: 0,
        missing_fields: 0,
        invalid_email_addresses: 0,
        errors: []
    };
    const seenRolls = new Set();
    const validRows = [];

    rows.slice(1).forEach((rawRow, index) => {
        const csvRowNumber = index + 2;
        const email = normalizeUniversityEmail(String(rawRow[emailIndex] ?? '').trim());
        const roll_number = cleanStudentInput(String(rawRow[rollIndex] ?? ''));
        const name = cleanStudentInput(String(rawRow[nameIndex] ?? ''));
        const rowErrors = [];
        if (!email || !roll_number || !name) rowErrors.push('Missing required field(s).');
        if (roll_number && !ROLL_NUMBER_PATTERN.test(roll_number)) rowErrors.push('Invalid Enrollment No.');
        if (name && name.length > 100) rowErrors.push('Student Name exceeds 100 characters.');
        if (email && (!EMAIL_PATTERN.test(email) || email.length > 150)) rowErrors.push('Invalid Email ID.');
        const rollKey = roll_number.toUpperCase();
        if (rollKey && seenRolls.has(rollKey)) rowErrors.push('Duplicate Enrollment No. within this CSV.');
        if (rollKey) seenRolls.add(rollKey);

        if (rowErrors.length) {
            summary.invalid_rows += 1;
            if (rowErrors.some(e => e.startsWith('Missing'))) summary.missing_fields += 1;
            if (rowErrors.some(e => e === 'Invalid Email ID.')) summary.invalid_email_addresses += 1;
            if (rowErrors.some(e => e.includes('Duplicate Enrollment'))) summary.duplicate_rows += 1;
            if (summary.errors.length < 100) summary.errors.push({ row: csvRowNumber, enrollment_no: roll_number || null, errors: rowErrors });
            return;
        }
        validRows.push({ roll_number, name, email });
    });

    try {
        await runExclusive((releaseLock) => {
            db.run('BEGIN IMMEDIATE TRANSACTION', async (beginErr) => {
                if (beginErr) { releaseLock(); return res.status(503).json({ error: 'The Student Master Database is busy. Please try again.' }); }
                try {
                    for (const student of validRows) {
                        const existingRows = await allDb(`SELECT id, name, email FROM student_master WHERE UPPER(TRIM(roll_number)) = UPPER(TRIM(?)) LIMIT 1`, [student.roll_number]);
                        if (!existingRows.length) {
                            await runDb(`INSERT INTO student_master (roll_number, name, email) VALUES (?, ?, ?)`, [student.roll_number, student.name, student.email]);
                            summary.newly_added += 1;
                            summary.successfully_imported += 1;
                        } else {
                            summary.existing_records_detected += 1;
                            const existing = existingRows[0];
                            if (String(existing.name || '') !== student.name || String(existing.email || '').toLowerCase() !== student.email.toLowerCase()) {
                                await runDb(`UPDATE student_master SET roll_number = ?, name = ?, email = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, [student.roll_number, student.name, student.email, existing.id]);
                                summary.updated += 1;
                            }
                            summary.successfully_imported += 1;
                        }
                    }
                    await runDb(`INSERT INTO audit_logs (action, admin_name, reason, new_status, ip_address) VALUES ('STUDENT_MASTER_IMPORTED', ?, ?, 'completed', ?)`, [req.authUser.username, `Imported ${summary.successfully_imported} valid row(s) from ${filename}; ${summary.newly_added} added, ${summary.updated} updated, ${summary.invalid_rows} invalid.`, req.ip]);
                    await runDb('COMMIT');
                    releaseLock();
                    res.json({ success: true, filename, summary });
                } catch (err) {
                    await runDb('ROLLBACK').catch(() => {});
                    releaseLock();
                    console.error('Student Master CSV import failed:', err.message);
                    res.status(500).json({ error: 'Student Master Database import failed. No partial import was committed.' });
                }
            });
        });
    } catch (err) {
        console.error('Student Master import queue failure:', err.message);
        return res.status(500).json({ error: 'Student Master Database import failed.' });
    }
});

app.delete('/api/admin/student-master/purge', requireAdmin, async (req, res) => {
    if (req.body.confirmation !== 'PURGE STUDENT MASTER DATABASE') {
        return res.status(400).json({ error: 'Strong confirmation is required before purging the Student Master Database.' });
    }
    try {
        await runExclusive((releaseLock) => {
            db.run('BEGIN IMMEDIATE TRANSACTION', async (beginErr) => {
                if (beginErr) { releaseLock(); return res.status(503).json({ error: 'The Student Master Database is busy. Please try again.' }); }
                try {
                    const beforeRows = await allDb(`SELECT COUNT(*) AS count FROM student_master`);
                    const removedCount = beforeRows.length ? Number(beforeRows[0].count) : 0;
                    await runDb(`DELETE FROM student_master`);
                    await runDb(`INSERT INTO audit_logs (action, admin_name, reason, new_status, ip_address) VALUES ('STUDENT_MASTER_PURGED', ?, ?, 'completed', ?)`, [req.authUser.username, `Purged ${removedCount} current Student Master Database record(s). Historical bookings and transactional records were not deleted.`, req.ip]);
                    await runDb('COMMIT');
                    releaseLock();
                    res.json({ success: true, removed_count: removedCount, message: 'Student Master Database purged. Historical bookings and transactional records were preserved.' });
                } catch (err) {
                    await runDb('ROLLBACK').catch(() => {});
                    releaseLock();
                    console.error('Student Master purge failed:', err.message);
                    res.status(500).json({ error: 'Student Master Database purge failed. No partial change was committed.' });
                }
            });
        });
    } catch (err) {
        console.error('Student Master purge queue failure:', err.message);
        return res.status(500).json({ error: 'Student Master Database purge failed.' });
    }
});

app.post('/api/admin/sports/add', requireAdmin, (req, res) => {
    const name = (req.body.name || '').trim();
    if (!name) return res.status(400).json({ error: "Sport name is required." });
    db.run("INSERT INTO sports (name) VALUES (?)", [name], function(err) {
        if (err) return res.status(400).json({ error: "Sport profile category mapping duplication detected." });
        res.json({ success: true, id: this.lastID });
    });
});

app.post('/api/admin/courts/add', requireAdmin, (req, res) => {
    const { sport_id } = req.body;
    const court_name = (req.body.court_name || '').trim();
    if (!sport_id) return res.status(400).json({ error: "A sport must be selected." });
    if (!court_name) return res.status(400).json({ error: "Court name is required." });
    db.run("INSERT INTO courts (sport_id, name) VALUES (?, ?)", [sport_id, court_name], function(err) {
        if (err) { console.error('Court creation failed:', err.message); return res.status(500).json({ error: 'Unable to add the court.' }); }
        res.json({ success: true, id: this.lastID });
    });
});

app.delete('/api/admin/courts/remove/:id', requireAdmin, (req, res) => {
    const courtId = Number(req.params.id);
    if (!Number.isInteger(courtId) || courtId <= 0) return res.status(400).json({ error: 'Invalid court.' });
    db.get(`SELECT COUNT(*) AS count FROM bookings WHERE court_id = ?`, [courtId], (countErr, row) => {
        if (countErr) return res.status(500).json({ error: 'Unable to validate the court.' });
        if (row.count > 0) return res.status(409).json({ error: 'This court has booking history and cannot be removed.' });
        db.run(`DELETE FROM courts WHERE id = ?`, [courtId], function(err) {
            if (err) return res.status(500).json({ error: "Failed to remove the court from database." });
            if (!this.changes) return res.status(404).json({ error: 'Court not found.' });
            res.json({ success: true, message: "Court asset successfully removed." });
        });
    });
});

app.post('/api/admin/users/create', requireAdmin, (req, res) => {
    const username = (req.body.username || '').trim();
    const { password, role } = req.body;
    const email = normalizeUniversityEmail(req.body.email || '');
    if (!username) return res.status(400).json({ error: "Username is required." });
    const passwordError = validatePasswordValue(password);
    if (passwordError) return res.status(400).json({ error: passwordError });
    if (!['admin', 'helpdesk'].includes(role)) return res.status(400).json({ error: "Role must be either 'admin' or 'helpdesk'." });
    if (!email) return res.status(400).json({ error: 'Email ID is required.' });
    if (!EMAIL_PATTERN.test(email) || email.length > 150) return res.status(400).json({ error: 'Enter a valid email address.' });
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);
    db.run("INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)", [username, hash, role, email || null], function(err) {
        if (err) return res.status(400).json({ error: "Username profile collision found inside system core." });
        res.json({ success: true });
    });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const users = await allDb(`SELECT id, username, email, role FROM users ORDER BY CASE role WHEN 'admin' THEN 0 ELSE 1 END, LOWER(username)`);
        res.json({ users });
    } catch (err) {
        console.error('Account list failed:', err.message);
        res.status(500).json({ error: 'Unable to load account list.' });
    }
});

app.post('/api/admin/users/delete/request', requireAdmin, async (req, res) => {
    const targetUserId = Number(req.body.user_id);
    if (!Number.isInteger(targetUserId) || targetUserId <= 0) return res.status(400).json({ error: 'Select a valid account.' });

    try {
        const target = await allDb(`SELECT id, username, email, role FROM users WHERE id = ? LIMIT 1`, [targetUserId]).then(rows => rows[0] || null);
        if (!target) return res.status(404).json({ error: 'The selected account no longer exists.' });
        if (!target.email || !EMAIL_PATTERN.test(String(target.email).trim())) return res.status(400).json({ error: 'The selected account does not have a valid registered email address.' });

        if (target.role === 'admin') {
            const adminCount = await allDb(`SELECT COUNT(*) AS count FROM users WHERE role = 'admin'`).then(rows => Number(rows[0]?.count || 0));
            if (adminCount <= 1) return res.status(400).json({ error: 'The last remaining Admin account cannot be deleted.' });
        }

        const recent = await allDb(`SELECT id, requested_at, expires_at FROM account_deletion_otps WHERE target_user_id = ? AND requester_user_id = ? AND used_at IS NULL ORDER BY id DESC LIMIT 1`, [target.id, req.authUser.userId]).then(rows => rows[0] || null);
        if (recent?.requested_at) {
            const requestedMs = parseStoredTimestamp(recent.requested_at);
            if (Number.isFinite(requestedMs) && Date.now() - requestedMs < FORGOT_COOLDOWN_MS) {
                const expiresMs = parseStoredTimestamp(recent.expires_at);
                const deleteToken = crypto.randomBytes(32).toString('hex');
                accountDeletionTokens.set(deleteToken, { otpId: recent.id, targetUserId: target.id, requesterUserId: req.authUser.userId, expires: Number.isFinite(expiresMs) ? expiresMs : Date.now() + FORGOT_OTP_TTL_MS });
                return res.json({ success: true, delete_token: deleteToken, username: target.username, email: String(target.email).trim().toLowerCase(), otp_expires_at: new Date(Number.isFinite(expiresMs) ? expiresMs : Date.now() + FORGOT_OTP_TTL_MS).toISOString(), resend_available_at: new Date(requestedMs + FORGOT_COOLDOWN_MS).toISOString() });
            }
        }

        const otp = String(crypto.randomInt(100000, 1000000));
        const now = new Date();
        const expires = new Date(now.getTime() + FORGOT_OTP_TTL_MS);
        const email = String(target.email).trim().toLowerCase();
        await runDb(`UPDATE account_deletion_otps SET used_at = COALESCE(used_at, CURRENT_TIMESTAMP) WHERE target_user_id = ? AND used_at IS NULL`, [target.id]);
        const result = await runDb(`INSERT INTO account_deletion_otps (target_user_id, requester_user_id, email, otp_hash, requested_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`, [target.id, req.authUser.userId, email, hashResetOtp(otp), now.toISOString(), expires.toISOString()]);
        const sent = await dispatchEmail({
            to: email,
            subject: 'Sports Facility Account Deletion OTP',
            text: `An account deletion was requested for username: ${target.username}.\n\nOTP: ${otp}\n\nThis OTP expires in 2 minutes and can be used only once. If you did not expect this request, contact your Sports Facility administrator immediately.\n\nRegards,\nUniversity Sports Facility`
        });
        if (!sent) console.error(`Account deletion OTP email delivery failed for record ${result.lastID}.`);
        const deleteToken = crypto.randomBytes(32).toString('hex');
        accountDeletionTokens.set(deleteToken, { otpId: result.lastID, targetUserId: target.id, requesterUserId: req.authUser.userId, expires: expires.getTime() });
        res.json({ success: true, delete_token: deleteToken, username: target.username, email, otp_expires_at: expires.toISOString(), resend_available_at: new Date(now.getTime() + FORGOT_COOLDOWN_MS).toISOString() });
    } catch (err) {
        console.error('Account deletion OTP request failed:', err.message);
        res.status(500).json({ error: 'Unable to start account deletion right now.' });
    }
});

app.post('/api/admin/users/delete/verify', requireAdmin, async (req, res) => {
    const deleteToken = typeof req.body.delete_token === 'string' ? req.body.delete_token.trim() : '';
    const otp = typeof req.body.otp === 'string' ? req.body.otp.trim() : '';
    if (!deleteToken || !/^\d{6}$/.test(otp)) return res.status(400).json({ error: 'Enter the 6-digit OTP.' });
    const tokenRecord = accountDeletionTokens.get(deleteToken);
    if (!tokenRecord || tokenRecord.expires <= Date.now() || Number(tokenRecord.requesterUserId) !== Number(req.authUser.userId)) {
        accountDeletionTokens.delete(deleteToken);
        return res.status(400).json({ error: 'Account deletion session has expired. Please request a new OTP.' });
    }

    try {
        const row = await allDb(`SELECT id, target_user_id, requester_user_id, otp_hash, expires_at, attempts, used_at FROM account_deletion_otps WHERE id = ? LIMIT 1`, [tokenRecord.otpId]).then(rows => rows[0] || null);
        if (!row || row.used_at || Number(row.target_user_id) !== Number(tokenRecord.targetUserId) || Number(row.requester_user_id) !== Number(req.authUser.userId)) return res.status(400).json({ error: 'Invalid account deletion session.' });
        const expiresMs = parseStoredTimestamp(row.expires_at);
        if (!Number.isFinite(expiresMs) || expiresMs <= Date.now()) return res.status(400).json({ error: 'OTP expired. Please request a new OTP.' });
        if (Number(row.attempts || 0) >= 5) return res.status(429).json({ error: 'Too many OTP attempts. Please request a new OTP.' });
        const suppliedHash = hashResetOtp(otp);
        const expected = Buffer.from(String(row.otp_hash), 'hex');
        const actual = Buffer.from(suppliedHash, 'hex');
        const valid = expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
        if (!valid) {
            await runDb(`UPDATE account_deletion_otps SET attempts = attempts + 1 WHERE id = ?`, [row.id]);
            return res.status(400).json({ error: 'Invalid OTP.' });
        }

        let selfDeleted = false;
        await runExclusive((releaseLock) => {
            db.run('BEGIN IMMEDIATE TRANSACTION', (beginErr) => {
                if (beginErr) { releaseLock(); return res.status(503).json({ error: 'The account service is busy. Please try again.' }); }
                const rollback = (message) => db.run('ROLLBACK', () => { releaseLock(); res.status(500).json({ error: message }); });
                db.get(`SELECT id, username, role FROM users WHERE id = ? LIMIT 1`, [tokenRecord.targetUserId], (targetErr, target) => {
                    if (targetErr) return rollback('Unable to verify the selected account.');
                    if (!target) return db.run('ROLLBACK', () => { releaseLock(); accountDeletionTokens.delete(deleteToken); res.status(404).json({ error: 'The selected account no longer exists.' }); });
                    db.get(`SELECT COUNT(*) AS count FROM users WHERE role = 'admin'`, [], (countErr, countRow) => {
                        if (countErr) return rollback('Unable to verify administrator protection.');
                        if (target.role === 'admin' && Number(countRow.count || 0) <= 1) return db.run('ROLLBACK', () => { releaseLock(); res.status(400).json({ error: 'The last remaining Admin account cannot be deleted.' }); });
                        selfDeleted = Number(target.id) === Number(req.authUser.userId);
                        db.run(`UPDATE account_deletion_otps SET used_at = CURRENT_TIMESTAMP WHERE id = ? AND used_at IS NULL`, [row.id], function(markErr) {
                            if (markErr || this.changes !== 1) return rollback('Account deletion OTP is no longer valid.');
                            db.run(`INSERT INTO audit_logs (action, admin_name, reason, new_status, ip_address) VALUES ('ACCOUNT_DELETED', ?, ?, 'deleted', ?)`, [req.authUser.username, `Deleted account: ${target.username} (${target.role})`, req.ip], (auditErr) => {
                                if (auditErr) console.error('Account deletion audit logging failed:', auditErr.message);
                                db.run(`DELETE FROM users WHERE id = ?`, [target.id], function(deleteErr) {
                                    if (deleteErr) return rollback('Unable to delete the account.');
                                    if (this.changes !== 1) return rollback('The selected account could not be deleted.');
                                    db.run('COMMIT', (commitErr) => {
                                        if (commitErr) return rollback('Account deletion could not be finalized.');
                                        accountDeletionTokens.delete(deleteToken);
                                        invalidateUserSessions(target.id);
                                        releaseLock();
                                        res.json({ success: true, self_deleted: selfDeleted, message: `Account ${target.username} was deleted successfully.` });
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    } catch (err) {
        console.error('Account deletion failed:', err.message);
        res.status(500).json({ error: 'Unable to delete the account right now.' });
    }
});

app.get('/api/bookings/participation-history', requireAuth, (req, res) => {
    const roll_number = cleanStudentInput(req.query.roll_number);
    if (!ROLL_NUMBER_PATTERN.test(roll_number)) return res.status(400).json({ error: 'Enter a valid roll number.' });
    db.all(`SELECT b.*, c.name AS court_name, sp.name AS sport_name, 'additional' AS participation_role,
        COALESCE(pst.name, b.student_name) AS display_student_name, COALESCE(pst.roll_number, b.roll_number) AS display_roll_number,
        (SELECT COUNT(*) FROM booking_participants pcount WHERE pcount.booking_id = b.id) AS additional_player_count,
        COALESCE((SELECT GROUP_CONCAT(pst2.name || ' (' || pst2.roll_number || ')', ', ') FROM booking_participants bp2 JOIN students pst2 ON pst2.id = bp2.student_id WHERE bp2.booking_id = b.id), '') AS additional_players
        FROM booking_participants bp JOIN students st ON st.id = bp.student_id JOIN bookings b ON b.id = bp.booking_id
        JOIN courts c ON c.id = b.court_id JOIN sports sp ON sp.id = c.sport_id LEFT JOIN students pst ON pst.id = b.primary_student_id
        WHERE UPPER(st.roll_number) = UPPER(?) ORDER BY b.id DESC`, [roll_number], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Unable to load participant booking history.' });
        res.json(rows || []);
    });
});

// Used by the additional-player form. The client never receives authority to
// overwrite a known student's stored name or email.
app.get('/api/students/by-roll', requireAuth, (req, res) => {
    const roll_number = cleanStudentInput(req.query.roll_number);
    if (!ROLL_NUMBER_PATTERN.test(roll_number)) return res.status(400).json({ error: 'Enter a valid roll number.' });
    db.get(`SELECT id, name, roll_number, email FROM student_master WHERE UPPER(TRIM(roll_number)) = UPPER(TRIM(?)) LIMIT 1`, [roll_number], (err, row) => {
        if (err) return res.status(500).json({ error: 'Unable to look up the current Student Master Database.' });
        if (!row) return res.json({ found: false });
        res.json({ found: true, student: { ...row, email: normalizeUniversityEmail(row.email || '') || null } });
    });
});

app.put('/api/students/:id', requireAuth, (req, res) => {
    const studentId = Number(req.params.id);
        const updated = validateStudentDetails(req.body);
    if (!Number.isInteger(studentId) || studentId <= 0) return res.status(400).json({ error: 'Invalid student record.' });
    if (updated.error) return res.status(400).json({ error: updated.error });

    db.get(`SELECT id, roll_number, name, email FROM students WHERE id = ?`, [studentId], (findErr, current) => {
        if (findErr) return res.status(500).json({ error: 'Unable to load the student record.' });
        if (!current) return res.status(404).json({ error: 'Student record not found.' });
        db.get(`SELECT id FROM students WHERE (UPPER(roll_number) = UPPER(?) OR LOWER(email) = LOWER(?)) AND id != ? LIMIT 1`, [updated.roll_number, updated.email, studentId], (duplicateErr, duplicate) => {
            if (duplicateErr) return res.status(500).json({ error: 'Unable to validate student details.' });
            if (duplicate) return res.status(409).json({ error: 'The new enrollment number or email already belongs to another student.' });
            runExclusive((releaseLock) => {
            db.run('BEGIN IMMEDIATE TRANSACTION', (beginErr) => {
                if (beginErr) { releaseLock(); return res.status(503).json({ error: 'The database is busy. Please try again.' }); }
                const rollback = (message) => db.run('ROLLBACK', () => { releaseLock(); res.status(500).json({ error: message }); });
                db.run(`UPDATE students SET roll_number = ?, name = ?, email = ? WHERE id = ?`, [updated.roll_number, updated.name, updated.email, studentId], (updateErr) => {
                    if (updateErr) return rollback('Student details could not be updated.');
                    // New bookings use primary_student_id. The guarded legacy clause
                    // updates only exact old snapshots, never unrelated bookings.
                    db.run(`UPDATE bookings SET roll_number = ?, student_name = ? WHERE primary_student_id = ? OR (primary_student_id IS NULL AND UPPER(roll_number) = UPPER(?))`, [updated.roll_number, updated.name, studentId, current.roll_number], (bookingErr) => {
                        if (bookingErr) return rollback('Student details could not be synchronized with bookings.');
                        db.run(`INSERT INTO audit_logs (action, admin_name, reason, new_status, ip_address) VALUES ('STUDENT_DETAILS_UPDATED', ?, ?, 'updated', ?)`, [req.authUser.username, `Student ID ${studentId}: ${current.roll_number} / ${current.name} / ${current.email || 'no email'} -> ${updated.roll_number} / ${updated.name} / ${updated.email}`, req.ip], (auditErr) => {
                            if (auditErr) return rollback('Student update audit could not be saved.');
                            db.run('COMMIT', (commitErr) => {
                                if (commitErr) return rollback('Student details could not be finalized.');
                                releaseLock();
                                res.json({ success: true, student: { id: studentId, ...updated } });
                            });
                        });
                    });
                });
            });
            });
        });
    });
});

// Returns the complete player group for one normal booking. Current student
// records are used so corrected personal details appear everywhere, while the
// booking snapshot remains a safe fallback for legacy bookings.
app.get('/api/bookings/:id/players', requireAuth, (req, res) => {
    const bookingId = Number(req.params.id);
    if (!Number.isInteger(bookingId) || bookingId <= 0) return res.status(400).json({ error: 'Invalid booking.' });
    db.get(`SELECT b.id, b.student_name, b.roll_number, b.primary_student_id,
        st.id AS primary_id, st.name AS current_primary_name, st.roll_number AS current_primary_roll, st.email AS current_primary_email
        FROM bookings b LEFT JOIN students st ON st.id = b.primary_student_id WHERE b.id = ?`, [bookingId], (bookingErr, booking) => {
        if (bookingErr) return res.status(500).json({ error: 'Unable to load booking players.' });
        if (!booking) return res.status(404).json({ error: 'Booking not found.' });
        const primary = {
            id: booking.primary_id || null,
            name: booking.current_primary_name || booking.student_name || 'Unknown',
            roll_number: booking.current_primary_roll || booking.roll_number || 'Unknown',
            email: booking.current_primary_email || null,
            role: 'primary'
        };
        db.all(`SELECT st.id, st.name, st.roll_number, st.email, 'additional' AS role
            FROM booking_participants bp JOIN students st ON st.id = bp.student_id
            WHERE bp.booking_id = ? ORDER BY bp.id ASC`, [bookingId], (playersErr, additional_players) => {
            if (playersErr) return res.status(500).json({ error: 'Unable to load booking players.' });
            res.json({ primary, additional_players: additional_players || [], total_players: 1 + (additional_players || []).length });
        });
    });
});

// ============================================================================
// SEARCH STUDENT -- full profile by Enrollment Number.
// Enrollment Number (roll_number) is the sole search key (section 9). Returns
// the student's profile, complete booking history with role (Primary Booker
// vs Additional Player) and the other participants on each booking, and the
// full restriction status/history using "Restricted"/"Restriction" wording
// rather than "blacklist" in the response shape.
// ============================================================================
app.get('/api/students/full-profile', requireAuth, (req, res) => {
    const roll_number = cleanStudentInput(req.query.roll_number);
    if (!ROLL_NUMBER_PATTERN.test(roll_number)) return res.status(400).json({ error: 'Enter a valid enrollment number.' });

    db.get(`SELECT id, name, roll_number, email FROM students WHERE UPPER(roll_number) = UPPER(?) ORDER BY id ASC LIMIT 1`, [roll_number], (studentErr, student) => {
        if (studentErr) return res.status(500).json({ error: 'Unable to load the student record.' });
        if (!student) return res.status(404).json({ error: 'No student found with that enrollment number.' });

        const primaryBookingsQuery = `SELECT b.*, 'primary' AS role, c.name AS court_name, sp.name AS sport_name,
            COALESCE((SELECT GROUP_CONCAT(st.name || ' (' || st.roll_number || ')', ', ') FROM booking_participants bp JOIN students st ON st.id = bp.student_id WHERE bp.booking_id = b.id), '') AS additional_players
            FROM bookings b JOIN courts c ON c.id = b.court_id JOIN sports sp ON sp.id = c.sport_id
            WHERE b.primary_student_id = ? ORDER BY b.id DESC`;
        const additionalBookingsQuery = `SELECT b.*, 'additional' AS role, c.name AS court_name, sp.name AS sport_name,
            COALESCE(pst.name, b.student_name) AS primary_booker_name,
            COALESCE(pst.roll_number, b.roll_number) AS primary_booker_roll,
            pst.email AS primary_booker_email,
            COALESCE((SELECT GROUP_CONCAT(st.name || ' (' || st.roll_number || ')', ', ') FROM booking_participants bp2 JOIN students st ON st.id = bp2.student_id WHERE bp2.booking_id = b.id AND st.id != ?), '') AS additional_players
            FROM booking_participants bp JOIN bookings b ON b.id = bp.booking_id JOIN courts c ON c.id = b.court_id JOIN sports sp ON sp.id = c.sport_id
            LEFT JOIN students pst ON pst.id = b.primary_student_id
            WHERE bp.student_id = ? ORDER BY b.id DESC`;

        db.all(primaryBookingsQuery, [student.id], (primaryErr, primaryBookings) => {
            if (primaryErr) return res.status(500).json({ error: 'Unable to load booking history.' });
            db.all(additionalBookingsQuery, [student.id, student.id], (additionalErr, additionalBookings) => {
                if (additionalErr) return res.status(500).json({ error: 'Unable to load booking history.' });

                const bookingHistory = [...primaryBookings, ...additionalBookings].sort((a, b) => b.id - a.id);
                const bookingIds = bookingHistory.map(b => b.id);
                const loadParticipants = (callback) => {
                    if (!bookingIds.length) return callback(null, {});
                    const placeholders = bookingIds.map(() => '?').join(',');
                    db.all(`SELECT bp.booking_id, st.id, st.name, st.roll_number, st.email, 'additional' AS role
                        FROM booking_participants bp JOIN students st ON st.id = bp.student_id
                        WHERE bp.booking_id IN (${placeholders}) ORDER BY bp.id ASC`, bookingIds, (participantErr, participantRows) => {
                        if (participantErr) return callback(participantErr);
                        const byBooking = {};
                        (participantRows || []).forEach(p => {
                            if (!byBooking[p.booking_id]) byBooking[p.booking_id] = [];
                            byBooking[p.booking_id].push({
                                id: p.id,
                                name: p.name,
                                roll_number: p.roll_number,
                                email: p.email || null,
                                role: p.role
                            });
                        });
                        callback(null, byBooking);
                    });
                };

                loadParticipants((participantErr, participantsByBooking) => {
                    if (participantErr) return res.status(500).json({ error: 'Unable to load participant details.' });
                    const enrichedBookingHistory = bookingHistory.map(b => ({
                        ...b,
                        additional_player_details: participantsByBooking[b.id] || []
                    }));

                    db.all(`SELECT sport_id, sport_name, status, start_datetime, end_datetime, reason, created_by, created_at, removed_by, removed_at
                        FROM blacklist WHERE UPPER(roll_number) = UPPER(?) ORDER BY created_at DESC`, [roll_number], (restrictionErr, restrictionRows) => {
                        if (restrictionErr) return res.status(500).json({ error: 'Unable to load restriction history.' });
                        const nowStr = formatISTDateTime(getISTNow());
                        res.json({
                            student: {
                                id: student.id,
                                name: student.name,
                                roll_number: student.roll_number,
                                email: normalizeUniversityEmail(student.email || '') || null
                            },
                            booking_history: enrichedBookingHistory,
                            restricted_list: {
                                currently_restricted: (restrictionRows || []).some(r => r.status === 'active' && r.end_datetime > nowStr),
                                active_restrictions: (restrictionRows || []).filter(r => r.status === 'active' && r.end_datetime > nowStr),
                                restriction_history: restrictionRows || []
                            }
                        });
                    });
                });
            });
        });
    });
});

// ============================================================================
// DATE-RANGE SPORTS BOOKING REPORT - EXCEL DOWNLOAD
//
// One genuine .xlsx workbook is generated in memory. Each configured sport
// represented in the selected range receives its own worksheet, and every
// booking is represented by exactly one row.
// ============================================================================

function formatReportDateForExcel(ymd) {
    if (!DATE_PATTERN.test(String(ymd || ''))) return String(ymd || '');
    const [year, month, day] = ymd.split('-').map(Number);
    const months = ['January','February','March','April','May','June','July','August','September','October','November','December'];
    return `${String(day).padStart(2, '0')} ${months[month - 1]} ${year}`;
}

function getReportRuntimeStatus(booking, now) {
    if (String(booking.status || '').toLowerCase() === 'cancelled') return 'Terminated';
    const today = formatISTDateOnly(now);
    const nowTime = formatISTDateTime(now).slice(11, 16);
    if (booking.booking_date < today || (booking.booking_date === today && booking.end_time <= nowTime)) return 'Over';
    if (booking.booking_date > today || (booking.booking_date === today && booking.start_time > nowTime)) return 'Future';
    return 'Active';
}

function makeUniqueSheetName(workbook, rawName) {
    let base = String(rawName || 'Sport').replace(/[\\\/\?\*\[\]\:]/g, '').trim() || 'Sport';
    base = base.substring(0, 31);
    let name = base;
    let counter = 1;
    while (workbook.SheetNames.includes(name)) {
        const suffix = `_${counter++}`;
        name = `${base.substring(0, 31 - suffix.length)}${suffix}`;
    }
    return name;
}

function buildDateRangeReportExcel(fromDate, toDate, sportGroups, generatedAt) {
    const workbook = XLSX.utils.book_new();
    const headers = [
        'Reservation No.',
        'Booking ID',
        'Token / Reference',
        'Sport',
        'Court',
        'Booking Date',
        'Start Time',
        'End Time',
        'Time Slot',
        'Primary Student Name',
        'Primary Enrollment Number',
        'Primary Email ID',
        'Additional Players',
        'Number of Players',
        'Status',
        'Created By',
        'Terminated By',
        'Terminated At',
        'Termination Reason'
    ];

    sportGroups.forEach((group) => {
        const rows = group.bookings.map((b, index) => {
            const additionalPlayers = (b.additional_players || []).length
                ? b.additional_players.map((player, playerIndex) =>
                    `${playerIndex + 1}. ${player.name || 'Not Available'} (${player.roll_number || 'Not Available'}, ${player.email || 'Not Available'})`
                ).join('\n')
                : 'None';

            return [
                index + 1,
                b.booking_id,
                b.token || `Booking #${b.booking_id}`,
                group.sport_name,
                b.court_name || 'Not Available',
                b.booking_date,
                b.start_time,
                b.end_time,
                `${b.start_time} - ${b.end_time}`,
                b.primary_name || 'Not Available',
                b.primary_roll_number || 'Not Available',
                b.primary_email || 'Not Available',
                additionalPlayers,
                1 + (b.additional_players || []).length,
                b.report_status,
                b.created_by || 'Not Recorded',
                b.cancelled_by || '',
                b.terminated_at || '',
                b.cancellation_reason || ''
            ];
        });

        const worksheet = XLSX.utils.aoa_to_sheet([
            ['University Sports Booking Report'],
            [`Report Period: ${formatReportDateForExcel(fromDate)} – ${formatReportDateForExcel(toDate)}`],
            [`Generated: ${generatedAt} IST`],
            []
        ]);

        XLSX.utils.sheet_add_aoa(worksheet, [headers], { origin: 'A5' });
        if (rows.length) XLSX.utils.sheet_add_aoa(worksheet, rows, { origin: 'A6' });

        const lastRow = 5 + rows.length;
        worksheet['!ref'] = `A1:S${Math.max(lastRow, 5)}`;
        worksheet['!freeze'] = { xSplit: 0, ySplit: 5 };
        worksheet['!autofilter'] = { ref: `A5:S${Math.max(lastRow, 5)}` };
        worksheet['!cols'] = [
            { wch: 16 }, { wch: 12 }, { wch: 24 }, { wch: 18 }, { wch: 24 },
            { wch: 15 }, { wch: 12 }, { wch: 12 }, { wch: 18 }, { wch: 28 },
            { wch: 28 }, { wch: 34 }, { wch: 60 }, { wch: 16 }, { wch: 14 },
            { wch: 22 }, { wch: 22 }, { wch: 24 }, { wch: 45 }
        ];
        worksheet['!rows'] = [
            { hpt: 24 }, { hpt: 20 }, { hpt: 20 }, { hpt: 8 }, { hpt: 30 },
            ...rows.map(() => ({ hpt: 45 }))
        ];

        // Styling is best-effort in SheetJS. The workbook remains a genuine XLSX
        // even when a viewer ignores optional style metadata.
        for (let col = 0; col < headers.length; col++) {
            const cell = XLSX.utils.encode_cell({ r: 4, c: col });
            if (worksheet[cell]) {
                worksheet[cell].s = {
                    font: { bold: true },
                    alignment: { vertical: 'center', wrapText: true }
                };
            }
        }
        ['A1', 'A2', 'A3'].forEach((cell, index) => {
            if (worksheet[cell]) {
                worksheet[cell].s = {
                    font: { bold: index === 0 },
                    alignment: { vertical: 'center', wrapText: true }
                };
            }
        });
        for (let r = 5; r < 5 + rows.length; r++) {
            for (let c = 0; c < headers.length; c++) {
                const cell = XLSX.utils.encode_cell({ r, c });
                if (worksheet[cell]) {
                    worksheet[cell].s = { alignment: { vertical: 'top', wrapText: true } };
                }
            }
        }

        XLSX.utils.book_append_sheet(workbook, worksheet, makeUniqueSheetName(workbook, group.sport_name));
    });

    return XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
}

function uniqueSorted(values) {
    return Array.from(new Set(values.filter(v => v !== null && v !== undefined && String(v).trim() !== '').map(v => String(v).trim()))).sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
}

function buildBulkBookingReportExcel(fromDate, toDate, events, generatedAt) {
    const workbook = XLSX.utils.book_new();
    const headers = [
        'Bulk Booking ID / Event ID',
        'Event / Reservation Name',
        'Purpose / Description / Reason',
        'Sport(s)',
        'Court(s)',
        'Start Date',
        'End Date',
        'Booked Days / Dates',
        'Start Time',
        'End Time',
        'Time Range(s)',
        'Total Slots',
        'Total Codes / Tokens',
        'Active Slot Count',
        'Future Slot Count',
        'Terminated Slot Count',
        'Status',
        'Created By',
        'Created At',
        'Terminated By',
        'Terminated At',
        'Termination Reason(s)'
    ];
    const rows = events.map(event => [
        event.bulk_group_id,
        event.event_name || '',
        event.reason || '',
        event.sports.join('\n'),
        event.courts.join('\n'),
        event.start_date || '',
        event.end_date || '',
        event.booked_dates.join('\n'),
        event.start_times.join('\n'),
        event.end_times.join('\n'),
        event.time_ranges.join('\n'),
        event.total_slots,
        event.total_codes,
        event.active_slot_count,
        event.future_slot_count,
        event.terminated_slot_count,
        event.status,
        event.created_by || '',
        event.created_at || '',
        event.terminated_by.join('\n'),
        event.terminated_at.join('\n'),
        event.termination_reasons.join('\n')
    ]);

    const worksheet = XLSX.utils.aoa_to_sheet([
        ['Bulk Booking Report'],
        [`Selected From Date: ${formatReportDateForExcel(fromDate)}`],
        [`Selected To Date: ${formatReportDateForExcel(toDate)}`],
        [`Generated: ${generatedAt} IST`],
        [],
        headers,
        ...rows
    ]);
    const headerRow = 5; // zero-based worksheet row for Excel row 6
    const firstDataRow = 6; // zero-based worksheet row for Excel row 7
    const lastExcelRow = Math.max(headerRow + 1, firstDataRow + rows.length); // convert zero-based last index to Excel row number
    worksheet['!ref'] = `A1:V${lastExcelRow}`;
    worksheet['!freeze'] = { xSplit: 0, ySplit: headerRow + 1 };
    worksheet['!autofilter'] = { ref: `A${headerRow + 1}:V${lastExcelRow}` };
    worksheet['!cols'] = [
        { wch: 38 }, { wch: 32 }, { wch: 42 }, { wch: 24 }, { wch: 28 }, { wch: 16 },
        { wch: 16 }, { wch: 34 }, { wch: 18 }, { wch: 18 }, { wch: 30 }, { wch: 14 },
        { wch: 18 }, { wch: 18 }, { wch: 18 }, { wch: 20 }, { wch: 22 }, { wch: 22 },
        { wch: 24 }, { wch: 26 }, { wch: 26 }, { wch: 48 }
    ];
    worksheet['!rows'] = [
        { hpt: 24 }, { hpt: 20 }, { hpt: 20 }, { hpt: 20 }, { hpt: 8 }, { hpt: 32 },
        ...rows.map(() => ({ hpt: 60 }))
    ];
    for (let col = 0; col < headers.length; col++) {
        const cell = XLSX.utils.encode_cell({ r: headerRow, c: col });
        if (worksheet[cell]) worksheet[cell].s = { font: { bold: true }, alignment: { vertical: 'center', wrapText: true } };
    }
    ['A1', 'A2', 'A3', 'A4'].forEach((cell, index) => {
        if (worksheet[cell]) worksheet[cell].s = { font: { bold: index === 0 }, alignment: { vertical: 'center', wrapText: true } };
    });
    for (let r = firstDataRow; r < firstDataRow + rows.length; r++) {
        for (let c = 0; c < headers.length; c++) {
            const cell = XLSX.utils.encode_cell({ r, c });
            if (worksheet[cell]) worksheet[cell].s = { alignment: { vertical: 'top', wrapText: true } };
        }
    }
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Bulk Bookings');
    return XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
}

app.get('/api/bookings/daily-report/bulk-download', requireAuth, async (req, res) => {
    const fromDate = typeof req.query.from_date === 'string' ? req.query.from_date.trim() : '';
    const toDate = typeof req.query.to_date === 'string' ? req.query.to_date.trim() : '';
    if (!DATE_PATTERN.test(fromDate) || !DATE_PATTERN.test(toDate)) return res.status(400).json({ error: 'From Date and To Date are required and must be valid dates.' });
    if (fromDate > toDate) return res.status(400).json({ error: 'From Date cannot be later than To Date.' });

    try {
        const groupRows = await allDb(`
            SELECT DISTINCT b.bulk_group_id
            FROM bookings b
            WHERE COALESCE(b.booking_type, 'student') = 'bulk'
              AND b.bulk_group_id IS NOT NULL
              AND TRIM(b.bulk_group_id) <> ''
              AND b.booking_date >= ?
              AND b.booking_date <= ?
            ORDER BY b.bulk_group_id
        `, [fromDate, toDate]);
        const groupIds = groupRows.map(row => row.bulk_group_id).filter(Boolean);
        if (!groupIds.length) return res.status(404).json({ error: 'No bulk bookings found for the selected date range.' });

        const placeholders = groupIds.map(() => '?').join(',');
        const slots = await allDb(`
            SELECT b.id, b.bulk_group_id, b.token, b.booking_date, b.start_time, b.end_time, b.status,
                   b.reason, b.admin_name, b.cancelled_by, b.cancelled_at, b.cancellation_reason,
                   c.name AS court_name, sp.name AS sport_name
            FROM bookings b
            JOIN courts c ON c.id = b.court_id
            JOIN sports sp ON sp.id = c.sport_id
            WHERE COALESCE(b.booking_type, 'student') = 'bulk'
              AND b.bulk_group_id IN (${placeholders})
            ORDER BY b.bulk_group_id, b.booking_date, b.start_time, b.id
        `, groupIds);
        const createdAudits = await allDb(`
            SELECT bulk_group_id, admin_name, date_time, reason
            FROM audit_logs
            WHERE action = 'BULK_BOOK_CREATED'
              AND bulk_group_id IN (${placeholders})
            ORDER BY id ASC
        `, groupIds);
        const groupCancelAudits = await allDb(`
            SELECT bulk_group_id, admin_name, date_time, reason
            FROM audit_logs
            WHERE action = 'BULK_CANCEL'
              AND bulk_group_id IN (${placeholders})
            ORDER BY id ASC
        `, groupIds);
        const slotIds = slots.map(s => s.id);
        const cancellationAudits = slotIds.length ? await allDb(`
            SELECT booking_id, admin_name, date_time, reason
            FROM audit_logs
            WHERE action = 'CANCEL_BOOKING'
              AND booking_id IN (${slotIds.map(() => '?').join(',')})
            ORDER BY id ASC
        `, slotIds) : [];

        const now = getISTNow();
        const createdByGroup = new Map();
        const createdAtGroup = new Map();
        const createdReasonGroup = new Map();
        createdAudits.forEach(a => {
            if (!createdByGroup.has(a.bulk_group_id)) createdByGroup.set(a.bulk_group_id, a.admin_name || '');
            if (!createdAtGroup.has(a.bulk_group_id)) createdAtGroup.set(a.bulk_group_id, a.date_time || '');
            if (!createdReasonGroup.has(a.bulk_group_id)) createdReasonGroup.set(a.bulk_group_id, a.reason || '');
        });
        const groupCancelMap = new Map();
        groupCancelAudits.forEach(a => {
            if (!groupCancelMap.has(a.bulk_group_id)) groupCancelMap.set(a.bulk_group_id, []);
            groupCancelMap.get(a.bulk_group_id).push(a);
        });
        const cancellationAuditMap = new Map();
        cancellationAudits.forEach(a => {
            if (!cancellationAuditMap.has(a.booking_id)) cancellationAuditMap.set(a.booking_id, []);
            cancellationAuditMap.get(a.booking_id).push(a);
        });

        const slotsByGroup = new Map();
        slots.forEach(slot => {
            if (!slotsByGroup.has(slot.bulk_group_id)) slotsByGroup.set(slot.bulk_group_id, []);
            slotsByGroup.get(slot.bulk_group_id).push(slot);
        });

        const events = groupIds.map(groupId => {
            const groupSlots = slotsByGroup.get(groupId) || [];
            if (!groupSlots.length) return null;
            const terminated = groupSlots.filter(s => String(s.status || '').toLowerCase() === 'cancelled');
            const active = groupSlots.filter(s => String(s.status || '').toLowerCase() === 'active');
            let activeSlotCount = 0;
            let futureSlotCount = 0;
            active.forEach(s => {
                const isToday = s.booking_date === formatISTDateOnly(now);
                const isFuture = s.booking_date > formatISTDateOnly(now) || (isToday && s.start_time > formatISTDateTime(now).slice(11, 16));
                if (isFuture) futureSlotCount += 1;
                else if (isToday && s.end_time > formatISTDateTime(now).slice(11, 16)) activeSlotCount += 1;
                else if (s.booking_date < formatISTDateOnly(now) || (isToday && s.end_time <= formatISTDateTime(now).slice(11, 16))) {
                    // Historical active rows are completed/over; they are not counted as active or future.
                }
            });

            let status = 'Future';
            if (terminated.length === groupSlots.length) status = 'Terminated';
            else if (terminated.length > 0) status = 'Partially Terminated';
            else {
                const hasCurrent = active.some(s => s.booking_date === formatISTDateOnly(now) && s.start_time <= formatISTDateTime(now).slice(11, 16) && s.end_time > formatISTDateTime(now).slice(11, 16));
                const hasFuture = active.some(s => s.booking_date > formatISTDateOnly(now) || (s.booking_date === formatISTDateOnly(now) && s.start_time > formatISTDateTime(now).slice(11, 16)));
                if (hasCurrent) status = 'Active';
                else if (hasFuture) status = 'Future';
                else status = 'Completed/Over';
            }

            const reasons = [];
            const terminatedBy = [];
            const terminatedAt = [];
            terminated.forEach(slot => {
                if (slot.cancellation_reason) reasons.push(`${slot.court_name} — ${slot.booking_date} ${slot.start_time}-${slot.end_time}: ${slot.cancellation_reason}`);
                if (slot.cancelled_by) terminatedBy.push(slot.cancelled_by);
                if (slot.cancelled_at) terminatedAt.push(slot.cancelled_at);
                (cancellationAuditMap.get(slot.id) || []).forEach(a => {
                    if (a.admin_name) terminatedBy.push(a.admin_name);
                    if (a.date_time) terminatedAt.push(a.date_time);
                    if (a.reason && !reasons.some(r => r.endsWith(`: ${a.reason}`))) reasons.push(`${slot.court_name} — ${slot.booking_date} ${slot.start_time}-${slot.end_time}: ${a.reason}`);
                });
            });
            (groupCancelMap.get(groupId) || []).forEach(a => {
                if (a.admin_name) terminatedBy.push(a.admin_name);
                if (a.date_time) terminatedAt.push(a.date_time);
                if (a.reason) reasons.push(a.reason);
            });

            return {
                bulk_group_id: groupId,
                event_name: groupSlots.find(s => s.reason)?.reason || createdReasonGroup.get(groupId) || 'Bulk Reservation',
                reason: groupSlots.find(s => s.reason)?.reason || createdReasonGroup.get(groupId) || '',
                sports: uniqueSorted(groupSlots.map(s => s.sport_name)),
                courts: uniqueSorted(groupSlots.map(s => s.court_name)),
                booked_dates: uniqueSorted(groupSlots.map(s => s.booking_date)),
                start_date: uniqueSorted(groupSlots.map(s => s.booking_date))[0] || '',
                end_date: uniqueSorted(groupSlots.map(s => s.booking_date)).slice(-1)[0] || '',
                start_times: uniqueSorted(groupSlots.map(s => s.start_time)),
                end_times: uniqueSorted(groupSlots.map(s => s.end_time)),
                time_ranges: uniqueSorted(groupSlots.map(s => `${s.start_time}-${s.end_time}`)),
                total_slots: groupSlots.length,
                total_codes: uniqueSorted(groupSlots.map(s => s.token)).length,
                active_slot_count: activeSlotCount,
                future_slot_count: futureSlotCount,
                terminated_slot_count: terminated.length,
                status,
                created_by: createdByGroup.get(groupId) || groupSlots.find(s => s.admin_name)?.admin_name || '',
                created_at: createdAtGroup.get(groupId) || '',
                terminated_by: uniqueSorted(terminatedBy),
                terminated_at: uniqueSorted(terminatedAt),
                termination_reasons: uniqueSorted(reasons)
            };
        }).filter(Boolean);

        if (!events.length) return res.status(404).json({ error: 'No bulk bookings found for the selected date range.' });
        const excel = buildBulkBookingReportExcel(fromDate, toDate, events, formatISTDateTime(now));
        const filename = `Bulk_Booking_Report_${fromDate}_to_${toDate}.xlsx`;
        res.set({
            'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'Content-Disposition': `attachment; filename="${filename}"`,
            'Content-Length': String(excel.length),
            'Cache-Control': 'no-store'
        });
        return res.send(excel);
    } catch (err) {
        console.error('Bulk Booking Excel report generation failed:', err);
        return res.status(500).json({ error: 'Unable to generate the Bulk Booking Excel report. Please try again.' });
    }
});

app.get('/api/bookings/daily-report/download', requireAuth, async (req, res) => {
    const fromDate = typeof req.query.from_date === 'string' ? req.query.from_date.trim() : '';
    const toDate = typeof req.query.to_date === 'string' ? req.query.to_date.trim() : '';

    if (!DATE_PATTERN.test(fromDate) || !DATE_PATTERN.test(toDate)) {
        return res.status(400).json({ error: 'From Date and To Date are required and must be valid dates.' });
    }
    if (fromDate > toDate) {
        return res.status(400).json({ error: 'From Date cannot be later than To Date.' });
    }

    try {
        const now = getISTNow();
        const generatedAt = formatISTDateTime(now);
        const bookings = await allDb(`
            SELECT
                b.id,
                b.token,
                b.booking_date,
                b.start_time,
                b.end_time,
                b.status,
                b.admin_name,
                b.cancelled_by,
                b.cancellation_reason,
                c.name AS court_name,
                sp.name AS sport_name,
                COALESCE(pst.name, b.student_name) AS primary_name,
                COALESCE(pst.roll_number, b.roll_number) AS primary_roll_number,
                pst.email AS primary_email,
                (
                    SELECT al.date_time
                    FROM audit_logs al
                    WHERE al.booking_id = b.id
                      AND al.action = 'CANCEL_BOOKING'
                    ORDER BY al.id DESC
                    LIMIT 1
                ) AS terminated_at
            FROM bookings b
            JOIN courts c ON c.id = b.court_id
            JOIN sports sp ON sp.id = c.sport_id
            LEFT JOIN students pst ON pst.id = b.primary_student_id
            WHERE b.booking_date >= ?
              AND b.booking_date <= ?
              AND COALESCE(b.booking_type, 'student') != 'bulk'
              AND (b.bulk_group_id IS NULL OR TRIM(b.bulk_group_id) = '')
            ORDER BY sp.name COLLATE NOCASE ASC, b.booking_date ASC, b.start_time ASC, b.id ASC
        `, [fromDate, toDate]);

        if (!bookings.length) {
            return res.status(404).json({
                error: 'No individual student reservations were found for the selected date range.'
            });
        }

        const bookingIds = bookings.map(b => b.id);
        const placeholders = bookingIds.map(() => '?').join(',');
        const participants = await allDb(`
            SELECT bp.booking_id, st.name, st.roll_number, st.email
            FROM booking_participants bp
            JOIN students st ON st.id = bp.student_id
            WHERE bp.booking_id IN (${placeholders})
            ORDER BY bp.booking_id ASC, bp.id ASC
        `, bookingIds);

        const participantsByBooking = new Map();
        participants.forEach((p) => {
            if (!participantsByBooking.has(p.booking_id)) participantsByBooking.set(p.booking_id, []);
            participantsByBooking.get(p.booking_id).push({
                name: p.name,
                roll_number: p.roll_number,
                email: p.email || null
            });
        });

        const sportsMap = new Map();
        bookings.forEach((b) => {
            if (!sportsMap.has(b.sport_name)) sportsMap.set(b.sport_name, []);
            sportsMap.get(b.sport_name).push({
                booking_id: b.id,
                token: b.token,
                booking_date: b.booking_date,
                start_time: b.start_time,
                end_time: b.end_time,
                court_name: b.court_name,
                primary_name: b.primary_name,
                primary_roll_number: b.primary_roll_number,
                primary_email: b.primary_email,
                additional_players: participantsByBooking.get(b.id) || [],
                report_status: getReportRuntimeStatus(b, now),
                created_by: b.admin_name,
                cancelled_by: b.cancelled_by,
                terminated_at: b.terminated_at,
                cancellation_reason: b.cancellation_reason
            });
        });

        const sportGroups = Array.from(sportsMap.entries()).map(([sport_name, sportBookings]) => ({
            sport_name,
            bookings: sportBookings
        }));

        const excel = buildDateRangeReportExcel(fromDate, toDate, sportGroups, generatedAt);
        const filename = `University_Sports_Booking_Report_${fromDate}_to_${toDate}.xlsx`;

        res.set({
            'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'Content-Disposition': `attachment; filename="${filename}"`,
            'Content-Length': String(excel.length),
            'Cache-Control': 'no-store'
        });
        return res.send(excel);
    } catch (err) {
        console.error('Date-range Excel report generation failed:', err);
        return res.status(500).json({ error: 'Unable to generate the Excel report. Please try again.' });
    }
});

// ============================================================================
// DAILY BOOKING HISTORY / ATTENDANCE TRACKING
// All bookings dated today (IST), grouped by sport rather than one large
// table, each with primary booker and additional player details.
// ============================================================================
app.get('/api/bookings/daily-report', requireAuth, (req, res) => {
    const nowIST = getISTNow();
    const today = formatISTDateOnly(nowIST);
    db.all(`SELECT b.*, c.name AS court_name, sp.id AS sport_id, sp.name AS sport_name,
        COALESCE(pst.name, b.student_name) AS primary_name, COALESCE(pst.roll_number, b.roll_number) AS primary_roll_number,
        pst.email AS primary_email
        FROM bookings b JOIN courts c ON c.id = b.court_id JOIN sports sp ON sp.id = c.sport_id
        LEFT JOIN students pst ON pst.id = b.primary_student_id
        WHERE b.booking_date = ? AND COALESCE(b.booking_type, 'student') != 'bulk' ORDER BY sp.name ASC, b.start_time ASC`, [today], (err, bookings) => {
        if (err) return res.status(500).json({ error: 'Unable to load the daily report.' });
        const bookingIds = bookings.map(b => b.id);
        if (bookingIds.length === 0) return res.json({ date: today, sports: [] });
        const placeholders = bookingIds.map(() => '?').join(',');
        db.all(`SELECT bp.booking_id, st.name, st.roll_number, st.email
            FROM booking_participants bp JOIN students st ON st.id = bp.student_id
            WHERE bp.booking_id IN (${placeholders}) ORDER BY bp.id ASC`, bookingIds, (playersErr, participantRows) => {
            if (playersErr) return res.status(500).json({ error: 'Unable to load the daily report.' });
            const participantsByBooking = {};
            (participantRows || []).forEach(p => {
                if (!participantsByBooking[p.booking_id]) participantsByBooking[p.booking_id] = [];
                participantsByBooking[p.booking_id].push({ name: p.name, roll_number: p.roll_number, email: p.email || null, role: 'additional' });
            });
            const sportsMap = new Map();
            bookings.forEach(b => {
                if (!sportsMap.has(b.sport_name)) sportsMap.set(b.sport_name, []);
                sportsMap.get(b.sport_name).push({
                    booking_id: b.id, token: b.token, court_name: b.court_name, booking_type: b.booking_type,
                    start_time: b.start_time, end_time: b.end_time, status: b.status,
                    runtime_status: getReportRuntimeStatus(b, nowIST).toLowerCase(), reason: b.reason,
                    primary_booker: b.booking_type === 'bulk' ? null : {
                        name: b.primary_name, roll_number: b.primary_roll_number, email: b.primary_email || null, role: 'primary'
                    },
                    additional_players: participantsByBooking[b.id] || []
                });
            });
            res.json({ date: today, sports: Array.from(sportsMap.entries()).map(([sport_name, bookingsForSport]) => ({ sport_name, bookings: bookingsForSport })) });
        });
    });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'API endpoint not found.' }));

// Malformed JSON / oversized bodies previously returned Express's default HTML error page.
app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'Request is too large.' });
    if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed request body.' });
    console.error('Unhandled server error:', err && err.message);
    res.status(500).json({ error: 'Internal server error.' });
});

process.on('unhandledRejection', (reason) => console.error('Unhandled promise rejection:', reason));

app.listen(PORT, () => {
    console.log(`================================================================`);
    console.log("RUNNING: Sports Portal Server listening on port " + PORT);
    console.log("LOCAL HOST LINK: http://localhost:" + PORT);
    console.log(`================================================================`);
});
