/**
 * Unified Express API — All routes consolidated for Vercel serverless deployment
 * Combines Flask auth/attendance routes + Express session/QR routes
 */
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
const path = require('path');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { getDb, initializeDatabase } = require('../lib/db');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// ─── Security Headers (CSP, HSTS, X-Frame-Options) ────────
const INACTIVITY_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

app.use((req, res, next) => {
    // Content Security Policy
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://unpkg.com; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data: blob:; " +
        "connect-src 'self'; " +
        "frame-ancestors 'none'"
    );
    // HTTP Strict Transport Security (1 year, include subdomains)
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');
    // Prevent MIME-type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // Referrer policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    // Permissions policy
    res.setHeader('Permissions-Policy', 'camera=(self), microphone=(), geolocation=()');
    next();
});

// ─── Rate Limiting (API-03, AVAIL-02) ─────────────────────────
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please try again later.' },
});
app.use('/api/', generalLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { error: 'Too many login attempts. Please try again later.' },
});

const attendanceLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: { error: 'Too many attendance attempts. Max 5 per minute.' },
});

// ─── Serve Static Frontend Files ──────────────────────────────
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
app.use(express.static(PUBLIC_DIR));

// Page routes — serve HTML files for /teacher, /student, /admin
app.get('/teacher', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'teacher', 'index.html')));
app.get('/student', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'student', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'admin', 'index.html')));
app.get('/', (req, res) => res.redirect('/teacher'));

// ─── Config ────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'jwt-super-secret-change-in-production';
const QR_HMAC_SECRET = process.env.QR_HMAC_SECRET || 'qr-hmac-shared-secret-between-flask-and-express';
const QR_WINDOW_SECONDS = parseInt(process.env.QR_WINDOW_SECONDS || '15', 10);

// ─── DB Initialization ────────────────────────────────────────
let dbInitialized = false;
async function ensureDb() {
    if (!dbInitialized) {
        await initializeDatabase();
        dbInitialized = true;
    }
    return getDb();
}

// ─── Password Hashing (bcrypt, 12 rounds — CRYPTO-02) ────────
const BCRYPT_ROUNDS = 12;

function hashPassword(password) {
    return bcrypt.hashSync(password, BCRYPT_ROUNDS);
}

function verifyPassword(password, stored) {
    try {
        // bcrypt hashes start with $2
        if (stored.startsWith('$2')) {
            return bcrypt.compareSync(password, stored);
        }
        // Legacy PBKDF2 fallback for pre-existing accounts
        const [saltHex, keyHex] = stored.split(':');
        const salt = Buffer.from(saltHex, 'hex');
        const key = crypto.pbkdf2Sync(password, salt, 260000, 32, 'sha256');
        return key.toString('hex') === keyHex;
    } catch {
        return false;
    }
}

// ─── JWT Middleware (Dual-method: Cookie or Header) ──────────
function verifyToken(req, res, next) {
    // 1. Try Cookie (Secure/HTTP-only)
    let token = req.cookies?.auth_token;

    // 2. Fallback to Authorization Header (Bearer)
    if (!token && req.headers.authorization?.startsWith('Bearer ')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ error: 'Authentication token required' });
    }
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload;

        // ── Inactivity timeout check (30 min) ──
        const lastActive = parseInt(req.cookies?.last_active || '0', 10);
        const now = Date.now();
        if (lastActive && (now - lastActive) > INACTIVITY_TIMEOUT_MS) {
            // Clear cookies and reject
            res.clearCookie('auth_token', { httpOnly: true, sameSite: 'Strict', path: '/' });
            res.clearCookie('last_active', { sameSite: 'Strict', path: '/' });
            return res.status(401).json({ error: 'Session expired due to inactivity' });
        }

        // Refresh the inactivity timer (sliding window)
        res.cookie('last_active', String(now), {
            httpOnly: false,  // readable by client for UI countdown if needed
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: INACTIVITY_TIMEOUT_MS,
            path: '/'
        });

        next();
    } catch (err) {
        // Clear stale/invalid cookies
        res.clearCookie('auth_token', { httpOnly: true, sameSite: 'Strict', path: '/' });
        res.clearCookie('last_active', { sameSite: 'Strict', path: '/' });
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token has expired' });
        }
        return res.status(401).json({ error: 'Invalid token' });
    }
}

function requireRole(...roles) {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Access denied' });
        }
        next();
    };
}

// ─── Input Validation & Sanitization Helpers ────────────────────
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX_RE = /^[0-9a-f]+$/i;

/** Trim and enforce max length; returns null if empty after trim */
function sanitizeString(val, maxLen = 255) {
    if (typeof val !== 'string') return null;
    const trimmed = val.trim();
    if (trimmed.length === 0) return null;
    return trimmed.slice(0, maxLen);
}

function isValidEmail(email) {
    return typeof email === 'string' && EMAIL_RE.test(email) && email.length <= 320;
}

/** Password: min 8 chars, at least 1 uppercase, 1 lowercase, 1 digit */
function isValidPassword(pw) {
    if (typeof pw !== 'string' || pw.length < 8 || pw.length > 128) return false;
    return /[A-Z]/.test(pw) && /[a-z]/.test(pw) && /[0-9]/.test(pw);
}

function isValidUUID(val) {
    return typeof val === 'string' && UUID_RE.test(val);
}

function isValidHex(val, expectedLen) {
    return typeof val === 'string' && HEX_RE.test(val) && val.length === expectedLen;
}

// ─── QR Code Generation ────────────────────────────────────────
function signQRPayload(sessionId, courseId, timestamp, nonce) {
    const message = `${sessionId}|${courseId}|${timestamp}|${nonce}`;
    return crypto.createHmac('sha256', QR_HMAC_SECRET).update(message).digest('hex');
}

async function generateQRCode(sessionId, courseId) {
    const timestamp = Date.now() / 1000;
    const nonce = crypto.randomBytes(32).toString('hex');
    const signature = signQRPayload(sessionId, courseId, timestamp, nonce);

    const payload = { session_id: sessionId, course_id: courseId, timestamp, nonce, signature };

    const qrDataUrl = await QRCode.toDataURL(JSON.stringify(payload), {
        width: 400, margin: 2,
        color: { dark: '#000000', light: '#ffffff' },
        errorCorrectionLevel: 'M',
    });

    return { qrDataUrl, payload };
}

// ═══════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', service: 'qr-attendance-api' });
});

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const db = await ensureDb();
        const { role, password } = req.body;

        // Sanitize all string inputs with length limits
        const university_id = sanitizeString(req.body.university_id, 50);
        const name          = sanitizeString(req.body.name, 100);
        const email         = sanitizeString(req.body.email, 320);
        const department    = sanitizeString(req.body.department, 100);
        const designation   = sanitizeString(req.body.designation, 100) || 'Lecturer';
        const class_batch   = sanitizeString(req.body.class_batch, 50);
        const semester      = sanitizeString(req.body.semester, 20);
        const program       = sanitizeString(req.body.program, 100);

        // Required field checks
        if (!university_id || !name || !email || !password || !role) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        if (!['teacher', 'student'].includes(role)) {
            return res.status(400).json({ error: 'Role must be "teacher" or "student"' });
        }
        if (!isValidEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        if (!isValidPassword(password)) {
            return res.status(400).json({ error: 'Password must be 8-128 characters with at least 1 uppercase, 1 lowercase, and 1 digit' });
        }

        // Check duplicates
        const existing = await db.execute({
            sql: 'SELECT id FROM users WHERE university_id = ? OR email = ?',
            args: [university_id, email],
        });
        if (existing.rows.length > 0) {
            return res.status(409).json({ error: 'University ID or email already registered' });
        }

        const id = uuidv4();
        const profileId = uuidv4();
        const password_hash = hashPassword(password);

        await db.execute({
            sql: `INSERT INTO users (id, university_id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?, ?)`,
            args: [id, university_id, name, email, password_hash, role],
        });

        // Auto-create role-specific profile
        if (role === 'teacher') {
            await db.execute({
                sql: `INSERT INTO teacher_profiles (id, teacher_id, department, designation) VALUES (?, ?, ?, ?)`,
                args: [profileId, id, department, designation],
            });
        } else {
            await db.execute({
                sql: `INSERT INTO student_profiles (id, student_id, class_batch, semester, program) VALUES (?, ?, ?, ?, ?)`,
                args: [profileId, id, class_batch, semester, program],
            });
        }

        res.status(201).json({
            message: 'Registration successful',
            user: { id, university_id, name, email, role },
        });
    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login (rate-limited: 20 attempts per 15 min)
app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
        const db = await ensureDb();
        const university_id = sanitizeString(req.body.university_id, 50);
        const password = req.body.password;

        if (!university_id || !password || typeof password !== 'string') {
            return res.status(400).json({ error: 'University ID and password are required' });
        }

        const result = await db.execute({
            sql: 'SELECT * FROM users WHERE university_id = ?',
            args: [university_id],
        });

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];

        if (!verifyPassword(password, user.password_hash)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { user_id: user.id, university_id: user.university_id, role: user.role },
            JWT_SECRET,
            { expiresIn: '8h' }
        );

        // Set JWT as HTTP-only cookie (not accessible via JS — XSS-safe)
        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: 8 * 60 * 60 * 1000, // 8 hours
            path: '/'
        });

        // Set inactivity tracker cookie
        res.cookie('last_active', String(Date.now()), {
            httpOnly: false,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict',
            maxAge: INACTIVITY_TIMEOUT_MS,
            path: '/'
        });

        res.json({
            message: 'Login successful',
            token, // Return token for fallback localStorage storage
            user: {
                id: user.id, university_id: user.university_id,
                name: user.name, email: user.email, role: user.role,
                device_bound: !!user.device_id,
            },
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Logout — clear HTTP-only auth cookie
app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('auth_token', { httpOnly: true, sameSite: 'Strict', path: '/' });
    res.clearCookie('last_active', { sameSite: 'Strict', path: '/' });
    res.json({ message: 'Logged out successfully' });
});

// Profile
app.get('/api/auth/profile', verifyToken, async (req, res) => {
    try {
        const db = await ensureDb();
        const result = await db.execute({
            sql: 'SELECT id, university_id, name, email, role, device_id, created_at FROM users WHERE id = ?',
            args: [req.user.user_id],
        });
        if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        const u = result.rows[0];
        res.json({ user: { ...u, device_bound: !!u.device_id } });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// ═══════════════════════════════════════════════════════════════
// TEACHER ROUTES
// ═══════════════════════════════════════════════════════════════

// Get teacher's courses
app.get('/api/attendance/teacher/courses', verifyToken, requireRole('teacher'), async (req, res) => {
    try {
        const db = await ensureDb();
        const result = await db.execute({
            sql: `SELECT c.*, u.name as teacher_name FROM courses c
                  JOIN users u ON c.teacher_id = u.id WHERE c.teacher_id = ?`,
            args: [req.user.user_id],
        });
        res.json({ courses: result.rows });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch courses' });
    }
});

// Create course
app.post('/api/attendance/teacher/courses', verifyToken, requireRole('teacher'), async (req, res) => {
    try {
        const db = await ensureDb();
        const code = sanitizeString(req.body.code, 20);
        const name = sanitizeString(req.body.name, 150);
        if (!code || !name) return res.status(400).json({ error: 'Course code and name are required' });
        if (!/^[A-Za-z0-9 _-]{2,20}$/.test(code)) {
            return res.status(400).json({ error: 'Course code must be 2-20 alphanumeric characters' });
        }

        const existing = await db.execute({ sql: 'SELECT id FROM courses WHERE code = ?', args: [code] });
        if (existing.rows.length > 0) return res.status(409).json({ error: 'Course code already exists' });

        const id = uuidv4();
        await db.execute({
            sql: 'INSERT INTO courses (id, code, name, teacher_id) VALUES (?, ?, ?, ?)',
            args: [id, code, name, req.user.user_id],
        });

        res.status(201).json({
            message: 'Course created',
            course: { id, code, name, teacher_id: req.user.user_id, teacher_name: null },
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to create course' });
    }
});

// Enroll student
app.post('/api/attendance/teacher/enroll', verifyToken, requireRole('teacher'), async (req, res) => {
    try {
        const db = await ensureDb();
        const student_university_id = sanitizeString(req.body.student_university_id, 50);
        const course_id = req.body.course_id;
        if (!student_university_id || !course_id) {
            return res.status(400).json({ error: 'student_university_id and course_id are required' });
        }
        if (!isValidUUID(course_id)) {
            return res.status(400).json({ error: 'Invalid course_id format' });
        }

        const course = await db.execute({ sql: 'SELECT * FROM courses WHERE id = ? AND teacher_id = ?', args: [course_id, req.user.user_id] });
        if (course.rows.length === 0) return res.status(404).json({ error: 'Course not found or access denied' });

        const student = await db.execute({
            sql: "SELECT * FROM users WHERE university_id = ? AND role = 'student'",
            args: [student_university_id],
        });
        if (student.rows.length === 0) return res.status(404).json({ error: 'Student not found' });

        const sid = student.rows[0].id;
        const dup = await db.execute({
            sql: 'SELECT id FROM enrollments WHERE student_id = ? AND course_id = ?',
            args: [sid, course_id],
        });
        if (dup.rows.length > 0) return res.status(409).json({ error: 'Student is already enrolled' });

        const id = uuidv4();
        await db.execute({
            sql: 'INSERT INTO enrollments (id, student_id, course_id) VALUES (?, ?, ?)',
            args: [id, sid, course_id],
        });

        res.status(201).json({ message: 'Student enrolled successfully', enrollment: { id, student_id: sid, course_id } });
    } catch (err) {
        res.status(500).json({ error: 'Failed to enroll student' });
    }
});

// Get teacher's sessions
app.get('/api/attendance/teacher/sessions', verifyToken, requireRole('teacher'), async (req, res) => {
    try {
        const db = await ensureDb();
        const result = await db.execute({
            sql: `SELECT s.*, c.code as course_code, c.name as course_name,
                  (SELECT COUNT(*) FROM attendance a WHERE a.session_id = s.id) as attendance_count
                  FROM sessions s JOIN courses c ON s.course_id = c.id
                  WHERE s.teacher_id = ? ORDER BY s.created_at DESC`,
            args: [req.user.user_id],
        });
        res.json({ sessions: result.rows });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch sessions' });
    }
});

// Get session attendance
app.get('/api/attendance/teacher/sessions/:sessionId/attendance', verifyToken, requireRole('teacher'), async (req, res) => {
    try {
        if (!isValidUUID(req.params.sessionId)) return res.status(400).json({ error: 'Invalid session ID format' });
        const db = await ensureDb();
        const session = await db.execute({
            sql: 'SELECT * FROM sessions WHERE id = ? AND teacher_id = ?',
            args: [req.params.sessionId, req.user.user_id],
        });
        if (session.rows.length === 0) return res.status(404).json({ error: 'Session not found' });

        const records = await db.execute({
            sql: `SELECT a.*, u.name as student_name, u.university_id as student_university_id
                  FROM attendance a JOIN users u ON a.student_id = u.id
                  WHERE a.session_id = ?`,
            args: [req.params.sessionId],
        });
        res.json({ session: session.rows[0], attendance: records.rows });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch attendance' });
    }
});

// ═══════════════════════════════════════════════════════════════
// SESSION ROUTES (QR Generation)
// ═══════════════════════════════════════════════════════════════

// Start session
app.post('/api/sessions/start', verifyToken, requireRole('teacher'), async (req, res) => {
    try {
        const db = await ensureDb();
        const { course_id } = req.body;
        if (!course_id) return res.status(400).json({ error: 'course_id is required' });
        if (!isValidUUID(course_id)) return res.status(400).json({ error: 'Invalid course_id format' });

        const id = uuidv4();
        await db.execute({
            sql: 'INSERT INTO sessions (id, course_id, teacher_id) VALUES (?, ?, ?)',
            args: [id, course_id, req.user.user_id],
        });

        const course = await db.execute({ sql: 'SELECT * FROM courses WHERE id = ?', args: [course_id] });
        const qr = await generateQRCode(id, course_id);

        res.status(201).json({
            message: 'Session started — QR code is now active',
            session: {
                id, course_id, teacher_id: req.user.user_id, is_locked: 0,
                course_code: course.rows[0]?.code,
                course_name: course.rows[0]?.name,
            },
            qr: { qrDataUrl: qr.qrDataUrl, payload: qr.payload },
        });
    } catch (err) {
        console.error('Start session error:', err);
        res.status(500).json({ error: 'Failed to start session' });
    }
});

// Stop/lock session
app.post('/api/sessions/stop', verifyToken, requireRole('teacher'), async (req, res) => {
    try {
        const db = await ensureDb();
        const { session_id } = req.body;
        if (!session_id) return res.status(400).json({ error: 'session_id is required' });
        if (!isValidUUID(session_id)) return res.status(400).json({ error: 'Invalid session_id format' });

        const session = await db.execute({
            sql: 'SELECT * FROM sessions WHERE id = ? AND teacher_id = ?',
            args: [session_id, req.user.user_id],
        });
        if (session.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
        if (session.rows[0].is_locked) return res.status(400).json({ error: 'Session is already locked' });

        await db.execute({
            sql: "UPDATE sessions SET is_locked = 1, locked_at = datetime('now') WHERE id = ?",
            args: [session_id],
        });

        const count = await db.execute({
            sql: 'SELECT COUNT(*) as cnt FROM attendance WHERE session_id = ?',
            args: [session_id],
        });

        res.json({
            message: 'Session locked — no more attendance can be marked',
            attendance_count: count.rows[0]?.cnt || 0,
        });
    } catch (err) {
        console.error('Stop session error:', err);
        res.status(500).json({ error: 'Failed to stop session' });
    }
});

// Get current QR for polling (replaces WebSocket)
app.get('/api/sessions/:id/qr', verifyToken, requireRole('teacher'), async (req, res) => {
    try {
        if (!isValidUUID(req.params.id)) return res.status(400).json({ error: 'Invalid session ID format' });
        const db = await ensureDb();
        const session = await db.execute({
            sql: 'SELECT * FROM sessions WHERE id = ? AND teacher_id = ?',
            args: [req.params.id, req.user.user_id],
        });
        if (session.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
        if (session.rows[0].is_locked) return res.status(400).json({ error: 'Session is locked' });

        const course_id = session.rows[0].course_id;
        const qr = await generateQRCode(req.params.id, course_id);

        res.json({ qr: { qrDataUrl: qr.qrDataUrl, payload: qr.payload } });
    } catch (err) {
        console.error('QR fetch error:', err);
        res.status(500).json({ error: 'Failed to generate QR code' });
    }
});

// Get session details
app.get('/api/sessions/:id', verifyToken, async (req, res) => {
    try {
        if (!isValidUUID(req.params.id)) return res.status(400).json({ error: 'Invalid session ID format' });
        const db = await ensureDb();
        const result = await db.execute({
            sql: `SELECT s.*, c.code as course_code, c.name as course_name,
                  (SELECT COUNT(*) FROM attendance a WHERE a.session_id = s.id) as attendance_count
                  FROM sessions s JOIN courses c ON s.course_id = c.id WHERE s.id = ?`,
            args: [req.params.id],
        });
        if (result.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
        res.json({ session: result.rows[0] });
    } catch (err) {
        console.error('Session details error:', err);
        res.status(500).json({ error: 'Failed to fetch session details' });
    }
});

// Delete session (teacher only — must own the session)
app.delete('/api/sessions/:id', verifyToken, requireRole('teacher'), async (req, res) => {
    try {
        if (!isValidUUID(req.params.id)) return res.status(400).json({ error: 'Invalid session ID format' });
        const db = await ensureDb();
        const session = await db.execute({
            sql: 'SELECT * FROM sessions WHERE id = ? AND teacher_id = ?',
            args: [req.params.id, req.user.user_id],
        });
        if (session.rows.length === 0) return res.status(404).json({ error: 'Session not found or access denied' });

        // Delete cascade: nonces → attendance → session
        await db.execute({ sql: 'DELETE FROM used_nonces WHERE session_id = ?', args: [req.params.id] });
        await db.execute({ sql: 'DELETE FROM attendance WHERE session_id = ?', args: [req.params.id] });
        await db.execute({ sql: 'DELETE FROM sessions WHERE id = ?', args: [req.params.id] });

        res.json({ message: 'Session deleted successfully' });
    } catch (err) {
        console.error('Delete session error:', err);
        res.status(500).json({ error: 'Failed to delete session' });
    }
});

// ═══════════════════════════════════════════════════════════════
// STUDENT ROUTES
// ═══════════════════════════════════════════════════════════════

// Get enrolled courses
app.get('/api/attendance/courses', verifyToken, requireRole('student'), async (req, res) => {
    try {
        const db = await ensureDb();
        const result = await db.execute({
            sql: `SELECT c.*, u.name as teacher_name FROM courses c
                  JOIN enrollments e ON c.id = e.course_id
                  JOIN users u ON c.teacher_id = u.id
                  WHERE e.student_id = ?`,
            args: [req.user.user_id],
        });
        res.json({ courses: result.rows });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch courses' });
    }
});

// Get attendance history
app.get('/api/attendance/history', verifyToken, requireRole('student'), async (req, res) => {
    try {
        const db = await ensureDb();
        const result = await db.execute({
            sql: `SELECT a.*, s.started_at as session_started_at, c.code as course_code, c.name as course_name
                  FROM attendance a
                  JOIN sessions s ON a.session_id = s.id
                  JOIN courses c ON s.course_id = c.id
                  WHERE a.student_id = ? ORDER BY a.scanned_at DESC`,
            args: [req.user.user_id],
        });
        res.json({ attendance: result.rows });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch attendance history' });
    }
});

// Mark attendance (THE critical endpoint — 8 security checks, rate-limited: 5/min per student)
app.post('/api/attendance/mark', attendanceLimiter, verifyToken, requireRole('student'), async (req, res) => {
    try {
        const db = await ensureDb();
        const { qr_data } = req.body;
        if (!qr_data || typeof qr_data !== 'object') return res.status(400).json({ error: 'QR data is required' });

        const { session_id, course_id, timestamp, nonce, signature } = qr_data;
        if (!session_id || !course_id || !timestamp || !nonce || !signature) {
            return res.status(400).json({ error: 'Invalid QR code: missing fields' });
        }
        // Validate QR field types and formats
        if (!isValidUUID(session_id) || !isValidUUID(course_id)) {
            return res.status(400).json({ error: 'Invalid QR code: malformed identifiers' });
        }
        if (typeof timestamp !== 'number' || !isFinite(timestamp)) {
            return res.status(400).json({ error: 'Invalid QR code: bad timestamp' });
        }
        if (!isValidHex(nonce, 64) || !isValidHex(signature, 64)) {
            return res.status(400).json({ error: 'Invalid QR code: malformed cryptographic fields' });
        }

        // Step 1: Verify HMAC Signature
        const expectedSig = signQRPayload(session_id, course_id, timestamp, nonce);
        if (!crypto.timingSafeEqual(Buffer.from(expectedSig, 'hex'), Buffer.from(signature, 'hex'))) {
            return res.status(403).json({ error: 'Invalid QR code: signature verification failed' });
        }

        // Step 2: Check Timestamp (time window)
        const now = Date.now() / 1000;
        if (Math.abs(now - parseFloat(timestamp)) > QR_WINDOW_SECONDS) {
            return res.status(410).json({
                error: 'QR code has expired',
                message: `QR codes are valid for ${QR_WINDOW_SECONDS} seconds only`,
            });
        }

        // Step 3: Check Nonce Reuse
        const nonceCheck = await db.execute({ sql: 'SELECT id FROM used_nonces WHERE nonce = ?', args: [nonce] });
        if (nonceCheck.rows.length > 0) {
            return res.status(409).json({ error: 'Replay attack detected', message: 'This QR code has already been used' });
        }

        // Step 4: Check Session Exists & Not Locked
        const session = await db.execute({ sql: 'SELECT * FROM sessions WHERE id = ?', args: [session_id] });
        if (session.rows.length === 0) return res.status(404).json({ error: 'Session not found' });
        if (session.rows[0].is_locked) {
            return res.status(423).json({ error: 'Session is locked', message: 'The teacher has closed this attendance session' });
        }

        // Step 5: Check Student Enrollment
        const enrollment = await db.execute({
            sql: 'SELECT id FROM enrollments WHERE student_id = ? AND course_id = ?',
            args: [req.user.user_id, course_id],
        });
        if (enrollment.rows.length === 0) {
            return res.status(403).json({ error: 'Not enrolled', message: 'You are not enrolled in this course' });
        }

        // Step 6: Check Duplicate Attendance
        const dupAtt = await db.execute({
            sql: 'SELECT id FROM attendance WHERE student_id = ? AND session_id = ?',
            args: [req.user.user_id, session_id],
        });
        if (dupAtt.rows.length > 0) {
            return res.status(409).json({ error: 'Already marked', message: 'Your attendance for this session is already recorded' });
        }

        // Step 7: Device Verification / Binding
        const deviceId = req.headers['x-device-fingerprint'] || 'unknown';
        const userResult = await db.execute({ sql: 'SELECT device_id FROM users WHERE id = ?', args: [req.user.user_id] });
        const currentDevice = userResult.rows[0]?.device_id;
        let deviceMsg = 'Device verified';

        if (!currentDevice) {
            // First scan — bind device
            await db.execute({
                sql: "UPDATE users SET device_id = ?, device_bound_at = datetime('now') WHERE id = ?",
                args: [deviceId, req.user.user_id],
            });
            deviceMsg = 'Device bound successfully (first scan)';
        } else if (currentDevice !== deviceId) {
            return res.status(403).json({
                error: 'Device mismatch',
                message: 'Attendance can only be marked from your registered device',
            });
        }

        // Step 8: Record Attendance & Mark Nonce as Used
        const nonceId = uuidv4();
        const attId = uuidv4();

        await db.execute({ sql: 'INSERT INTO used_nonces (id, nonce, session_id) VALUES (?, ?, ?)', args: [nonceId, nonce, session_id] });
        await db.execute({
            sql: 'INSERT INTO attendance (id, session_id, student_id, device_id, nonce_used) VALUES (?, ?, ?, ?, ?)',
            args: [attId, session_id, req.user.user_id, deviceId, nonce],
        });

        res.status(201).json({
            message: 'Attendance marked successfully',
            device_status: deviceMsg,
        });
    } catch (err) {
        console.error('Mark attendance error:', err);
        res.status(500).json({ error: 'Failed to record attendance' });
    }
});

// ═══════════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════════════

// List all teachers (protected by X-Admin-Key header)
app.get('/api/admin/teachers', async (req, res) => {
    const adminKey = req.headers['x-admin-key'];
    if (adminKey !== 'AZK:epstein') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    try {
        const db = await ensureDb();
        const result = await db.execute({
            sql: "SELECT id, university_id, name, email, created_at FROM users WHERE role = 'teacher' ORDER BY created_at DESC",
            args: [],
        });
        res.json({ teachers: result.rows });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch teachers' });
    }
});

// ═══════════════════════════════════════════════════════════════
// Start server (local dev) or export for Vercel
// ═══════════════════════════════════════════════════════════════
// ─── Global Error Handler (catch-all — never leak internals) ──
app.use((err, req, res, _next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'An unexpected error occurred' });
});

module.exports = app;


if (require.main === module) {
    const PORT = process.env.PORT || 3001;
    app.listen(PORT, () => {
        console.log(`QR Attendance API running on port ${PORT}`);
        ensureDb().then(() => console.log('Database ready'));
    });
}
