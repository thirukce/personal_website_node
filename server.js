require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcryptjs');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const publicPath = path.join(__dirname, 'public');												  
const fs = require('fs');
const util = require('util');
const fsPromises = require('fs').promises;
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const compression = require('compression');
const morgan = require('morgan');
const nodemailer = require('nodemailer');
const cron = require('node-cron');

const app = express();

/**
 * Formats a Date object into a local time string 'YYYY-MM-DDTHH:MM:SS'
 * that is compatible with SQLite's string sorting and is safely parsed as local time by `new Date()`.
 * This avoids UTC conversion and uses the server's local timezone.
 * @param {Date} date The date to format.
 * @returns {string} The formatted date string.
 */
function formatDbDate(date) {
    const year = date.getFullYear();
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const day = date.getDate().toString().padStart(2, '0');
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    const seconds = date.getSeconds().toString().padStart(2, '0');
    return `${year}-${month}-${day}T${hours}:${minutes}:${seconds}`;
}

const PORT = process.env.PORT || 3000;
const BASE_PATH = process.env.BASE_PATH || '';

// Resolve DB_PATH to an absolute path. This makes it robust whether the .env path is relative or absolute.
const rawDbPath = process.env.DB_PATH || 'personal_website.db';
const DB_PATH = path.isAbsolute(rawDbPath) 
    ? rawDbPath 
    : path.join(__dirname, rawDbPath);

// Resolve UPLOAD_DIR to an absolute path.
const rawUploadDir = process.env.UPLOAD_DIR || 'uploads';
const UPLOAD_DIR = path.isAbsolute(rawUploadDir) 
    ? rawUploadDir 
    : path.join(__dirname, rawUploadDir);

const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE, 10) || 5 * 1024 * 1024; // 5MB

const LOGIN_RATE_LIMIT_WINDOW = parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW, 10) || 15 * 60 * 1000; // 15 mins
const LOGIN_RATE_LIMIT_MAX = parseInt(process.env.LOGIN_RATE_LIMIT_MAX, 10) || 5;

const GENERAL_RATE_LIMIT_WINDOW = parseInt(process.env.GENERAL_RATE_LIMIT_WINDOW, 10) || 15 * 60 * 1000; // 15 mins
const GENERAL_RATE_LIMIT_MAX = parseInt(process.env.GENERAL_RATE_LIMIT_MAX, 10) || 100;

const SESSION_MAX_AGE = parseInt(process.env.SESSION_MAX_AGE, 10) || 5 * 60 * 1000; // 5 minutes

// Tell Express to trust the reverse proxy (Apache)
// This is crucial for secure cookies to work correctly behind a proxy.
// '1' means it will trust the first hop from the proxy.
app.set('trust proxy', 1);												   
																	   
														
						  

// Security middleware

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-hashes'"], // Keep this line as is for now
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            connectSrc: ["'self'"]
        }
    }
}));

app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', "script-src 'self' 'unsafe-hashes' 'sha256-QA/FIksfX1sNsodmGrqUEjjFV2RwmHeCgDudLGiBoNM=' 'sha256-ieoeWczDHkReVBsRBqaal5AFMlBtNjMzgwKvLqi/tSU=' 'sha256-cb1s2KXb6Vwrf7gzleZTBAonupdoB+PxWX4XqMsaOCA=' 'sha256-nNIzcrCDgTAbdBswdLX1vTxRHuqvwXKARgmUjSRYEzQ=' 'sha256-an0GuWy3FgNMLNOXAWC0ixNAboyIp4cOn0PeYbPNcV0='");
    next();
});

// CORS configuration
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true
}));

// Compression and logging
app.use(compression());
app.use(morgan('combined'));

// Serve static files from the 'public' directory
app.use(BASE_PATH, express.static(publicPath));												 
									

// Create uploads directory if it doesn't exist
if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Database setup
const db = new sqlite3.Database(DB_PATH);

// Promisify db methods for async/await support
const dbRun = util.promisify(db.run.bind(db));
const dbGet = util.promisify(db.get.bind(db));
const dbAll = util.promisify(db.all.bind(db));

// Initialize database tables
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Add email column to existing users table if it doesn't exist.
    // A proper migration system would be better, but this works for simple cases.
    db.run("ALTER TABLE users ADD COLUMN email TEXT", (err) => {
        if (!err) console.log("Added 'email' column to 'users' table.");
    });

    // Checklists table
    db.run(`CREATE TABLE IF NOT EXISTS checklists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT NOT NULL,
        completed BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Notes table
    db.run(`CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT NOT NULL,
        content TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Files table
    db.run(`CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT NOT NULL,
        original_name TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_size INTEGER,
        mime_type TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Reminders table
    db.run(`CREATE TABLE IF NOT EXISTS reminders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT NOT NULL,
        remind_at DATETIME NOT NULL,
        recurrence TEXT DEFAULT 'none' NOT NULL, -- 'none', 'daily', 'weekly'
        notified BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Add recurrence column to reminders table if it doesn't exist.
    db.run("ALTER TABLE reminders ADD COLUMN recurrence TEXT DEFAULT 'none' NOT NULL", (err) => {
        if (!err) console.log("Added 'recurrence' column to 'reminders' table.");
    });

    // Add new columns for multi-stage notifications
    db.run("ALTER TABLE reminders ADD COLUMN notified_24h BOOLEAN DEFAULT 0", (err) => {
        if (!err) console.log("Added 'notified_24h' column to 'reminders' table.");
    });
    db.run("ALTER TABLE reminders ADD COLUMN notified_3h BOOLEAN DEFAULT 0", (err) => {
        if (!err) console.log("Added 'notified_3h' column to 'reminders' table.");
    });

    // Create default admin user. The password should be set in the .env file.
    // This runs only on the first start if the 'admin' user doesn't exist.
    const adminPassword = process.env.ADMIN_DEFAULT_PASSWORD || 'admin123';
    if (adminPassword === 'admin123' && process.env.NODE_ENV === 'production') {
        console.warn('⚠️ WARNING: Using a fallback admin password in production. Please set ADMIN_DEFAULT_PASSWORD in your .env file for security.');
    }
    const hashedPassword = bcrypt.hashSync(adminPassword, 10);
    db.run(`INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`,
           ['admin', hashedPassword]);
    
    // Set a default email for the admin user if not set
    db.run(`UPDATE users SET email = ? WHERE username = 'admin' AND email IS NULL`, ['admin@example.com']);
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-key-change-in-production',
    resave: false,
    store: new SQLiteStore({
        db: path.basename(DB_PATH),
        dir: path.dirname(DB_PATH),
        table: 'sessions'
    }),
    saveUninitialized: false,
    name: 'sessionId', // Don't use default session name
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        httpOnly: true, // Prevent XSS
        maxAge: SESSION_MAX_AGE, // e.g., 5 minutes
        sameSite: 'strict' // CSRF protection
    }
}));

// Rate limiting for login attempts
const loginLimiter = rateLimit({
    windowMs: LOGIN_RATE_LIMIT_WINDOW,
    max: LOGIN_RATE_LIMIT_MAX,
    message: { error: 'Too many login attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

// General rate limiting
const generalLimiter = rateLimit({
    windowMs: GENERAL_RATE_LIMIT_WINDOW,
    max: GENERAL_RATE_LIMIT_MAX,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

app.use(generalLimiter);

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOAD_DIR);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { 
        fileSize: MAX_FILE_SIZE,
        files: 1 // Only one file at a time
    },
    fileFilter: (req, file, cb) => {
        // Stricter file type validation
        const allowedMimes = [
            'image/jpeg', 'image/jpg', 'image/png', 'image/gif',
            'application/pdf', 'text/plain',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ];
        const allowedExts = /\.(jpeg|jpg|png|gif|pdf|txt|doc|docx)$/i;
        
        if (allowedMimes.includes(file.mimetype) && allowedExts.test(file.originalname)) {
            return cb(null, true);
        } else {
            cb(new Error('File type not allowed. Only images, PDFs, and documents are permitted.'));
        }
    }
});

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.redirect(BASE_PATH + '/login');
    }
};

// Routes
app.get(BASE_PATH + '/', (req, res) => {
    res.render('index', { basePath: BASE_PATH });
});

app.get(BASE_PATH + '/login', (req, res) => {
    let error = null;
    if (req.query.reason === 'inactive') {
        error = 'You have been logged out due to inactivity.';
    }
    res.render('login', { error, basePath: BASE_PATH });
});

// Input validation middleware
const loginValidation = [
    body('username')
        .trim()
        .isLength({ min: 3, max: 50 })
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('Username must be 3-50 characters and contain only letters, numbers, and underscores'),
    body('password')
        .isLength({ min: 6, max: 128 })
        .withMessage('Password must be 6-128 characters long')
];

app.post(BASE_PATH + '/login', loginLimiter, loginValidation, (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.render('login', { error: 'Invalid input format', basePath: BASE_PATH });
    }
    
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            return res.render('login', { error: 'Database error', basePath: BASE_PATH });
        }
        
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.render('login', { error: 'Invalid username or password', basePath: BASE_PATH });
        }
        
        req.session.userId = user.id;
        req.session.username = user.username;
        res.redirect(BASE_PATH + '/dashboard');
    });
});


app.get(BASE_PATH + '/logout', (req, res) => {
    const reason = req.query.reason;
    req.session.destroy((err) => {
        if (err) {
            console.error("Session destruction error:", err);
            return res.redirect(BASE_PATH + '/dashboard'); // Stay on dashboard if logout fails
        }
        // Redirect to login with a message for inactivity, otherwise to the homepage
        const redirectPath = reason === 'inactive' ? '/login?reason=inactive' : '/';
        res.redirect(BASE_PATH + redirectPath);
    });
});

app.get(BASE_PATH + '/dashboard', requireAuth, async (req, res, next) => {
    try {
        const userId = req.session.userId;

        // Fetch all dashboard data in parallel for better performance
        const [checklists, notes, files, reminders, user] = await Promise.all([
            dbAll('SELECT * FROM checklists WHERE user_id = ? ORDER BY created_at DESC', [userId]),
            dbAll('SELECT * FROM notes WHERE user_id = ? ORDER BY updated_at DESC', [userId]),
            dbAll('SELECT * FROM files WHERE user_id = ? ORDER BY created_at DESC', [userId]),
            dbAll('SELECT * FROM reminders WHERE user_id = ? ORDER BY remind_at ASC', [userId]),
            dbGet('SELECT email FROM users WHERE id = ?', [userId])
        ]);

        res.render('dashboard', {
            username: req.session.username,
            userEmail: user?.email,
            checklists: checklists || [],
            notes: notes || [],
            files: files || [],
            reminders: reminders || [],
            sessionMaxAge: SESSION_MAX_AGE,
            basePath: BASE_PATH
        });
    } catch (err) {
        next(err); // Pass errors to the global error handler
    }
});

// Checklist routes with validation
const checklistValidation = [
    body('title')
        .trim()
        .isLength({ min: 1, max: 200 })
        .escape()
        .withMessage('Title must be 1-200 characters')
];

app.post(BASE_PATH + '/checklist', requireAuth, checklistValidation, (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.redirect(BASE_PATH + '/dashboard?error=Invalid checklist title');
    }
    
    const { title } = req.body;
    const userId = req.session.userId;
    
    db.run('INSERT INTO checklists (user_id, title) VALUES (?, ?)', [userId, title], (err) => {
        if (err) {
            return res.redirect(BASE_PATH + '/dashboard?error=Failed to create checklist');
        }
        res.redirect(BASE_PATH + '/dashboard');
    });
});

app.post(BASE_PATH + '/checklist/:id/toggle', requireAuth, (req, res) => {
    const checklistId = req.params.id;
    const userId = req.session.userId;
    
    db.run('UPDATE checklists SET completed = NOT completed WHERE id = ? AND user_id = ?', 
           [checklistId, userId], (err) => {
        res.redirect(BASE_PATH + '/dashboard');
    });
});

app.post(BASE_PATH + '/checklist/:id/delete', requireAuth, (req, res) => {
    const checklistId = req.params.id;
    const userId = req.session.userId;
    
    db.run('DELETE FROM checklists WHERE id = ? AND user_id = ?', [checklistId, userId], (err) => {
        res.redirect(BASE_PATH + '/dashboard');
    });
});

// Notes routes with validation
const notesValidation = [
    body('title')
        .trim()
        .isLength({ min: 1, max: 200 })
        .escape()
        .withMessage('Title must be 1-200 characters'),
    body('content')
        .trim()
        .isLength({ max: 10000 })
        .escape()
        .withMessage('Content must be less than 10000 characters')
];

app.post(BASE_PATH + '/notes', requireAuth, notesValidation, (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.redirect(BASE_PATH + '/dashboard?error=Invalid note data');
    }
    
    const { title, content } = req.body;
    const userId = req.session.userId;
    
    db.run('INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)', 
           [userId, title, content], (err) => {
        if (err) {
            return res.redirect(BASE_PATH + '/dashboard?error=Failed to create note');
        }
        res.redirect(BASE_PATH + '/dashboard');
    });
});

app.post(BASE_PATH + '/notes/:id/delete', requireAuth, (req, res) => {
    const noteId = req.params.id;
    const userId = req.session.userId;
    
    db.run('DELETE FROM notes WHERE id = ? AND user_id = ?', [noteId, userId], (err) => {
        res.redirect(BASE_PATH + '/dashboard');
    });
});

// Reminder routes with validation
const reminderValidation = [
    body('title')
        .trim()
        .isLength({ min: 1, max: 200 })
        .escape()
        .withMessage('Title must be 1-200 characters'),
    body('remind_at')
        .isISO8601()
        .toDate()
        .withMessage('Invalid date format for reminder.'),
    body('recurrence')
        .isIn(['none', 'daily', 'weekly'])
        .withMessage('Invalid recurrence type.')
];

app.post(BASE_PATH + '/reminders', requireAuth, reminderValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.error('Reminder validation errors:', errors.array());
        return res.redirect(BASE_PATH + '/dashboard?error=Invalid reminder data');
    }

    const { title, recurrence } = req.body;
    const remindAtDate = req.body.remind_at; // This is a Date object from the validator
    const userId = req.session.userId;
    const now = new Date();

    // Pre-emptively mark notifications as "sent" or "not applicable" if the reminder is set for the near future.
    const notified_24h = remindAtDate.getTime() < (now.getTime() + 24 * 60 * 60 * 1000) ? 1 : 0;
    const notified_3h = remindAtDate.getTime() < (now.getTime() + 3 * 60 * 60 * 1000) ? 1 : 0;

    // Format the date to a local time string for database storage, instead of default UTC.
    const remindAtForDb = formatDbDate(remindAtDate);

    try {
        // Insert the new reminder with the local time string.
        await dbRun(
            'INSERT INTO reminders (user_id, title, remind_at, recurrence, notified, notified_24h, notified_3h) VALUES (?, ?, ?, ?, 0, ?, ?)',
            [userId, title, remindAtForDb, recurrence, notified_24h, notified_3h]
        );
        res.redirect(BASE_PATH + '/dashboard');
    } catch (err) {
        res.redirect(BASE_PATH + '/dashboard?error=Failed to create reminder');
    }
});

app.post(BASE_PATH + '/reminders/:id/delete', requireAuth, async (req, res) => {
    const reminderId = req.params.id;
    const userId = req.session.userId;

    try {
        await dbRun('DELETE FROM reminders WHERE id = ? AND user_id = ?', [reminderId, userId]);
        res.redirect(BASE_PATH + '/dashboard');
    } catch (err) {
        console.error(`Failed to delete reminder ${reminderId}:`, err);
        res.redirect(BASE_PATH + '/dashboard?error=Failed to delete reminder');
    }
});

// Profile route for setting email
const emailValidation = [
    body('email')
        .isEmail()
        .normalizeEmail({ gmail_remove_dots: false })
        .withMessage('Please provide a valid email address.')
];

app.post(BASE_PATH + '/profile/email', requireAuth, emailValidation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.redirect(BASE_PATH + '/dashboard?error=Invalid email address');
    }

    const { email } = req.body;
    const userId = req.session.userId;

    try {
        await dbRun('UPDATE users SET email = ? WHERE id = ?', [email, userId]);
        res.redirect(BASE_PATH + '/dashboard?success=Email updated successfully');
    } catch (err) {
        console.error('Failed to update email:', err);
        res.redirect(BASE_PATH + '/dashboard?error=Failed to update email');
    }
});

// A temporary route for testing email functionality
app.get(BASE_PATH + '/test-email', requireAuth, async (req, res) => {
    const userId = req.session.userId;
    try {
        const user = await dbGet('SELECT email FROM users WHERE id = ?', [userId]);

        if (!user || !user.email) {
            return res.status(400).send('No email configured for your account. Please set one in the dashboard.');
        }

        if (!process.env.EMAIL_HOST) {
            return res.status(500).send('Email service is not configured on the server. Check .env variables.');
        }

        await transporter.sendMail({
            from: process.env.EMAIL_FROM || `"Personal Dashboard Test" <${process.env.EMAIL_USER}>`,
            to: user.email,
            subject: 'SMTP Configuration Test',
            text: 'Hello! If you received this email, your SMTP configuration is working correctly.',
            html: '<p>Hello!</p><p>If you received this email, your SMTP configuration is working correctly.</p>',
        });

        console.log(`Test email sent successfully to ${user.email}`);
        res.send(`Successfully sent a test email to <strong>${user.email}</strong>. Please check your inbox.`);

    } catch (error) {
        console.error('Failed to send test email:', error);
        res.status(500).send(`Failed to send test email. Check server logs for details. Error: ${error.message}`);
    }
});
// --- Email and Scheduler Setup ---

// Nodemailer transporter setup using environment variables
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT || '587'),
    secure: process.env.EMAIL_PORT === '465', // true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

if (process.env.EMAIL_HOST) {
    transporter.verify().then(() => {
        console.log('✅ Email server is ready for reminder notifications.');
    }).catch(err => {
        console.error('⚠️ Email server configuration error. Reminders will not be sent.', err.message);
    });
} else {
    console.log('ℹ️ Email host not configured. Reminder emails are disabled.');
}

// File upload route with proper error handling
app.post(BASE_PATH + '/upload', requireAuth, (req, res) => {
    // This is the correct way to handle multer errors
    upload.single('file')(req, res, async (err) => {
        if (err instanceof multer.MulterError) {
            // A Multer error occurred when uploading.
            return res.status(400).send(`Multer Error: ${err.message}`);
        } else if (err) {
            // An unknown error occurred.
            // This is where your custom fileFilter error will be passed.
            return res.status(400).send(`Upload Error: ${err.message}`);
        }

        // If no file was provided in the request
        if (!req.file) {
            return res.status(400).send('No file selected for upload.');
        }

        const userId = req.session.userId;
        const { filename, originalname, size, mimetype } = req.file;
        
        try {
            const filePath = path.join(UPLOAD_DIR, filename);
            await dbRun('INSERT INTO files (user_id, filename, original_name, file_path, file_size, mime_type) VALUES (?, ?, ?, ?, ?, ?)',
                [userId, filename, originalname, filePath, size, mimetype]);
            // Respond with a success message that the client's fetch can see
            res.status(200).send('File uploaded successfully!');
        } catch (dbErr) {
            console.error('Database insertion failed:', dbErr);
            res.status(500).send('Failed to save file to database.');
        }
    });
});

app.get(BASE_PATH + '/download/:id', requireAuth, (req, res) => {
    const fileId = req.params.id;
    const userId = req.session.userId;
    
    db.get('SELECT * FROM files WHERE id = ? AND user_id = ?', [fileId, userId], (err, file) => {
        if (err || !file) {
            return res.status(404).send('File not found');
        }
        
        res.download(file.file_path, file.original_name);
    });
});

app.post(BASE_PATH + '/files/:id/delete', requireAuth, async (req, res) => {
    const fileId = req.params.id;
    const userId = req.session.userId;

    try {
        const file = await dbGet('SELECT * FROM files WHERE id = ? AND user_id = ?', [fileId, userId]);
        if (file) {
            // Delete physical file first, and wait for it to complete
            await fsPromises.unlink(file.file_path);
            // Then delete from database
            await dbRun('DELETE FROM files WHERE id = ? AND user_id = ?', [fileId, userId]);
        }
        res.redirect(BASE_PATH + '/dashboard');
    } catch (err) {
        console.error(`Failed to delete file ${fileId} for user ${userId}:`, err);
        res.redirect(BASE_PATH + '/dashboard?error=Failed+to+delete+file');
    }
});
/*  */
// Cron job to check for reminders every minute
cron.schedule('* * * * *', async () => {
    // Only run if email is configured
    if (!process.env.EMAIL_HOST) return;

    // "Heartbeat" log in local time to confirm the cron job is running.
    console.log(`[${new Date().toLocaleString('en-US')}] Cron job running: Checking for reminders...`);

    const now = new Date();
    const twentyFourHoursFromNow = new Date(now.getTime() + 24 * 60 * 60 * 1000);
    const threeHoursFromNow = new Date(now.getTime() + 3 * 60 * 60 * 1000);

    // Format dates into local time strings for DB query, instead of UTC with toISOString().
    const nowForDb = formatDbDate(now);
    const threeHoursFromNowForDb = formatDbDate(threeHoursFromNow);
    const twentyFourHoursFromNowForDb = formatDbDate(twentyFourHoursFromNow);

    try {
        // --- Check for 24-hour reminders ---
        // This window captures reminders that are between 3 and 24 hours away.
        const remindersFor24h = await dbAll(
            `SELECT r.*, u.email FROM reminders r JOIN users u ON r.user_id = u.id
             WHERE r.remind_at > ? AND r.remind_at <= ? AND r.notified_24h = 0 AND u.email IS NOT NULL AND u.email != ''`,
            [threeHoursFromNowForDb, twentyFourHoursFromNowForDb]
        );

        for (const reminder of remindersFor24h) {
            try {
                await transporter.sendMail({
                    from: process.env.EMAIL_FROM || `"Personal Dashboard" <${process.env.EMAIL_USER}>`,
                    to: reminder.email,
                    subject: `Reminder (24 hours): ${reminder.title}`,
                    text: `This is a 24-hour reminder for: "${reminder.title}".\nIt is scheduled for ${new Date(reminder.remind_at).toLocaleString()}.`,
                    html: `<p>This is a 24-hour reminder for: "<b>${reminder.title}</b>".</p><p>It is scheduled for ${new Date(reminder.remind_at).toLocaleString()}.</p>`,
                });
                console.log(`24-hour reminder email sent to ${reminder.email} for reminder ID ${reminder.id}`);
                await dbRun('UPDATE reminders SET notified_24h = 1 WHERE id = ?', [reminder.id]);
            } catch (processErr) {
                console.error(`Failed to process 24h reminder ${reminder.id}:`, processErr);
            }
        }

        // --- Check for 3-hour reminders ---
        // This window captures reminders that are within the next 3 hours.
        const remindersFor3h = await dbAll(
            `SELECT r.*, u.email FROM reminders r JOIN users u ON r.user_id = u.id
             WHERE r.remind_at >= ? AND r.remind_at <= ? AND r.notified_3h = 0 AND u.email IS NOT NULL AND u.email != ''`,
            [nowForDb, threeHoursFromNowForDb]
        );

        for (const reminder of remindersFor3h) {
            try {
                await transporter.sendMail({
                    from: process.env.EMAIL_FROM || `"Personal Dashboard" <${process.env.EMAIL_USER}>`,
                    to: reminder.email,
                    subject: `Reminder (3 hours): ${reminder.title}`,
                    text: `This is a 3-hour reminder for: "${reminder.title}".\nIt is scheduled for ${new Date(reminder.remind_at).toLocaleString()}.`,
                    html: `<p>This is a 3-hour reminder for: "<b>${reminder.title}</b>".</p><p>It is scheduled for ${new Date(reminder.remind_at).toLocaleString()}.</p>`,
                });
                console.log(`3-hour reminder email sent to ${reminder.email} for reminder ID ${reminder.id}`);
                await dbRun('UPDATE reminders SET notified_3h = 1 WHERE id = ?', [reminder.id]);
            } catch (processErr) {
                console.error(`Failed to process 3h reminder ${reminder.id}:`, processErr);
            }
        }

        // --- Handle recurrence for reminders that have passed ---
        // Only select reminders that are strictly in the past to avoid rescheduling them at the exact moment they are due.
        const pastDueRecurringReminders = await dbAll(`SELECT * FROM reminders WHERE remind_at < ? AND recurrence != 'none'`, [nowForDb]);

        for (const reminder of pastDueRecurringReminders) {
            // The DB stores a 'YYYY-MM-DDTHH:MM:SS' string which new Date() correctly parses as local time.
            let nextRemindAt = new Date(reminder.remind_at);

            const recurrenceLogic = {
                daily: () => nextRemindAt.setDate(nextRemindAt.getDate() + 1),
                weekly: () => nextRemindAt.setDate(nextRemindAt.getDate() + 7),
            };
            // Keep advancing the date until it's in the future relative to the current cron job time.
            while (nextRemindAt <= now) {
                // Correctly call the recurrence logic function based on the reminder's setting.
                recurrenceLogic[reminder.recurrence]();
            }
            // When an event is rescheduled, reset all notification flags to 0
            // to allow the new reminder instance to trigger its own notifications correctly.
            const nextRemindAtForDb = formatDbDate(nextRemindAt);
            await dbRun('UPDATE reminders SET remind_at = ?, notified = 0, notified_24h = 0, notified_3h = 0 WHERE id = ?', [nextRemindAtForDb, reminder.id]);
            console.log(`Rescheduled reminder ID ${reminder.id} for ${nextRemindAtForDb}`);
        }

        // --- Cleanup old, non-recurring reminders ---
        // The logic to delete old, non-recurring reminders has been removed as per the new requirement.
        // const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        // await dbRun(`DELETE FROM reminders WHERE recurrence = 'none' AND remind_at < ?`, [oneDayAgo.toISOString()]);
    } catch (error) {
        console.error('Error in reminder cron job:', error);
    }
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something went wrong!');
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});