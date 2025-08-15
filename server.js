require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const compression = require('compression');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'"],
            connectSrc: ["'self'"]
        }
    }
}));

// CORS configuration
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true
}));

// Compression and logging
app.use(compression());
app.use(morgan('combined'));

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Database setup
const db = new sqlite3.Database('personal_website.db');

// Initialize database tables
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

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

    // Create default admin user (password: admin123)
    const hashedPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`, 
           ['admin', hashedPassword]);
});

// Middleware
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    name: 'sessionId', // Don't use default session name
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // HTTPS only in production
        httpOnly: true, // Prevent XSS
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'strict' // CSRF protection
    }
}));

// Rate limiting for login attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: { error: 'Too many login attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

// General rate limiting
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

app.use(generalLimiter);

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { 
        fileSize: 5 * 1024 * 1024, // 5MB limit (reduced for security)
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
        res.redirect('/login');
    }
};

// Routes
app.get('/', (req, res) => {
    res.render('index');
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
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

app.post('/login', loginLimiter, loginValidation, (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.render('login', { error: 'Invalid input format' });
    }
    
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            return res.render('login', { error: 'Database error' });
        }
        
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.render('login', { error: 'Invalid username or password' });
        }
        
        req.session.userId = user.id;
        req.session.username = user.username;
        res.redirect('/dashboard');
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/dashboard', requireAuth, (req, res) => {
    // Get user's checklists, notes, and files
    const userId = req.session.userId;
    
    db.all('SELECT * FROM checklists WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, checklists) => {
        if (err) checklists = [];
        
        db.all('SELECT * FROM notes WHERE user_id = ? ORDER BY updated_at DESC', [userId], (err, notes) => {
            if (err) notes = [];
            
            db.all('SELECT * FROM files WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, files) => {
                if (err) files = [];
                
                res.render('dashboard', { 
                    username: req.session.username,
                    checklists: checklists,
                    notes: notes,
                    files: files
                });
            });
        });
    });
});

// Checklist routes with validation
const checklistValidation = [
    body('title')
        .trim()
        .isLength({ min: 1, max: 200 })
        .escape()
        .withMessage('Title must be 1-200 characters')
];

app.post('/checklist', requireAuth, checklistValidation, (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.redirect('/dashboard?error=Invalid checklist title');
    }
    
    const { title } = req.body;
    const userId = req.session.userId;
    
    db.run('INSERT INTO checklists (user_id, title) VALUES (?, ?)', [userId, title], (err) => {
        if (err) {
            return res.redirect('/dashboard?error=Failed to create checklist');
        }
        res.redirect('/dashboard');
    });
});

app.post('/checklist/:id/toggle', requireAuth, (req, res) => {
    const checklistId = req.params.id;
    const userId = req.session.userId;
    
    db.run('UPDATE checklists SET completed = NOT completed WHERE id = ? AND user_id = ?', 
           [checklistId, userId], (err) => {
        res.redirect('/dashboard');
    });
});

app.post('/checklist/:id/delete', requireAuth, (req, res) => {
    const checklistId = req.params.id;
    const userId = req.session.userId;
    
    db.run('DELETE FROM checklists WHERE id = ? AND user_id = ?', [checklistId, userId], (err) => {
        res.redirect('/dashboard');
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

app.post('/notes', requireAuth, notesValidation, (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.redirect('/dashboard?error=Invalid note data');
    }
    
    const { title, content } = req.body;
    const userId = req.session.userId;
    
    db.run('INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)', 
           [userId, title, content], (err) => {
        if (err) {
            return res.redirect('/dashboard?error=Failed to create note');
        }
        res.redirect('/dashboard');
    });
});

app.post('/notes/:id/delete', requireAuth, (req, res) => {
    const noteId = req.params.id;
    const userId = req.session.userId;
    
    db.run('DELETE FROM notes WHERE id = ? AND user_id = ?', [noteId, userId], (err) => {
        res.redirect('/dashboard');
    });
});

// File upload routes
app.post('/upload', requireAuth, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.redirect('/dashboard?error=No file selected');
    }
    
    const userId = req.session.userId;
    const { filename, originalname, path: filePath, size, mimetype } = req.file;
    
    db.run('INSERT INTO files (user_id, filename, original_name, file_path, file_size, mime_type) VALUES (?, ?, ?, ?, ?, ?)',
           [userId, filename, originalname, filePath, size, mimetype], (err) => {
        res.redirect('/dashboard');
    });
});

app.get('/download/:id', requireAuth, (req, res) => {
    const fileId = req.params.id;
    const userId = req.session.userId;
    
    db.get('SELECT * FROM files WHERE id = ? AND user_id = ?', [fileId, userId], (err, file) => {
        if (err || !file) {
            return res.status(404).send('File not found');
        }
        
        const filePath = path.join(__dirname, file.file_path);
        res.download(filePath, file.original_name);
    });
});

app.post('/files/:id/delete', requireAuth, (req, res) => {
    const fileId = req.params.id;
    const userId = req.session.userId;
    
    db.get('SELECT * FROM files WHERE id = ? AND user_id = ?', [fileId, userId], (err, file) => {
        if (file) {
            // Delete physical file
            fs.unlink(path.join(__dirname, file.file_path), () => {});
            
            // Delete from database
            db.run('DELETE FROM files WHERE id = ? AND user_id = ?', [fileId, userId], (err) => {
                res.redirect('/dashboard');
            });
        } else {
            res.redirect('/dashboard');
        }
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Default login: username=admin, password=admin123');
});
