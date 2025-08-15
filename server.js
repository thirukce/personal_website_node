const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

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
    secret: 'your-secret-key-change-this-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Rate limiting for login attempts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: 'Too many login attempts, please try again later.'
});

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
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        // Allow images and common file types
        const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt|zip/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only images and documents are allowed!'));
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

app.post('/login', loginLimiter, (req, res) => {
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

// Checklist routes
app.post('/checklist', requireAuth, (req, res) => {
    const { title } = req.body;
    const userId = req.session.userId;
    
    db.run('INSERT INTO checklists (user_id, title) VALUES (?, ?)', [userId, title], (err) => {
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

// Notes routes
app.post('/notes', requireAuth, (req, res) => {
    const { title, content } = req.body;
    const userId = req.session.userId;
    
    db.run('INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)', 
           [userId, title, content], (err) => {
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
