# Personal Website with Dashboard

A beautiful, secure personal website featuring a public homepage and private authenticated dashboard for managing tasks, notes, and files.

## Features

### Public Homepage
- Modern, responsive design with gradient backgrounds
- Feature showcase with animated cards
- Professional landing page for visitors

### Private Dashboard (Authentication Required)
- **Task Management**: Create, complete, and delete checklist items
- **Notes System**: Add, view, and manage personal notes
- **File Upload**: Upload, download, and manage files and photos
- **Secure Authentication**: Protected access to personal data

## Default Login Credentials
- **Username**: `admin`
- **Password**: `admin123`

## Installation

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
npm start
```

3. For development with auto-restart:
```bash
npm run dev
```

4. Open your browser and navigate to:
```
http://localhost:3000
```

## Technology Stack

- **Backend**: Node.js with Express
- **Database**: SQLite3 for data persistence
- **Authentication**: bcryptjs for password hashing, express-session for sessions
- **File Uploads**: Multer with file type validation
- **Frontend**: EJS templating with modern CSS and JavaScript
- **Security**: Rate limiting, input validation, secure file handling

## File Structure

```
├── server.js              # Main server file
├── package.json           # Dependencies and scripts
├── views/                 # EJS templates
│   ├── index.ejs         # Public homepage
│   ├── login.ejs         # Login page
│   └── dashboard.ejs     # Private dashboard
├── uploads/              # File upload directory (auto-created)
├── personal_website.db   # SQLite database (auto-created)
└── README.md            # This file
```

## Security Features

- Password hashing with bcryptjs
- Session-based authentication
- Rate limiting on login attempts
- File type validation for uploads
- SQL injection protection with parameterized queries
- CSRF protection through session validation

## Customization

- Change default credentials in `server.js`
- Modify the secret key in session configuration
- Adjust file upload limits and allowed types
- Customize the UI colors and styling in the EJS templates

## Database Schema

The application automatically creates the following tables:
- `users` - User authentication data
- `checklists` - Task/checklist items
- `notes` - Personal notes
- `files` - Uploaded file metadata

## Support

This is a self-contained personal website. All data is stored locally in the SQLite database.
