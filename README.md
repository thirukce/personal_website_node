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

## Local Development Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the development server with auto-restart:
   ```bash
   npm run dev
   ```

## Deployment

For production deployment on an Ubuntu server, please follow the detailed instructions in INSTALL.md.

## Technology Stack

- **Backend**: Node.js with Express
- **Database**: SQLite3 for data persistence
- **Authentication**: bcryptjs for password hashing, express-session for sessions
- **File Uploads**: Multer 2.0 with strict file type validation
- **Frontend**: EJS templating with modern CSS and JavaScript
- **Security**: Helmet, rate limiting, input validation, CORS, compression, logging
- **Validation**: express-validator for input sanitization and validation

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

- **Enhanced Security Headers**: Helmet middleware with CSP, XSS protection
- **Password Security**: bcryptjs hashing with secure session management
- **Rate Limiting**: Login attempts (5/15min) and general requests (100/15min)
- **Input Validation**: express-validator with sanitization and escaping
- **File Upload Security**: Strict MIME type validation, 5MB limit, single file uploads
- **SQL Injection Protection**: Parameterized queries throughout
- **CSRF Protection**: SameSite cookies and secure session configuration
- **XSS Prevention**: Input escaping and Content Security Policy
- **CORS Configuration**: Configurable allowed origins
- **Secure Cookies**: HttpOnly, Secure (HTTPS), and SameSite attributes
- **Logging**: Morgan middleware for security monitoring

See [SECURITY.md](SECURITY.md) for complete security documentation.

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
