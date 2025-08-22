# Security Guide

## Security Enhancements Implemented

### 🔒 **Dependencies Security**
- **Updated Multer**: Upgraded from vulnerable 1.4.5 to 2.0.0-rc.4
- **Updated Express**: Latest version with security patches
- **Added Helmet**: Comprehensive security headers
- **Added express-validator**: Input validation and sanitization
- **Added compression**: Reduces payload size
- **Added morgan**: Security logging

### 🛡️ **Security Middleware**

#### Helmet Security Headers
- Content Security Policy (CSP)
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block

#### Rate Limiting
- **Login attempts**: 5 attempts per 15 minutes per IP
- **General requests**: 100 requests per 15 minutes per IP

#### Session Security
- HttpOnly cookies (prevents XSS)
- Secure cookies in production (HTTPS only)
- SameSite: strict (CSRF protection)
- Custom session name (security through obscurity)

### 🔐 **Input Validation**
- Username: 3-50 characters, alphanumeric + underscore only
- Password: 6-128 characters
- Checklist titles: 1-200 characters, HTML escaped
- Notes: Title 1-200 chars, content max 10,000 chars, HTML escaped

### 📁 **File Upload Security**
- **Reduced file size**: 5MB limit (was 10MB)
- **Strict MIME type validation**: Only specific file types allowed
- **File extension validation**: Double-check with extension matching
- **Single file uploads only**: Prevents batch upload attacks

### 🌐 **CORS Configuration**
- Configurable allowed origins
- Credentials support for authenticated requests

## Deployment Security Checklist

### 1. Environment Variables
```bash
# Copy and configure environment file
cp .env.example .env
nano .env
```

**Required changes:**
- `SESSION_SECRET`: Generate a strong random secret (32+ characters)
- `ALLOWED_ORIGINS`: Set your actual domain
- `ADMIN_DEFAULT_PASSWORD`: Set a strong, unique password for the default admin user.
- `NODE_ENV=production`

### 2. Generate Secure Session Secret
```bash
# Generate a secure session secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 3. File Permissions
```bash
# Set proper file permissions
chmod 600 .env
chmod 755 uploads/
chown -R www-data:www-data /var/www/personal-website
```

### 4. Database Security
```bash
# Secure database file
chmod 600 personal_website.db
chown www-data:www-data personal_website.db
```

### 5. Apache Security Headers
Add to your Apache virtual host:
```apache
# Additional security headers
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# Hide Apache version
ServerTokens Prod
ServerSignature Off
```

### 6. Firewall Configuration
```bash
# Configure UFW firewall
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 'Apache Full'
sudo ufw deny 3000  # Block direct access to Node.js port
```

### 7. SSL/TLS Setup
```bash
# Install SSL certificate
sudo certbot --apache -d yourdomain.com -d www.yourdomain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

## Security Monitoring

### 1. Log Monitoring
```bash
# Monitor access logs
tail -f /var/log/apache2/personal-website_access.log

# Monitor error logs
tail -f /var/log/apache2/personal-website_error.log

# Monitor PM2 logs
pm2 logs personal-website
```

### 2. Security Scanning
```bash
# Regular npm audit
npm audit
npm audit fix

# Check for outdated packages
npm outdated
```

### 3. System Updates
```bash
# Regular system updates
sudo apt update && sudo apt upgrade -y

# Update Node.js dependencies
npm update
```

## Security Best Practices

### ✅ **Implemented**
- Input validation and sanitization
- Rate limiting
- Secure session management
- File upload restrictions
- Security headers
- HTTPS enforcement (production)
- SQL injection prevention (parameterized queries)
- XSS prevention (input escaping)
- CSRF protection (SameSite cookies)

### 📋 **Additional Recommendations**
- Regular security audits
- Database backups with encryption
- Log rotation and monitoring
- Intrusion detection system
- Regular dependency updates
- Security penetration testing

## Incident Response

### If Security Breach Detected:
1. **Immediate**: Stop the application (`pm2 stop personal-website`)
2. **Assess**: Check logs for attack vectors
3. **Contain**: Block malicious IPs via firewall
4. **Recover**: Restore from clean backup if needed
5. **Improve**: Update security measures based on findings

## Contact
For security issues, please create a GitHub issue or contact the administrator directly.
