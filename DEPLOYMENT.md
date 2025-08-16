# Deployment Guide: Personal Website Admin Panel

This guide will help you deploy your Node.js personal website admin panel to your Ubuntu server at `https://www.mythiru.com/admin`.

## Prerequisites

- Ubuntu server with sudo access
- Domain `www.mythiru.com` pointing to your server
- Nginx already configured for your static website
- Git installed on the server

## Quick Deployment

1. **Run the deployment script on your Ubuntu server:**
   ```bash
   wget https://raw.githubusercontent.com/thirukce/personal_website_node/main/deploy.sh
   chmod +x deploy.sh
   ./deploy.sh
   ```

## Manual Deployment Steps

### 1. Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 18.x
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PM2 for process management
sudo npm install -g pm2
```

### 2. Setup Application

```bash
# Create application directory
sudo mkdir -p /var/www/personal-website-admin
sudo chown -R $USER:$USER /var/www/personal-website-admin
cd /var/www/personal-website-admin

# Clone repository
git clone https://github.com/thirukce/personal_website_node.git .

# Install dependencies
npm install --production

# Create environment file
cp .env.example .env
```

### 3. Configure Environment

Edit the `.env` file with your production settings:

```bash
nano .env
```

**Important settings:**
- `NODE_ENV=production`
- `BASE_PATH=/admin`
- `SESSION_SECRET=` (generate a secure random string)
- `ALLOWED_ORIGINS=https://www.mythiru.com`
- `PORT=3000` (or your preferred port)

### 4. Configure Nginx

Add the following configuration to your existing nginx server block for `www.mythiru.com`:

```nginx
# Include this in your existing server block
location /admin {
    # Remove /admin from the path when forwarding to Node.js app
    rewrite ^/admin(/.*)$ $1 break;
    rewrite ^/admin$ / break;
    
    # Forward to Node.js application
    proxy_pass http://localhost:3000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_cache_bypass $http_upgrade;
    
    # Handle static files
    location ~* /admin/\.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        proxy_pass http://localhost:3000;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}

# Optional: Redirect /admin/ to /admin for consistency
location = /admin/ {
    return 301 /admin;
}
```

Test and reload nginx:
```bash
sudo nginx -t
sudo systemctl reload nginx
```

### 5. Start the Application

```bash
# Start with PM2
pm2 start ecosystem.config.js --env production

# Save PM2 configuration
pm2 save

# Setup PM2 to start on boot
pm2 startup
```

### 6. Set Permissions

```bash
# Set proper permissions
sudo chown -R $USER:www-data /var/www/personal-website-admin
sudo chmod -R 755 /var/www/personal-website-admin
sudo chmod -R 775 /var/www/personal-website-admin/uploads
```

## Access Your Admin Panel

Once deployed, you can access your admin panel at:
**https://www.mythiru.com/admin**

**Default login credentials:**
- Username: `admin`
- Password: `admin123`

⚠️ **Important:** Change the default password immediately after first login!

## Management Commands

```bash
# View application logs
pm2 logs personal-website-admin

# Restart application
pm2 restart personal-website-admin

# Stop application
pm2 stop personal-website-admin

# View application status
pm2 status

# Update application
cd /var/www/personal-website-admin
git pull origin main
npm install --production
pm2 restart personal-website-admin
```

## Security Considerations

1. **Change default credentials** immediately
2. **Use HTTPS** (ensure SSL certificate covers your domain)
3. **Regular updates**: Keep Node.js, npm packages, and system updated
4. **Firewall**: Only allow necessary ports (80, 443, SSH)
5. **Backup**: Regular database and uploads backup

## Troubleshooting

### Application won't start
```bash
# Check PM2 logs
pm2 logs personal-website-admin

# Check if port is available
sudo netstat -tlnp | grep :3000
```

### Nginx 502 Bad Gateway
```bash
# Check if Node.js app is running
pm2 status

# Check nginx error logs
sudo tail -f /var/log/nginx/error.log
```

### Database issues
```bash
# Check database file permissions
ls -la /var/www/personal-website-admin/personal_website.db

# Ensure uploads directory exists
mkdir -p /var/www/personal-website-admin/uploads
```

## File Structure

```
/var/www/personal-website-admin/
├── server.js              # Main application file
├── package.json           # Dependencies
├── ecosystem.config.js    # PM2 configuration
├── .env                   # Environment variables
├── personal_website.db    # SQLite database
├── uploads/               # File uploads directory
├── views/                 # EJS templates
│   ├── index.ejs
│   ├── login.ejs
│   └── dashboard.ejs
└── public/               # Static files (if any)
```

## Support

If you encounter any issues during deployment, check:
1. PM2 logs: `pm2 logs personal-website-admin`
2. Nginx logs: `sudo tail -f /var/log/nginx/error.log`
3. System logs: `sudo journalctl -u nginx -f`
