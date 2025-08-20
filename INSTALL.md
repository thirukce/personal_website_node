# Manual Installation Guide

This guide provides step-by-step instructions to deploy the Personal Website application on an Ubuntu 22.04/20.04 server. The application will be served by Node.js and PM2, with Apache2 acting as a reverse proxy for the entire `www.mythiru.com` domain.

## Prerequisites

*   An Ubuntu server with `sudo` access.
*   A domain name (e.g., `www.mythiru.com`) configured in your DNS to point to your server's public IP address.
*   Apache2 installed. It will be configured to act as a reverse proxy for the Node.js application.
*   Git is installed (`sudo apt install git`).

---

### Step 1: Prepare the Server

First, update your server's package list and install necessary tools.

```bash
# Update package lists and upgrade existing packages
sudo apt update && sudo apt upgrade -y

# Install Apache2 if it's not already present
sudo apt install -y apache2

# Enable the Apache2 modules required for the reverse proxy
sudo a2enmod proxy proxy_http headers rewrite ssl
sudo systemctl restart apache2
```

### Step 2: Install Node.js and PM2

The application runs on Node.js. We'll use PM2 to manage the Node.js process.

```bash
# Install Node.js v18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PM2, a process manager for Node.js applications
sudo npm install -g pm2
```

### Step 3: Clone and Set Up the Application

Create a directory for the application, clone the source code, and install its dependencies.

```bash
# Define the application directory
APP_DIR="/var/www/mythiru.com"

# Create the directory and set your user as the owner for now
sudo mkdir -p $APP_DIR
sudo chown -R $USER:$USER $APP_DIR

# Navigate into the new directory
cd $APP_DIR

# Clone the repository into the current directory
git clone https://github.com/thirukce/personal_website_node.git .

# Install production dependencies
npm install --production
```

### Step 4: Configure Environment Variables

The application's configuration is managed through a `.env` file.

```bash
# Copy the example environment file
cp .env.example .env

# Open the file for editing
nano .env
```

Now, update the file with your production settings. **This is a critical security step.**

```ini
# .env
NODE_ENV=production
PORT=3000 # The internal port for the Node.js app
BASE_PATH= # Leave this empty to serve from the root domain
ALLOWED_ORIGINS=https://www.mythiru.com

# ❗️ Generate a new secret using the command below
SESSION_SECRET=your_super_long_and_random_secret_string_here
```

To generate a secure `SESSION_SECRET`, run this command in your terminal and paste the output into the `.env` file:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Step 5: Configure Apache2 as a Reverse Proxy

Edit your existing Apache2 virtual host configuration for `www.mythiru.com`. This is typically located at `/etc/apache2/sites-available/your-domain-le-ssl.conf` if you use Let's Encrypt.

Add the following lines inside the `<VirtualHost *:443>` block:

```apache
# Add this inside your <VirtualHost *:443> block for www.mythiru.com
# This will forward all traffic to your Node.js application
ProxyPreserveHost On
# Set the X-Forwarded-Proto header to tell Node.js the original request was HTTPS.
# This is required for secure cookies to work correctly.
RequestHeader set X-Forwarded-Proto "https"
ProxyPass / http://localhost:3000/
ProxyPassReverse / http://localhost:3000/
```

After saving the file, test your Apache configuration and reload the service:

```bash
sudo apache2ctl configtest
sudo systemctl reload apache2
```

### Step 6: Start the Application with PM2

Now, start the application using PM2 and configure it to launch automatically on server boot.

```bash
# Ensure you are in the application directory
cd /var/www/mythiru.com

# Start the application using the ecosystem file
pm2 start ecosystem.config.js --env production

# Save the current process list to be resurrected on reboot
pm2 save

# Generate and run the startup script for your system
sudo env PATH=$PATH:/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u $USER --hp /home/$USER
```

### Step 7: Set Final Permissions & Security

Secure your application files, especially the `.env` file and the database.

```bash
# Set ownership to your user and the web server group (www-data)
sudo chown -R $USER:www-data /var/www/mythiru.com

# Set secure permissions for the application directory
sudo chmod -R 750 /var/www/mythiru.com

# Allow the web server to write to the uploads directory
sudo chmod -R 770 /var/www/mythiru.com/uploads

# Protect your environment file and database from being read by others
sudo chmod 600 /var/www/mythiru.com/.env
sudo chmod 600 /var/www/mythiru.com/personal_website.db
```

### Step 8: Secure Your Server (Firewall & SSL)

If you haven't already, secure your server with a firewall and ensure you have an SSL certificate.

```bash
# Configure UFW (Uncomplicated Firewall)
sudo ufw allow ssh       # Allow SSH connections
sudo ufw allow 'Apache Full' # Allow HTTP/HTTPS traffic
sudo ufw deny 3000       # Block direct access to the Node.js port
sudo ufw enable

# Install Certbot for free SSL certificates from Let's Encrypt
sudo apt install certbot python3-certbot-apache -y

# Obtain and install a certificate for your domain
sudo certbot --apache -d www.mythiru.com
```

### You're Done!

Your application should now be accessible at **`https://www.mythiru.com`**. You can log in at `https://www.mythiru.com/login`.

**Default login:**
*   **Username**: `admin`
*   **Password**: `admin123`

> ⚠️ **IMPORTANT:** Log in immediately and change the default password. The application does not yet have a "change password" feature, so you will need to do this manually.

For more security best practices, please review the `SECURITY.md` file.

---
## Application Management

Here are some useful commands for managing your running application.

```bash
# View application status
pm2 status mythiru.com

# View live logs
pm2 logs mythiru.com

# Restart the application
pm2 restart mythiru.com

# Stop the application
pm2 stop mythiru.com
```

## Updating the Application

To update your application to the latest version from GitHub:

```bash
cd /var/www/mythiru.com
git pull origin main
npm install --production
pm2 restart mythiru.com
```