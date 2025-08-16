#!/bin/bash

# Deployment script for Personal Website Admin Panel
# This script sets up the Node.js application on Ubuntu server

set -e

echo "🚀 Starting deployment of Personal Website Admin Panel..."

# Update system packages
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Node.js (if not already installed)
if ! command -v node &> /dev/null; then
    echo "📥 Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

# Install PM2 (if not already installed)
if ! command -v pm2 &> /dev/null; then
    echo "📥 Installing PM2..."
    sudo npm install -g pm2
fi

# Create application directory
APP_DIR="/var/www/personal-website-admin"
echo "📁 Setting up application directory at $APP_DIR..."
sudo mkdir -p $APP_DIR
sudo chown -R $USER:$USER $APP_DIR

# Navigate to application directory
cd $APP_DIR

# Clone or update repository
if [ -d ".git" ]; then
    echo "🔄 Updating existing repository..."
    git pull origin main
else
    echo "📥 Cloning repository..."
    git clone https://github.com/thirukce/personal_website_node.git .
fi

# Install dependencies
echo "📦 Installing Node.js dependencies..."
npm install --production

# Create .env file from example
if [ ! -f ".env" ]; then
    echo "⚙️ Creating environment configuration..."
    cp .env.example .env
    echo "⚠️  Please edit .env file with your production settings!"
fi

# Create uploads directory
mkdir -p uploads

# Set proper permissions
sudo chown -R $USER:www-data $APP_DIR
sudo chmod -R 755 $APP_DIR
sudo chmod -R 775 uploads

# Start/restart application with PM2
echo "🔄 Starting application with PM2..."
pm2 delete personal-website-admin 2>/dev/null || true
pm2 start ecosystem.config.js --env production
pm2 save
pm2 startup

echo "✅ Deployment completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Edit .env file with your production settings"
echo "2. Configure nginx with the provided nginx-admin.conf"
echo "3. Restart nginx: sudo systemctl restart nginx"
echo "4. Access your admin panel at: https://www.mythiru.com/admin"
echo ""
echo "🔧 Useful commands:"
echo "- View logs: pm2 logs personal-website-admin"
echo "- Restart app: pm2 restart personal-website-admin"
echo "- Stop app: pm2 stop personal-website-admin"
