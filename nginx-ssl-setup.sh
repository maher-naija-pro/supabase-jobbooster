#!/bin/bash

# Nginx SSL Setup Script for db.thejobbooster.com
# This script installs nginx, configures Let's Encrypt SSL, and sets up reverse proxy to localhost:8000

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DOMAIN="db.thejobbooster.com"
EMAIL="admin@thejobbooster.com"  # Change this to your email
UPSTREAM_PORT="8000"
NGINX_CONFIG_DIR="/etc/nginx/sites-available"
NGINX_ENABLED_DIR="/etc/nginx/sites-enabled"
CERTBOT_DIR="/etc/letsencrypt/live/$DOMAIN"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

print_status "Starting Nginx SSL setup for $DOMAIN"

# Update package list
print_status "Updating package list..."
apt update

# Install nginx
print_status "Installing Nginx..."
apt install -y nginx

# Install certbot and nginx plugin
print_status "Installing Certbot and Nginx plugin..."
apt install -y certbot python3-certbot-nginx

# Start and enable nginx
print_status "Starting and enabling Nginx..."
systemctl start nginx
systemctl enable nginx

# Create initial nginx configuration for HTTP (needed for Let's Encrypt validation)
print_status "Creating initial HTTP configuration for Let's Encrypt validation..."
cat > "$NGINX_CONFIG_DIR/$DOMAIN" << EOF
server {
    listen 80;
    server_name $DOMAIN;

    # Let's Encrypt challenge location
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    # Temporary redirect to HTTPS (will be updated after SSL setup)
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}
EOF

# Enable the site
print_status "Enabling the site configuration..."
ln -sf "$NGINX_CONFIG_DIR/$DOMAIN" "$NGINX_ENABLED_DIR/$DOMAIN"

# Test nginx configuration
print_status "Testing Nginx configuration..."
nginx -t

# Reload nginx
print_status "Reloading Nginx..."
systemctl reload nginx

# Obtain SSL certificate
print_status "Obtaining SSL certificate from Let's Encrypt..."
print_warning "Make sure your domain $DOMAIN points to this server's IP address!"
print_warning "Press Enter to continue when DNS is ready, or Ctrl+C to cancel..."
read -r

# Run certbot
certbot --nginx -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive

# Update nginx configuration with SSL and reverse proxy
print_status "Updating Nginx configuration with SSL and reverse proxy..."
cat > "$NGINX_CONFIG_DIR/$DOMAIN" << EOF
# HTTP server - redirect to HTTPS
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    # SSL Configuration
    ssl_certificate $CERTBOT_DIR/fullchain.pem;
    ssl_certificate_key $CERTBOT_DIR/privkey.pem;
    
    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Proxy settings
    location / {
        proxy_pass http://localhost:$UPSTREAM_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_read_timeout 86400;
    }

    # Let's Encrypt challenge location (for renewals)
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
}
EOF

# Test nginx configuration
print_status "Testing updated Nginx configuration..."
nginx -t

if [ $? -eq 0 ]; then
    # Reload nginx
    print_status "Reloading Nginx with new configuration..."
    systemctl reload nginx
    
    # Setup automatic certificate renewal
    print_status "Setting up automatic certificate renewal..."
    (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet --nginx") | crontab -
    
    print_status "Nginx SSL setup completed successfully!"
    print_status "Your domain $DOMAIN is now configured with SSL and will redirect to localhost:$UPSTREAM_PORT"
    print_status "Certificate will be automatically renewed via cron job"
    
    # Show status
    print_status "Nginx status:"
    systemctl status nginx --no-pager -l
    
    print_status "SSL certificate info:"
    certbot certificates
    
else
    print_error "Nginx configuration test failed. Please check the configuration manually."
    exit 1
fi
