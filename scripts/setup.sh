#!/bin/bash
#
# Server Setup Script
# Run this on your Ubuntu server after cloning the repo
#

set -e

DOMAIN="blog.269147.xyz"
REPO_URL="https://github.com/YOUR_USERNAME/blog.git"  # Change this
APP_DIR="/var/www/blog"
BACKEND_PORT=8080

echo "=== Installing dependencies ==="
apt update
apt install -y nginx git curl

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo "Installing Go..."
    wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    rm go1.21.0.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
fi

# Install Node.js if not present
if ! command -v node &> /dev/null; then
    echo "Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt install -y nodejs
fi

echo "=== Setting up application directory ==="
mkdir -p $APP_DIR
cd $APP_DIR

# Clone repo if not exists, otherwise pull
if [ ! -d ".git" ]; then
    git clone $REPO_URL .
else
    git pull origin main
fi

echo "=== Building frontend ==="
cd $APP_DIR/frontend
npm install
npm run build

echo "=== Setting up backend ==="
cd $APP_DIR/backend
go mod download
go build -o blog-server main.go

echo "=== Creating systemd service ==="
cat > /etc/systemd/system/blog-backend.service << EOF
[Unit]
Description=Blog Backend Service
After=network.target

[Service]
WorkingDirectory=$APP_DIR/backend
ExecStart=$APP_DIR/backend/blog-server
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable blog-backend
systemctl restart blog-backend

echo "=== Configuring Nginx ==="
cat > /etc/nginx/sites-available/$DOMAIN << EOF
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        root $APP_DIR/frontend/dist;
        try_files \$uri \$uri/ /index.html;
    }

    location /api {
        proxy_pass http://127.0.0.1:$BACKEND_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

ln -sf /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-available/default
nginx -t && systemctl restart nginx

echo "=== Setup complete ==="
echo "Backend running at: http://127.0.0.1:$BACKEND_PORT"
echo "Site accessible at: http://$DOMAIN"
