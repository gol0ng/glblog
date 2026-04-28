# Blog System

A minimalist blog system with React + Vite frontend and Go + Gin backend.

## Features

- Minimalist "no style please" theme
- Markdown-based posts with LaTeX support
- Admin dashboard for post management
- Basic authentication

## Local Development

### Backend

```bash
cd backend
go mod download
go run main.go
```

Backend runs at http://localhost:8080

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at http://localhost:5173

## Deployment

### 1. Push to GitHub

Edit `scripts/deploy.sh` to set your GitHub repo URL, then run:

```bash
./scripts/deploy.sh
```

### 2. Setup Server

SSH to your Ubuntu server and clone the repo:

```bash
git clone https://github.com/YOUR_USERNAME/blog.git /var/www/blog
cd /var/www/blog
./scripts/setup.sh
```

### 3. Configure Domain

Update DNS records for `blog.269147.xyz` to point to your server's IP.

### 4. SSL Certificate (Optional)

```bash
apt install -y certbot python3-certbot-nginx
certbot --nginx -d blog.269147.xyz
```

## Admin Access

- URL: http://blog.269147.xyz/admin
- Username: `admin`
- Password: `admin123`

## Project Structure

```
blog/
├── backend/
│   ├── main.go           # Entry point
│   ├── handlers/        # API handlers
│   ├── models/         # Data models
│   └── posts/          # Markdown posts
├── frontend/
│   ├── src/
│   │   ├── pages/      # React components
│   │   └── App.jsx     # Router
│   └── dist/          # Built files
├── scripts/
│   ├── deploy.sh       # Build & push to GitHub
│   └── setup.sh        # Server setup
└── README.md
```

## Image Upload

Use the included script to upload images to Qiniu CDN:

```bash
export QINIU_ACCESS_KEY="your-key"
export QINIU_SECRET_KEY="your-secret"
export QINIU_BUCKET="your-bucket"
export QINIU_DOMAIN="your-domain.com"

node scripts/upload-image.js path/to/image.png
```

Then reference in Markdown: `![desc](https://cdn-url/image.png)`
