#!/bin/bash
#
# Deploy Script - Build and push to GitHub
# Usage: ./scripts/deploy.sh
#

set -e

cd "$(dirname "$0")/.."

echo "=== Building frontend ==="
cd frontend
npm install
npm run build
cd ..

echo "=== Committing changes ==="
git add -A
git commit -m "Update blog content"
git push origin main

echo "=== Deploy complete ==="
echo "Now SSH to server and run: ./scripts/setup.sh"
