#!/usr/bin/env node
/**
 * Qiniu Image Uploader Script
 *
 * Usage:
 *   1. Set environment variables:
 *      export QINIU_ACCESS_KEY="your-access-key"
 *      export QINIU_SECRET_KEY="your-secret-key"
 *      export QINIU_BUCKET="your-bucket-name"
 *      export QINIU_DOMAIN="your-domain.com"  // without http://
 *
 *   2. Run script:
 *      node scripts/upload-image.js <image-file>
 *
 *   3. Or drag and drop:
 *      node scripts/upload-image.js
 *
 * Output: Qiniu CDN URL for the uploaded image
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Configuration from environment variables
const ACCESS_KEY = process.env.QINIU_ACCESS_KEY || '';
const SECRET_KEY = process.env.QINIU_SECRET_KEY || '';
const BUCKET = process.env.QINIU_BUCKET || '';
const DOMAIN = process.env.QINIU_DOMAIN || '';

// Get file path from command line or stdin
function getInputFile() {
  const args = process.argv.slice(2);
  if (args.length > 0) {
    return args[0];
  }

  // For drag-and-drop on Windows, read from stdin
  if (process.stdin.isTTY) {
    console.log('Usage: node upload-image.js <image-file>');
    process.exit(1);
  }

  return null;
}

// Generate upload token
function generateUploadToken() {
  const policy = {
    scope: BUCKET,
    deadline: Math.floor(Date.now() / 1000) + 3600, // 1 hour expiry
  };

  const policyJson = JSON.stringify(policy);
  const encodedPolicy = Buffer.from(policyJson).toString('base64url');

  const sign = crypto
    .createHmac('sha1', SECRET_KEY)
    .update(encodedPolicy)
    .digest('base64url');

  return `${ACCESS_KEY}:${encodedPolicy}:${sign}`;
}

// Upload file to Qiniu
function uploadToQiniu(filePath, fileData) {
  return new Promise((resolve, reject) => {
    const uploadToken = generateUploadToken();
    const key = path.basename(filePath);

    const boundary = '----FormBoundary' + Math.random().toString(36);
    const body = Buffer.concat([
      Buffer.from(`--${boundary}\r\n`),
      Buffer.from(`Content-Disposition: form-data; name="file"; filename="${key}"\r\n`),
      Buffer.from(`Content-Type: application/octet-stream\r\n\r\n`),
      fileData,
      Buffer.from(`\r\n--${boundary}\r\n`),
      Buffer.from(`Content-Disposition: form-data; name="key"\r\n\r\n`),
      Buffer.from(key + '\r\n'),
      Buffer.from(`--${boundary}--\r\n`),
    ]);

    const options = {
      hostname: 'upload.qiniup.com',
      path: '/',
      method: 'POST',
      headers: {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Authorization': `UpToken ${uploadToken}`,
        'Content-Length': body.length,
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const result = JSON.parse(data);
          if (result.error) {
            reject(new Error(result.error));
          } else {
            resolve(`https://${DOMAIN}/${result.key}`);
          }
        } catch (e) {
          reject(e);
        }
      });
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// Main function
async function main() {
  if (!ACCESS_KEY || !SECRET_KEY || !BUCKET || !DOMAIN) {
    console.error('Error: Missing required environment variables:');
    console.error('  QINIU_ACCESS_KEY');
    console.error('  QINIU_SECRET_KEY');
    console.error('  QINIU_BUCKET');
    console.error('  QINIU_DOMAIN');
    process.exit(1);
  }

  const input = getInputFile();

  if (!input) {
    console.error('Error: No input file specified');
    console.error('Usage: node upload-image.js <image-file>');
    process.exit(1);
  }

  const filePath = path.resolve(input);

  if (!fs.existsSync(filePath)) {
    console.error(`Error: File not found: ${filePath}`);
    process.exit(1);
  }

  const fileData = fs.readFileSync(filePath);

  try {
    const url = await uploadToQiniu(filePath, fileData);
    console.log(url);
  } catch (error) {
    console.error('Upload failed:', error.message);
    process.exit(1);
  }
}

main();
