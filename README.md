# HR API

Express + MySQL + Socket.IO server.

## Requirements
- Node.js 18+ (for global `fetch`) on Ubuntu (use nvm or apt)
- MySQL server (5.7+; MySQL 8 recommended for recursive CTE features)

## Configuration
Copy `.env.example` to `.env` and set values:

- `PORT`: default 5000
- `FRONTEND_URL`: your web app origin
- `JWT_SECRET`: long random string
- `DB_*`: MySQL connection
- `USER_SERVICE_URL` (optional): if using external user lookup
- `ALLOWED_ORIGINS`: comma-separated list (e.g., `capacitor://localhost,ionic://localhost`)
- `CORS_ALLOW_ALL`: set to `true` to allow any origin (dev only)
- `ALLOWED_ORIGIN_REGEX`: optional regex to match origins (e.g., `.*\\.ngrok-free\\.app$`)

## Install & Run
```bash
# install deps
npm ci

# run in dev (auto-restart)
npm run dev

# run in production
NODE_ENV=production npm start
```

## Systemd service (Ubuntu)
Create `/etc/systemd/system/hrapi.service`:
```
[Unit]
Description=HR API
After=network.target

[Service]
Environment=NODE_ENV=production
EnvironmentFile=/var/www/hrapi/.env
WorkingDirectory=/var/www/hrapi
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=10
User=www-data
Group=www-data

[Install]
WantedBy=multi-user.target
```
Reload and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable hrapi
sudo systemctl start hrapi
sudo systemctl status hrapi
```

## Reverse proxy (Nginx example)
```
server {
  listen 80;
  server_name api.yourdomain.com;

  location / {
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Host $host;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade"; # for websockets
    proxy_pass http://127.0.0.1:5000;
  }
}
```

## Mobile access checklist
- Base URL:
  - Android emulator -> use `http://10.0.2.2:5000`
  - iOS simulator -> use your host machine IP (e.g., `http://192.168.1.10:5000`)
  - Physical devices -> same LAN IP and port as server
- HTTP vs HTTPS:
  - Android 9+ blocks cleartext HTTP by default; either use HTTPS (ngrok/SSL) or allow cleartext in network security config.
  - iOS ATS requires HTTPS or add an exception for your domain.
- CORS:
  - For WebView apps (Capacitor/Ionic), set `ALLOWED_ORIGINS` to include `capacitor://localhost` or `ionic://localhost`.
  - For native mobile fetch, Origin header is typically absent (server already allows no-origin requests).
- Firewalls/ports:
  - Ensure port 5000 is reachable or proxy via Nginx 80/443.
- Auth:
  - Send `Authorization: Bearer <token>` header for protected routes.

## File uploads
- Files are stored under `uploads/certificates/`
- Ensure the user running Node has read/write permission to this folder

## Notes
- `/attendance/calendar` requires MySQL 8+. If on MySQL 5.7, consider removing or replacing with JS date generation.
- The `POST /users` endpoint now generates an 8-char id automatically.
- Debug logging for 400/404 responses is enabled by default; consider gating by env var if too chatty in prod.
