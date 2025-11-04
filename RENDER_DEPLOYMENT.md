# Render Deployment Instructions

## Environment Variables to Set on Render:

Go to your Render dashboard → Your Web Service → Environment tab and add these variables:

### Database Configuration:
```
DB_HOST=<your-production-database-host>
DB_USER=<your-production-database-user>
DB_PASSWORD=<your-production-database-password>
DB_NAME=<your-production-database-name>
```

### JWT Configuration:
```
JWT_SECRET=69c79aedc19fe39368c06b600d4941225f2fad9554d7ea6c5879ee971bd1dffe
JWT_REFRESH_SECRET=<generate-a-different-secret>
```

### Email Configuration:
```
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=465
EMAIL_SECURE=true
EMAIL_USER=api245481@gmail.com
EMAIL_PASS=qmpcvwpsmkslpiky
EMAIL_FROM="GWC HRMS" <api245481@gmail.com>
```

### Node Environment:
```
NODE_ENV=production
```

## Database Options for Render:

### Option 1: Render PostgreSQL (Recommended)
- Go to Render Dashboard → Add New → PostgreSQL
- Create a new PostgreSQL database
- Copy the connection details to your environment variables
- You'll need to migrate your MySQL schema to PostgreSQL

### Option 2: External MySQL Database
- Use services like:
  - PlanetScale (MySQL-compatible)
  - Railway (MySQL support)
  - AWS RDS MySQL
  - Google Cloud SQL MySQL

### Option 3: Quick Test with SQLite (Development Only)
- Modify your app to use SQLite for testing
- Not recommended for production

## Troubleshooting Steps:

1. **Check Render Logs:**
   - Go to Render Dashboard → Your Service → Logs
   - Look for startup errors

2. **Test Health Endpoint:**
   - Visit: `https://your-app.onrender.com/health`
   - This will show database connection status

3. **Common Issues:**
   - Missing environment variables
   - Database connection timeout
   - Incorrect database credentials
   - Network connectivity issues

## Quick Fix for Testing:

If you just want to get the server running without database:
1. Set all DB_* environment variables on Render (even with dummy values)
2. The server will now start even if database connection fails
3. Use the /health endpoint to monitor status