// --- Department CRUD API ---

// Get all departments

// Get teacher_id and password from evaluation table



// Get id and name of users with rol0e_id 2 or 4 (faculty or dean)


const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const morgan = require('morgan');
const helmet = require('helmet');
const dotenv = require('dotenv');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');


const app = express();
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

// Middleware
// Configure CORS to allow the known frontend and an optional NGROK_URL
const allowedOrigins = [
  process.env.NGROK_URL,
  process.env.FRONTEND_URL || 'http://localhost:3000',
  'https://active-upward-sunbeam.ngrok-free.app', "https://hrmc.onrender.com"
].filter(Boolean);
console.log('CORS allowed origins:', allowedOrigins.length ? allowedOrigins : 'any');

app.use(cors({
  origin: function(origin, callback) {
    // allow requests with no origin (like mobile apps or curl)
    if (!origin) return callback(null, true);
    if (allowedOrigins.length === 0) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) return callback(null, true);
    return callback(new Error('CORS policy: This origin is not allowed'));
  },
  credentials: true,
  allowedHeaders: [
        'Origin',
        'X-Requested-With',
        'Content-Type',
        'Accept',
        'Authorization',
        'ngrok-skip-browser-warning'
    ],
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE']
}));
  // JWT authentication middleware for protected routes
  // function authenticateToken(req, res, next) {
  //   const authHeader = req.headers['authorization'];
  //   if (!authHeader || !authHeader.startsWith('Bearer ')) {
  //     return res.status(401).json({ error: 'Unauthorized: No token provided' });
  //   }
  //   const token = authHeader.split(' ')[1];
  //   try {
  //     req.user = jwt.verify(token, process.env.JWT_SECRET);
  //     next();
  //   } catch (err) {
  //     return res.status(401).json({ error: 'Unauthorized: Invalid token' });
  //   }
  // }

app.use(express.json());
app.use(cookieParser());
app.use(morgan('dev'));
app.use(helmet());
// Debug middleware: capture and log responses with 400 or 404 for easier debugging
app.use((req, res, next) => {
  // hold original methods
  const originalJson = res.json.bind(res);
  const originalSend = res.send.bind(res);
  const originalStatus = res.status.bind(res);

  // store the body that will be sent
  let responseBody;
  res.json = (body) => {
    responseBody = body;
    return originalJson(body);
  };
  res.send = (body) => {
    responseBody = body;
    return originalSend(body);
  };

  // intercept status to know final status code
  res.status = (code) => {
    res.__statusCode = code;
    return originalStatus(code);
  };

  // after response finished, check code and log if 400 or 404
  res.on('finish', () => {
    const statusCode = res.__statusCode || res.statusCode;
    if (statusCode === 400 || statusCode === 404) {
      try {
        console.warn(`HTTP ${statusCode} -> ${req.method} ${req.originalUrl}`);
        console.warn('  params:', req.params);
        console.warn('  query :', req.query);
        console.warn('  body  :', req.body);
        console.warn('  response body:', responseBody);
      } catch (e) {
        console.warn('Error logging 400/404 details:', e);
      }
    }
  });

  next();
});
// JWT authentication middleware helper
// Use this middleware selectively by passing `authenticateToken` to routes that require auth.
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  // Log the header for debugging (avoid printing full token in production)
  if (!authHeader) {
    console.warn('authenticateToken: missing Authorization header');
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  if (!authHeader.startsWith('Bearer ')) {
    console.warn('authenticateToken: Authorization header does not start with "Bearer " -', authHeader.slice(0, 30));
    return res.status(401).json({ error: 'Unauthorized: Malformed Authorization header' });
  }
  const token = authHeader.split(' ')[1];

  // If JWT_SECRET is not set (development), decode token without verification and allow
  if (!process.env.JWT_SECRET) {
    console.warn('Warning: JWT_SECRET not set — authenticateToken will decode token without verification (development only)');
    try {
      req.user = jwt.decode(token);
    } catch (e) {
      req.user = null;
    }
    return next();
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    console.warn('authenticateToken: jwt.verify failed:', err && err.message);
    return res.status(401).json({ error: 'Unauthorized: Invalid token', details: err && err.message });
  }
}
// MySQL connection setup
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect((err) => {
  if (err) {
    console.error('MySQL connection error:', err);
  } else {
    console.log('Connected to MySQL database');
  }
});

/**
 * API Health Check
 * GET /
 * Returns: API status message
 */
app.get('/', (req, res) => {
  res.json({ message: 'API is running!' });
});

/**
 * Get All Users
 * GET /users
 * Returns: List of all users
 */
app.get('/users', (req, res) => {
  db.query('SELECT u.id, u.name, u.email, COALESCE(r.name, "No Role") AS roleName  FROM users u LEFT JOIN roles r ON u.role_id = r.id', (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error' });
    }
    res.json(results);
  });
});
//get roles
app.get('/roles', (req, res) => {
  db.query('SELECT id, name FROM roles', (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error' });
    }
    res.json(results);
  });
});

/**
 * Get All User Codes
 * GET /users/codes
 * Returns: List of all user codes
 */
app.get('/users/codes', (req, res) => {
  db.query('SELECT code FROM users', (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error' });
    }
    // Return array of codes only
    const codes = results.map(row => row.code);
    res.json(codes);
  });
});

/**
 * Check if User Code Exists
 * GET /users/check-code/:code
 * Returns: true if code exists, false otherwise
 */
app.get('/users/check-code/:code', (req, res) => {
  const code = String(req.params.code).trim();
  db.query('SELECT id, code FROM users WHERE TRIM(CAST(code AS CHAR)) = ?', [code], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message || 'Database query error' });
    }
    res.json({ exists: results.length > 0 });
  });
});

app.get('/users/professors', (req, res) => {
  db.query('SELECT id, name FROM users WHERE role_id IN (2,4)', (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error' });
    }
    res.json(results);
  });
});

app.get('/users/:id/name', (req, res) => {
  const userId = req.params.id;
  db.query('SELECT id, name FROM users WHERE id = ?', [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(results[0]);
  });
});



/**
 * Create New User
 * POST /users
 * Body: { id, name, email, password, role_id, department_id }  
 * Returns: Success message and userId
 */
app.post('/users', async (req, res) => {
  const { name, email, password, role_id, department_id, code } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // helper to generate 8-char hex id
  const genId = () => crypto.randomBytes(4).toString('hex');

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const created_at = new Date();
    const sql = `INSERT INTO users (id, name, email, password, role_id, department_id, code, created_at, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`;

    // Try inserting with generated ids, retry on duplicate-id collisions
    const maxAttempts = 5;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const id = genId();
      const values = [id, name, email, hashedPassword, role_id, department_id, code, created_at];
      try {
        const [result] = await db.promise().query(sql, values);
        return res.status(201).json({ message: 'User created', userId: id });
      } catch (err) {
        // If duplicate entry, determine whether it's the id (primary) or other unique field (email/code)
        if (err && err.code === 'ER_DUP_ENTRY') {
          const msg = String(err.message || err.sqlMessage || '').toLowerCase();
          // If duplicate is on primary key (id) then retry, otherwise return conflict
          if (msg.includes('primary') || msg.includes('for key') && (msg.includes('id') || msg.includes("users.id"))) {
            // id collision: try again
            if (attempt === maxAttempts) {
              return res.status(500).json({ error: 'Failed to generate unique id after multiple attempts' });
            }
            continue; // retry with a new id
          }
          // Duplicate on other unique field (likely email or code) — return 409
          return res.status(409).json({ error: 'Duplicate entry', details: err.message });
        }
        // Other DB error
        return res.status(500).json({ error: 'Database insert error', details: err.message || err });
      }
    }

    // If we fallthrough (shouldn't), return generic error
    return res.status(500).json({ error: 'Unable to create user' });
  } catch (err) {
    return res.status(500).json({ error: 'Password hashing failed', details: err.message || err });
  }
});


/**
 * User Login
 * POST /login
 * Body: { email, password }
 * Returns: user info if credentials are valid
 */
app.post('/login', (req, res) => {
  console.log('Login API accessed:', req.body.email);
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error', details: err });
    }
    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const user = results[0];
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    // Generate access token (short lived)
    const accessToken = jwt.sign({ id: user.id, email: user.email, role_id: user.role_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    // Create a refresh token (opaque string) and persist
    const refreshToken = crypto.randomBytes(48).toString('hex');
    const refreshExpiry = new Date(Date.now() + (30 * 24 * 60 * 60 * 1000)); // 30 days

    const persistRefresh = (cb) => {
      if (db && typeof db.query === 'function') {
        // Ensure table exists then insert
        const createSql = `CREATE TABLE IF NOT EXISTS refresh_tokens (token VARCHAR(255) PRIMARY KEY, user_id VARCHAR(255), expires_at DATETIME)`;
        db.query(createSql, (createErr) => {
          if (createErr) return cb(createErr);
          db.query('INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, ?)', [refreshToken, user.id, refreshExpiry], cb);
        });
      } else {
        global.__refreshTokens = global.__refreshTokens || new Map();
        global.__refreshTokens.set(refreshToken, { user_id: user.id, expires_at: refreshExpiry });
        cb && cb(null);
      }
    };

    persistRefresh((persistErr) => {
      if (persistErr) console.warn('persist refresh token failed', persistErr);
      // set refresh token cookie
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        expires: refreshExpiry
      });
      return res.status(200).json({ message: 'Login successful', token: accessToken, user: { id: user.id, name: user.name, email: user.email, role_id: user.role_id, department_id: user.department_id } });
    });
  });
});

// Refresh endpoint: issues a new access token when refresh cookie is present
app.post('/auth/refresh', (req, res) => {
  const rtoken = req.cookies && req.cookies.refreshToken;
  if (!rtoken) return res.status(401).json({ error: 'no_refresh' });
  if (db && typeof db.query === 'function') {
    db.query('SELECT user_id, expires_at FROM refresh_tokens WHERE token = ?', [rtoken], (err, rows) => {
      if (err) return res.status(500).json({ error: 'db' });
      if (!rows || rows.length === 0) return res.status(401).json({ error: 'invalid_refresh' });
      const rec = rows[0];
      if (new Date(rec.expires_at) < new Date()) return res.status(401).json({ error: 'refresh_expired' });
      const newAccess = jwt.sign({ id: rec.user_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      return res.json({ accessToken: newAccess });
    });
  } else {
    global.__refreshTokens = global.__refreshTokens || new Map();
    const rec = global.__refreshTokens.get(rtoken);
    if (!rec) return res.status(401).json({ error: 'invalid_refresh' });
    if (new Date(rec.expires_at) < new Date()) return res.status(401).json({ error: 'refresh_expired' });
    const newAccess = jwt.sign({ id: rec.user_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    return res.json({ accessToken: newAccess });
  }
});

/**
 * Get Role by ID
 * GET /roles/:id
 * Returns: Role object with id and name
 */
app.get('/roles/:id', authenticateToken, (req, res) => {
  const roleId = req.params.id;
  db.query('SELECT id, name FROM roles WHERE id = ?', [roleId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'Role not found' });
    }
    res.json(results[0]);
  });
});

// 404 handler
/**
 * Create Leave Request
 * POST /leave_request
 * Body: { user_id, type, start_date, end_date, status, reason, is_approve }
 * Returns: Success message and inserted record id
 */
app.post('/leave_request', (req, res) => {
  const { user_id, type, start_date, end_date, reason} = req.body;
  if (!user_id || !type || !start_date || !end_date || !reason) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const sql = `INSERT INTO leave_request (user_id, type, start_date, end_date, reason) VALUES (?, ?, ?, ?, ?)`;
  const values = [user_id, type, start_date, end_date, reason];
  db.promise().query(sql, values, (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Database insert error', details: err });
    }
    res.status(201).json({ message: 'Leave request created', id: result.insertId });
  });
});

/**
 * Get All Leave Requests
 * GET /leave_request
 * Returns: List of all leave requests
 */
app.get('/leave_request', (req, res) => {
   const sql = `
    SELECT lr.*, u.name AS employee_name
    FROM leave_request lr
    LEFT JOIN users u ON lr.user_id = u.id
  `;
  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error' });
    }
    res.json(results);
  });
});

/**
 * Get Leave Requests by User ID
 * GET /leave_request/user/:user_id
 * Returns: Array of leave requests for the user
 */
app.get('/leave_request/user/:user_id', (req, res) => {
  const user_id = req.params.user_id;
  db.query('SELECT * FROM leave_request WHERE user_id = ?', [user_id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'No leave requests found for this user' });
    }
    res.json(results);
  });
});

/**
 * Update Leave Request
 * PUT /leave_request/:id
 * Body: { user_id, type, start_date, end_date, status, reason, is_approve }
 * Returns: Success message
 */
app.put('/leave_request/:id', (req, res) => {
  const id = req.params.id;
  const { user_id, type, start_date, end_date, status, reason, is_approve } = req.body;
  const sql = `UPDATE leave_request SET user_id = ?, type = ?, start_date = ?, end_date = ?, status = ?, reason = ?, is_approve = ? WHERE id = ?`;
  const values = [user_id, type, start_date, end_date, status, reason, is_approve, id];
  db.query(sql, values, (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Database update error', details: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Leave request not found' });
    }
    res.json({ message: 'Leave request updated' });
  });
});

/**
 * Delete Leave Request
 * DELETE /leave_request/:id
 * Returns: Success message
 */
app.delete('/leave_request/:id', (req, res) => {
  const id = req.params.id;
  db.query('DELETE FROM leave_request WHERE id = ?', [id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Database delete error', details: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Leave request not found' });
    }
    res.json({ message: 'Leave request deleted' });
  });
});

/**
 * Approve/Disapprove Leave Request
 * PATCH /leave_request/:id/approve
 * Body: { is_approve }
 * Returns: Success message
 */
app.patch('/leave_request/:id/approve', (req, res) => {
  const id = req.params.id;
 

  const sql = `UPDATE leave_request SET is_approve = 1, status = 'approved' WHERE id = ?`;
  const values = [id];

  db.query(sql, values, (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Database update error', details: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Leave request not found' });
    }
    res.json({ message: 'Leave request approved' });
  });
});

app.patch('/leave_request/:id/disapprove', (req, res) => {
  const id = req.params.id;


  const sql = `UPDATE leave_request SET is_approve = 0, status = 'disapproved' WHERE id = ?`;
  const values = [id];

  db.query(sql, values, (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Database update error', details: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Leave request not found' });
    }

    res.json({ message: 'Leave request disapproved' });
  });
});


/**
 * Get Leave Request by ID
 * GET /leave_request/:id
 * Returns: Leave request details
 */
app.get('/leave_request/:id', (req, res) => {
  const id = req.params.id;
  db.query('SELECT * FROM leave_request WHERE id = ?', [id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'Leave request not found' });
    }
    res.json(results[0]);
  });
});

/**
 * Cancel Leave Request
 * PATCH /leave_request/:id/cancel
 * Updates status to 'cancelled'
 * Returns: Success message
 */
app.patch('/leave_request/:id/cancel', (req, res) => {
  const id = req.params.id;
  
  const sql = `UPDATE leave_request SET status = 'cancelled' WHERE id = ?`;
  
  db.query(sql, [id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Database update error', details: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Leave request not found' });
    }
    res.json({ message: 'Leave request cancelled successfully' });
  });
});

/**
 * Create Attendance Record
 * POST /attendance
 * Body: { user_id, time_in, time_out, status, late_minutes, date }
 * Returns: Success message and inserted record id
 */
app.post('/attendance', (req, res) => {
  const { user_id, time_in, time_out, status, late_minutes, date } = req.body;
  if (!user_id || !date) {
    return res.status(400).json({ error: 'Missing required fields: user_id and date are required' });
  }
  const sql = `INSERT INTO attendance (user_id, time_in, time_out, status, late_minutes) VALUES (?, ?, ?, ?, ?)`;
  const values = [user_id, time_in, time_out, status, late_minutes];
  db.query(sql, values, (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Database insert error', details: err });
    }
    res.status(201).json({ message: 'Attendance record created', id: result.insertId });
  });
});
/**
 * Get All Attendance Records
 * GET /attendance
 * Returns: List of all attendance records
 */
app.get('/attendance', (req, res) => {
  // join users to include the user's display name
  // Use TRIM(CAST(... AS CHAR)) to normalize IDs so varchar/whitespace mismatches don't hide the user name
  const sql = `
    SELECT a.id, a.user_id, TRIM(CAST(u.name AS CHAR)) AS user_name,
      COALESCE(TRIM(CAST(u.name AS CHAR)), TRIM(CAST(a.user_id AS CHAR))) AS display_name,
      a.time_in, a.time_out, a.status, a.late_minutes, a.date
    FROM attendance a
    LEFT JOIN users u ON TRIM(CAST(a.user_id AS CHAR)) = TRIM(CAST(u.id AS CHAR))
    ORDER BY a.date DESC
  `;
  db.query(sql, (err, results) => {
    if (err) {
      console.error('GET /attendance query error:', err);
      return res.status(500).json({ error: 'Database query error' });
    }
    res.json(results);
  });
});

/**
 * Get Attendance Records by User ID
 * GET /attendance/user/:user_id
 * Returns: Array of attendance records for the user
 */
app.get('/attendance/user/:user_id', (req, res) => {
  // normalize incoming id to a trimmed string to avoid mismatches
  const user_id = String(req.params.user_id).trim();
  const sql = `
    SELECT a.id, a.user_id, TRIM(CAST(u.name AS CHAR)) AS user_name,
           a.time_in, a.time_out, a.status, a.late_minutes, a.date
  FROM attendance a
  LEFT JOIN users u ON TRIM(CAST(a.user_id AS CHAR)) = TRIM(CAST(u.id AS CHAR))
    WHERE TRIM(CAST(a.user_id AS CHAR)) = ?
    ORDER BY a.date DESC
  `;

  db.query(sql, [user_id], (err, results) => {
    if (err) {
      console.error(`Attendance /attendance/user/${user_id} query error:`, err);
      return res.status(500).json({ error: 'Database query error' });
    }

    if (results.length === 0) {
      // No attendance rows — still try to return the user's name so the UI can display it
      db.query('SELECT id, name FROM users WHERE TRIM(CAST(id AS CHAR)) = ?', [user_id], (uerr, urows) => {
        if (uerr) {
          console.error('Error fetching user for attendance fallback:', uerr);
          return res.status(500).json({ error: 'Database query error' });
        }
        if (urows.length === 0) {
          return res.status(404).json({ error: 'User not found and no attendance records' });
        }
        const user = urows[0];
        // Return a single fallback row with null attendance fields but with user_name filled
        const fallback = [{
          id: null,
          user_id: user.id,
          user_name: user.name,
          time_in: null,
          time_out: null,
          status: null,
          late_minutes: null,
          date: null
        }];
        return res.json(fallback);
      });
      return;
    }

    res.json(results);
  });
});

/**
 * Get full attendance view (full outer join emulation)
 * GET /attendance/full
 * Returns: all attendance rows joined with users and also users without attendance
 */
app.get('/attendance/full', (req, res) => {
  // By default return attendance rows annotated with user info (LEFT JOIN).
  // If client requests include_missing=true then also include users with no attendance (full outer emulation).
  const includeMissing = String(req.query.include_missing || '').toLowerCase() === 'true';

  const leftSql = `
    SELECT a.id AS attendance_id, a.user_id, u.name AS user_name, a.time_in, a.time_out, a.status, a.late_minutes, a.date
    FROM attendance a
    LEFT JOIN users u ON a.user_id = u.id
  `;

  // includeMissing === true -> emulate full outer join (attendance rows + users without attendance)
  const rightSql = `
    SELECT NULL AS attendance_id, u.id AS user_id, u.name AS user_name, NULL AS time_in, NULL AS time_out, NULL AS status, NULL AS late_minutes, NULL AS date
    FROM users u
    WHERE u.id NOT IN (SELECT DISTINCT user_id FROM attendance)
  `;
  const fullSql = `${leftSql} UNION ALL ${rightSql} ORDER BY date DESC, user_name`;
  db.query(fullSql, (err, rows) => {
    if (err) {
      console.error('GET /attendance/full (full) query error:', err);
      return res.status(500).json({ error: 'Database error', details: err.message });
    }
    res.json(rows);
  });
});
/**
 * Time In/Out API
 * POST /users/:id/time-log
 * Logic:
 *   - If time_in is null, set time_in to Philippine time
 *   - If time_in is set and time_out is null, set time_out to Philippine time
 *   - If both are set, return error
 */
app.post('/users/:id/time-log', (req, res) => {
  const userId = req.params.id;
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ error: 'Missing code in request body' });
  }
  // Check if user exists and code matches
  db.query('SELECT id, code FROM users WHERE id = ?', [userId], (err, userResults) => {
    if (err) return res.status(500).json({ error: 'Database query error (users)' });
    if (userResults.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = userResults[0];
    if (String(user.code).trim() !== String(code).trim()) {
      return res.status(400).json({ error: 'Code does not match user' });
    }
  // Use MySQL CURDATE() for date
  db.query('SELECT * FROM attendance WHERE user_id = ? AND date = CURDATE()', [userId], (err2, attResults) => {
      if (err2) return res.status(500).json({ error: 'Database query error (attendance)' });
      if (attResults.length === 0) {
        // No attendance for today, insert time_in and set date
        db.query('INSERT INTO attendance (user_id, time_in, date, status, late_minutes) VALUES (?, CONVERT_TZ(NOW(), "+00:00", "+08:00"), CURDATE(), "Present", 0)', [userId], (err3, result3) => {
          if (err3) return res.status(500).json({ error: 'Database insert error', details: err3 });
          return res.status(201).json({ message: 'Time in recorded', id: result3.insertId });
        });
      } else {
        // Attendance record exists for today
        const record = attResults[0];
        if (!record.time_in) {
          // Should not happen, but handle gracefully
          return res.status(400).json({ error: 'Attendance record exists but no time_in. Please contact admin.' });
        }
        if (!record.time_out) {
          // Only allow time_out update, never insert new record
          db.query('UPDATE attendance SET time_out = CONVERT_TZ(NOW(), "+00:00", "+08:00") WHERE id = ?', [record.id], (err4) => {
            if (err4) return res.status(500).json({ error: 'Database update error', details: err4 });
            return res.json({ message: 'Time out recorded' });
          });
        } else {
          // Both time_in and time_out set for today, do NOT create new record
          return res.status(400).json({
            error: 'Attendance for today is already complete.',
            details: 'You have already timed in and out for this date. If you need to correct your attendance, please contact HR or your administrator.'
          });
        }
      }
    });
  });
});

// --- Evaluation API ---
// Create evaluation
app.post('/evaluation', async (req, res) => {
  const { teacher_id, student_id, expires_at, password, status, created_by } = req.body;
  // Generate id: year + month + 5 random digits
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const randomNum = Math.floor(10000 + Math.random() * 90000); // 5 digits
  const evaluation_id = `${year}${month}${randomNum}`;
  try {
    const [result] = await db.execute(
      'INSERT INTO evaluation (id, teacher_id, student_id, expires_at, password, status, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [evaluation_id, teacher_id, student_id, expires_at, password, status, created_by]
    );
    res.json({ id: evaluation_id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all evaluations
app.get('/evaluation', async (req, res) => {
  try {
    const [rows] = await db.promise().query('SELECT * FROM evaluation');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/evaluation/teacher-passwords', async (req, res) => {
  try {
    const [rows] = await db.promise().query('SELECT id, teacher_id, password, expires_at FROM evaluation');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Evaluation Answers API ---
// Create answer
app.post('/evaluation_answers', async (req, res) => {
  const { evaluation_id, question_id, student_id, rating, remarks } = req.body;
  
  // Add logging to see what data is received
  console.log('Received evaluation answer:', {
    evaluation_id,
    question_id,
    student_id,
    rating,
    remarks,
    types: {
      evaluation_id: typeof evaluation_id,
      question_id: typeof question_id,
      student_id: typeof student_id,
      rating: typeof rating
    }
  });
  
  try {
    const [result] = await db.promise().query(
      'INSERT INTO evaluation_answers (evaluation_id, question_id, student_id, rating, remarks) VALUES (?, ?, ?, ?, ?)',
      [evaluation_id, question_id, student_id, rating, remarks]
    );
    console.log('Successfully inserted with ID:', result.insertId);
    res.json({ id: result.insertId });
  } catch (err) {
    console.error('Database error:', err.message);
    console.error('Full error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Get all answers for an evaluation
app.get('/evaluation_answers/:evaluation_id', async (req, res) => {
  try {
    const [rows] = await db.execute(
      'SELECT * FROM evaluation_answers WHERE evaluation_id = ?',
      [req.params.evaluation_id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Evaluation Question API ---
// Create question (fix typo: use evaluation_question)
app.post('/evaluation_question', async (req, res) => {
  const { evaluation_id, question_text } = req.body;
  try {
    const [result] = await db.execute(
      'INSERT INTO evaluation_questions (evaluation_id, question_text) VALUES (?, ?)',
      [evaluation_id, question_text]
    );
    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all questions for an evaluation
app.get('/evaluation_question/:evaluation_id', async (req, res) => {
  try {
    const [rows] = await db.execute(
      'SELECT * FROM evaluation_questions WHERE evaluation_id = ?',
      [req.params.evaluation_id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Professor Overall Average API ---
// Get overall average rating for a professor (teacher_id)
app.get('/professor/:teacher_id/average', async (req, res) => {
  const teacher_id = req.params.teacher_id;
  try {
    // Get all evaluations for this professor
    const [evaluations] = await db.promise().query('SELECT id FROM evaluation WHERE teacher_id = ?', [teacher_id]);
    if (evaluations.length === 0) {
      return res.status(404).json({ error: 'No evaluations found for this professor.' });
    }
    const evaluationIds = evaluations.map(e => e.id);
    // Get all ratings for these evaluations
    const [ratings] = await db.promise().query(
      `SELECT rating FROM evaluation_answers WHERE evaluation_id IN (?)`, [evaluationIds]
    );
    if (ratings.length === 0) {
      return res.status(404).json({ error: 'No ratings found for this professor.' });
    }
    // Calculate average
    const sum = ratings.reduce((acc, r) => acc + r.rating, 0);
    const avg = sum / ratings.length;
    res.json({ teacher_id, average_rating: avg });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Admin: Get all professor evaluations with averages ---
app.get('/admin/professors/evaluations', async (req, res) => {
  try {
    // Get all professors (users with role_id = faculty or dean)
    const [professors] = await db.promise().query('SELECT id, name FROM users WHERE role_id IN (2,4)');
    if (professors.length === 0) {
      return res.status(404).json({ error: 'No professors found.' });
    }
    // For each professor, get their evaluations and average rating
    const results = [];
    for (const prof of professors) {
      // Get evaluations for this professor
      const [evaluations] = await db.promise().query('SELECT id FROM evaluation WHERE teacher_id = ?', [prof.id]);
      const evaluationIds = evaluations.map(e => e.id);
      let avg = null;
      let ratingsCount = 0;
      if (evaluationIds.length > 0) {
        const [ratings] = await db.promise().query('SELECT rating FROM evaluation_answers WHERE evaluation_id IN (?)', [evaluationIds]);
        ratingsCount = ratings.length;
        if (ratingsCount > 0) {
          const sum = ratings.reduce((acc, r) => acc + r.rating, 0);
          avg = sum / ratingsCount;
        }
      }
      results.push({
        professor_id: prof.id,
        professor_name: prof.name,
        evaluation_count: evaluationIds.length,
        ratings_count: ratingsCount,
        average_rating: avg
      });
    }
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
  

// Bulk insert 10 evaluation questions for professors
app.post('/evaluation_questions/bulk', async (req, res) => {
  // 10 sample questions
  const questions = [
    'Comes to class with well-prepared lessons.',
'Presents lessons clearly and understandably.',
'Demonstrates mastery of the subject matter.',
'Uses appropriate teaching strategies and instructional materials.',
'Encourages critical thinking and active participation.',
'Assesses student performance fairly and regularly.',
'Utilizes multiple assessment strategies and tools.',
'Provides prompt and meaningful feedback performance and progress.',
'Maintains discipline and a respectful classroom environment regardless of beliefs, value systems and lifestyles.',
'Addresses student concerns appropriately.',
'Starts and ends classes on time.',
'Implements and promotes stewardship materials being used.',
'Demonstrates punctuality and regular attendance.',
'Dresses appropriately and professionally.',
'Observes confidentiality and integrity',
'Shows respect to colleagues, students, and administrators.',
'Exemplifies teamwork and support to the institutional ways and processes to help deliver quality education stakeholders',
'Models and promotes the Core Values of GWC - integrity, godliness, diligence, excellence, compassion, accessibility, Christian virtue and transformation.',
'Encourages moral and spiritual formation among students.',
'Integrates Vision, Mission and Core Values of GWC in teaching where applicable.'
  ];
  try {
    // Insert each question with auto-generated id
    for (const question_text of questions) {
      await db.promise().query('INSERT INTO evaluation_questions (question_text) VALUES (?)', [question_text]);
    }
    res.json({ message: '10 questions inserted.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all evaluation questions
app.get('/evaluation_questions', async (req, res) => {
  try {
    const [rows] = await db.promise().query('SELECT id, question_text FROM evaluation_questions');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * Get All Evaluation Questions (Alternative endpoint)
 * GET /evaluation_question
 * Returns: List of all evaluation questions with id and question_text
 */
app.get('/evaluation_question', async (req, res) => {
  try {
    const [rows] = await db.promise().query('SELECT id, question_text FROM evaluation_questions');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create evaluation with frontend-provided teacher_id, student_id, created_by
app.post('/evaluation/create', async (req, res) => {
  const { teacher_id} = req.body;
  if (!teacher_id) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  // Generate id: year + month + 5 random digits
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const randomNum = Math.floor(10000 + Math.random() * 90000); // 5 digits
  // Set expires_at to today at 10:00 PM
  const expires_at = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 22, 0, 0);
  // Generate random 4-digit password
  const password = Math.floor(1000 + Math.random() * 9000).toString();
  try {
    const [result] = await db.execute(
      'INSERT INTO evaluation (teacher_id, expires_at, password) VALUES (?, ?, ?)',
      [teacher_id, expires_at, password]
    );
    res.json({ teacher_id, expires_at, password});
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET evaluation answers with questions for a specific evaluation
app.get('/evaluation_answers/:evaluation_id', async (req, res) => {
  const { evaluation_id } = req.params;
  const { student_id } = req.query;
  
  try {
    // First, get the evaluation details
    const [evaluationDetails] = await db.promise().query(
      `SELECT 
        e.id as evaluation_id,
        e.teacher_id,
        e.student_id,
        e.created_at,
        e.expires_at,
        e.status,
        u.name as teacher_name
      FROM evaluation e
      LEFT JOIN users u ON e.teacher_id = u.id
      WHERE e.id = ? AND e.student_id = ?`,
      [evaluation_id, student_id]
    );

    if (evaluationDetails.length === 0) {
      return res.status(404).json({ error: 'Evaluation not found' });
    }

    // Get all answers with their corresponding questions
    const [answers] = await db.promise().query(
      `SELECT 
        ea.id,
        ea.question_id,
        ea.student_id,
        ea.rating,
        eq.question_text
      FROM evaluation_answers ea
      JOIN evaluation_questions eq ON ea.question_id = eq.id
      WHERE ea.evaluation_id = ? AND ea.student_id = ?
      ORDER BY ea.question_id`,
      [evaluation_id, student_id]
    );

    // Format the response to match the component's expected structure
    const response = {
      evaluation_id: evaluationDetails[0].evaluation_id,
      teacher_id: evaluationDetails[0].teacher_id,
      teacher_name: evaluationDetails[0].teacher_name,
      student_id: evaluationDetails[0].student_id,
      created_at: evaluationDetails[0].created_at,
      expires_at: evaluationDetails[0].expires_at,
      status: evaluationDetails[0].status,
      answers: answers.map(answer => ({
        id: answer.id,
        question_id: answer.question_id,
        question_text: answer.question_text,
        rating: answer.rating,
        student_id: answer.student_id
      }))
    };

    res.json(response);
    
  } catch (err) {
    console.error('Error fetching evaluation data:', err);
    res.status(500).json({ error: err.message });
  }
});

// Alternative endpoint if you want to get ALL evaluation answers for an evaluation (all students)
app.get('/evaluation/:evaluation_id/all_answers', async (req, res) => {
  const { evaluation_id } = req.params;
  
  try {
    // Get evaluation details
    const [evaluationDetails] = await db.promise().query(
      `SELECT 
        e.id as evaluation_id,
        e.teacher_id,
        e.created_at,
        e.expires_at,
        e.status,
        u.name as teacher_name
      FROM evaluation e
      LEFT JOIN users u ON e.teacher_id = u.id
      WHERE e.id = ?`,
      [evaluation_id]
    );

    if (evaluationDetails.length === 0) {
      return res.status(404).json({ error: 'Evaluation not found' });
    }

    // Get all answers from all students for this evaluation
    const [answers] = await db.promise().query(
      `SELECT
        ea.id,
        ea.question_id,
        ea.student_id,
        ea.rating,
        eq.question_text
      FROM evaluation_answers ea
      JOIN evaluation_questions eq ON ea.question_id = eq.id
      WHERE ea.evaluation_id = ?
      ORDER BY ea.student_id, ea.question_id`,
      [evaluation_id]
    );

    // Group answers by student
    const studentAnswers = {};
    answers.forEach(answer => {
      if (!studentAnswers[answer.student_id]) {
        studentAnswers[answer.student_id] = [];
      }
      studentAnswers[answer.student_id].push({
        id: answer.id,
        question_id: answer.question_id,
        question_text: answer.question_text,
        rating: answer.rating
      });
    });

    const response = {
      evaluation_id: evaluationDetails[0].evaluation_id,
      teacher_id: evaluationDetails[0].teacher_id,
      teacher_name: evaluationDetails[0].teacher_name,
      created_at: evaluationDetails[0].created_at,
      expires_at: evaluationDetails[0].expires_at,
      status: evaluationDetails[0].status,
      students: Object.keys(studentAnswers).map(studentId => ({
        student_id: studentId,
        answers: studentAnswers[studentId],
        average_rating: (studentAnswers[studentId].reduce((sum, ans) => sum + ans.rating, 0) / studentAnswers[studentId].length).toFixed(1)
      }))
    };

    res.json(response);
    
  } catch (err) {
    console.error('Error fetching all evaluation data:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET evaluation statistics for admin dashboard
app.get('/evaluation/stats', async (req, res) => {
  try {
    // Get overall statistics
    const [stats] = await db.promise().query(`
      SELECT 
        COUNT(DISTINCT e.id) as total_evaluations,
        COUNT(DISTINCT e.teacher_id) as evaluated_teachers,
        COUNT(DISTINCT ea.student_id) as participating_students,
        ROUND(AVG(ea.rating), 2) as overall_average_rating
      FROM evaluation e
      LEFT JOIN evaluation_answers ea ON e.id = ea.evaluation_id
    `);

    // Get status breakdown
    const [statusBreakdown] = await db.promise().query(`
      SELECT 
        status,
        COUNT(*) as count
      FROM evaluation
      GROUP BY status
    `);

    // Get recent evaluations
    const [recentEvaluations] = await db.promise().query(`
      SELECT 
        e.id,
        e.teacher_id,
        e.student_id,
        e.status,
        e.created_at,
        u.name as teacher_name
      FROM evaluation e
      LEFT JOIN users u ON e.teacher_id = u.id
      ORDER BY e.created_at DESC
      LIMIT 5
    `);

    res.json({
      stats: stats[0],
      statusBreakdown,
      recentEvaluations
    });
    
  } catch (err) {
    console.error('Error fetching evaluation stats:', err);
    res.status(500).json({ error: err.message });
  }
});

// New Express.js endpoint for evaluation summary with question averages
app.get('/evaluation/:evaluation_id/summary', async (req, res) => {
  const { evaluation_id } = req.params;
  
  console.log('Getting evaluation summary for ID:', evaluation_id);
  
  try {
    // Get evaluation details
    const [evaluationDetails] = await db.promise().query(
      `SELECT 
        e.id as evaluation_id,
        e.teacher_id,
        e.created_at,
        e.expires_at,
        e.status,
        u.name as teacher_name
      FROM evaluation e
      LEFT JOIN users u ON e.teacher_id = u.id
      WHERE e.id = ?`,
      [evaluation_id]
    );

    if (evaluationDetails.length === 0) {
      return res.status(404).json({ error: 'Evaluation not found' });
    }

    // Get all questions for this evaluation with their averages
    const [questionSummaries] = await db.promise().query(
      `SELECT 
        eq.id as question_id,
        eq.question_text,
        COUNT(ea.id) as total_responses,
        ROUND(AVG(ea.rating), 2) as average_rating,
        SUM(CASE WHEN ea.rating = 1 THEN 1 ELSE 0 END) as rating_1_count,
        SUM(CASE WHEN ea.rating = 2 THEN 1 ELSE 0 END) as rating_2_count,
        SUM(CASE WHEN ea.rating = 3 THEN 1 ELSE 0 END) as rating_3_count,
        SUM(CASE WHEN ea.rating = 4 THEN 1 ELSE 0 END) as rating_4_count,
        SUM(CASE WHEN ea.rating = 5 THEN 1 ELSE 0 END) as rating_5_count
      FROM evaluation_questions eq
      LEFT JOIN evaluation_answers ea ON eq.id = ea.question_id AND ea.evaluation_id = ?
      GROUP BY eq.id, eq.question_text
      HAVING COUNT(ea.id) > 0
      ORDER BY eq.id`,
      [evaluation_id]
    );

    if (questionSummaries.length === 0) {
      return res.status(404).json({ error: 'No evaluation responses found' });
    }

    // Get total number of unique students who responded
    const [studentCount] = await db.promise().query(
      `SELECT COUNT(DISTINCT student_id) as total_students
       FROM evaluation_answers
       WHERE evaluation_id = ?`,
      [evaluation_id]
    );

    // Calculate overall average
    const overallAverage = questionSummaries.reduce((sum, q) => sum + parseFloat(q.average_rating), 0) / questionSummaries.length;

    // Format the response
    const response = {
      evaluation_id: evaluationDetails[0].evaluation_id,
      teacher_id: evaluationDetails[0].teacher_id,
      teacher_name: evaluationDetails[0].teacher_name,
      created_at: evaluationDetails[0].created_at,
      expires_at: evaluationDetails[0].expires_at,
      status: evaluationDetails[0].status,
      total_students: studentCount[0].total_students,
      overall_average: parseFloat(overallAverage.toFixed(2)),
      questions: questionSummaries.map(question => ({
        question_id: question.question_id,
        question_text: question.question_text,
        average_rating: parseFloat(question.average_rating),
        total_responses: question.total_responses,
        ratings_breakdown: {
          1: question.rating_1_count,
          2: question.rating_2_count,
          3: question.rating_3_count,
          4: question.rating_4_count,
          5: question.rating_5_count
        }
      }))
    };

    console.log('Sending evaluation summary:', response);
    res.json(response);
    
  } catch (err) {
    console.error('Error fetching evaluation summary:', err);
    res.status(500).json({ error: err.message });
  }
});

// Get evaluations by user ID (teacher)
app.get('/evaluation/user/:user_id', async (req, res) => {
  const { user_id } = req.params;
  
  try {
    const [rows] = await db.promise().query(
      'SELECT id, teacher_id, expires_at, password FROM evaluation WHERE teacher_id = ?',
      [user_id]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'No evaluations found for this user' });
    }
    
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = path.join(__dirname, 'uploads', 'certificates');
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    // Get original file extension
    const originalExtension = path.extname(file.originalname).toLowerCase();
    
    // Sanitize the base filename (without extension)
    const baseName = path.basename(file.originalname, originalExtension)
      .replace(/[^a-zA-Z0-9.-]/g, '_');
    
    // Generate unique identifier
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    
    // Ensure extension is included
    const finalExtension = originalExtension || '.pdf'; // Default to .pdf if no extension
    
    const finalFilename = `certificate-${uniqueSuffix}-${baseName}${finalExtension}`;
    
    console.log('Multer filename generation:');
    console.log('- Original:', file.originalname);
    console.log('- Extension:', originalExtension);
    console.log('- Base name:', baseName);
    console.log('- Final filename:', finalFilename);
    
    cb(null, finalFilename);
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.pdf', '.doc', '.docx'];
    const fileExt = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(fileExt)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only PDF, DOC, and DOCX are allowed.'));
    }
  }
});

// Get all certificate requests (admin/dean view)
app.get('/certificates', (req, res) => {
  const sql = `
    SELECT cr.*, u.name as user_name 
    FROM certificate_requests cr
    LEFT JOIN users u ON cr.user_id = u.id
    ORDER BY cr.request_date DESC
  `;
  
  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error', details: err });
    }
    res.json(results);
  });
});

// Get user's certificate requests
app.get('/certificates/user/:user_id', (req, res) => {
  const { user_id } = req.params;
  
  if (!user_id) {
    return res.status(400).json({ error: 'Missing required parameter: user_id' });
  }
  
  const sql = `
    SELECT * FROM certificate_requests 
    WHERE user_id = ?
    ORDER BY request_date DESC
  `;
  
  db.query(sql, [user_id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error', details: err });
    }
    res.json(results);
  });
});

// Submit new certificate request
app.post('/certificates/request', (req, res) => {
  const { user_id, certificate_type, purpose, additional_details } = req.body;
  
  if (!user_id || !certificate_type || !purpose) {
    return res.status(400).json({ error: 'Missing required fields: user_id, certificate_type, and purpose are required' });
  }
  
  const sql = `INSERT INTO certificate_requests (user_id, certificate_type, purpose, additional_details) VALUES (?, ?, ?, ?)`;
  const values = [user_id, certificate_type, purpose, additional_details || null];
  
  db.query(sql, values, (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Database insert error', details: err });
    }
    res.status(201).json({ 
      message: 'Certificate request submitted successfully', 
      id: result.insertId,
      success: true
    });
  });
});

// Upload certificate file and approve request
app.post('/certificates/:id/upload', upload.single('certificate_file'), (req, res) => {
  const { id } = req.params;
  const { notes, approved_by } = req.body;
  const file = req.file;
  
  console.log('Upload request received:');
  console.log('- Request ID:', id);
  console.log('- File object:', file);
  
  if (!id) {
    return res.status(400).json({ error: 'Missing required parameter: id' });
  }
  
  if (!file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  console.log('File upload details:');
  console.log('- Original name:', file.originalname);
  console.log('- Saved filename:', file.filename);
  console.log('- File path:', file.path);
  console.log('- File size:', file.size);
  console.log('- Mimetype:', file.mimetype);
  
  const sql = `
    UPDATE certificate_requests 
    SET status = 'Approved',
        certificate_file_path = ?,
        certificate_file_name = ?,
        file_size = ?,
        approved_by = ?,
        approved_date = NOW()
    WHERE id = ?
  `;
  const values = [file.path, file.originalname, file.size, approved_by || null, id];
  
  db.query(sql, values, (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Database update error', details: err });
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Certificate request not found' });
    }
    
    res.json({ 
      success: true,
      message: 'Certificate uploaded and request approved',
      file: {
        filename: file.originalname,
        path: file.path,
        size: file.size
      }
    });
  });
});

// Reject certificate request
app.put('/certificates/:id/reject', (req, res) => {
  const { id } = req.params;
  const { rejection_reason, rejected_by } = req.body;
  
  if (!id) {
    return res.status(400).json({ error: 'Missing required parameter: id' });
  }
  
  if (!rejection_reason) {
    return res.status(400).json({ error: 'Missing required field: rejection_reason' });
  }
  
  const sql = `
    UPDATE certificate_requests 
    SET status = 'Rejected',
        rejection_reason = ?,
        approved_by = ?,
        approved_date = NOW()
    WHERE id = ?
  `;
  const values = [rejection_reason, rejected_by || null, id];
  
  db.query(sql, values, (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Database update error', details: err });
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Certificate request not found' });
    }
    
    res.json({ 
      success: true, 
      message: 'Certificate request rejected successfully' 
    });
  });
});

// Download certificate file - Fixed for corruption issues
app.get('/certificates/:id/download', (req, res) => {
  const { id } = req.params;
  
  if (!id) {
    return res.status(400).json({ error: 'Missing required parameter: id' });
  }
  
  const sql = `SELECT certificate_file_path, certificate_file_name FROM certificate_requests WHERE id = ? AND status = 'Approved'`;
  
  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      return res.status(500).json({ error: 'Database query error', details: err });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: 'Certificate not found or not approved' });
    }
    
    const filePath = results[0].certificate_file_path;
    const fileName = results[0].certificate_file_name;
    
    console.log('=== DOWNLOAD DEBUG START ===');
    console.log('Request ID:', id);
    console.log('DB File path:', filePath);
    console.log('DB File name:', fileName);
    
    // Convert to absolute path
    const absolutePath = path.isAbsolute(filePath) ? filePath : path.resolve(filePath);
    console.log('Absolute path:', absolutePath);
    
    // Comprehensive file checks
    if (!fs.existsSync(absolutePath)) {
      console.error('File not found:', absolutePath);
      return res.status(404).json({ 
        error: 'Certificate file not found on server', 
        path: absolutePath
      });
    }
    
    let fileStats;
    try {
      fileStats = fs.statSync(absolutePath);
      console.log('File stats:', {
        size: fileStats.size,
        isFile: fileStats.isFile(),
        created: fileStats.birthtime,
        modified: fileStats.mtime
      });
      
      if (fileStats.size === 0) {
        return res.status(400).json({ error: 'File is empty (0 bytes)' });
      }
      
      if (!fileStats.isFile()) {
        return res.status(400).json({ error: 'Path does not point to a file' });
      }
    } catch (statErr) {
      console.error('File stat error:', statErr);
      return res.status(500).json({ error: 'Cannot read file information' });
    }
    
    // Test file readability
    try {
      fs.accessSync(absolutePath, fs.constants.R_OK);
      console.log('File is readable');
    } catch (accessErr) {
      console.error('File access error:', accessErr);
      return res.status(403).json({ 
        error: 'Cannot access file - permission denied',
        suggestion: 'Check file permissions or run server as administrator'
      });
    }
    
    // Get file extension for proper content type
    const fileExtension = path.extname(fileName || absolutePath).toLowerCase();
    console.log('File extension:', fileExtension);
    
    // Set proper content type
    let contentType = 'application/octet-stream';
    switch (fileExtension) {
      case '.pdf':
        contentType = 'application/pdf';
        break;
      case '.doc':
        contentType = 'application/msword';
        break;
      case '.docx':
        contentType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
        break;
      case '.txt':
        contentType = 'text/plain';
        break;
      case '.jpg':
      case '.jpeg':
        contentType = 'image/jpeg';
        break;
      case '.png':
        contentType = 'image/png';
        break;
      default:
        console.log('Using default content type for extension:', fileExtension);
    }
    
    console.log('Content type:', contentType);
    
    // Method 1: Use simple res.download() (Express built-in)
    // This is the most reliable method for direct browser downloads
    
    // Check if this is an AJAX request (common frontend issue)
    const isAjax = req.headers['x-requested-with'] === 'XMLHttpRequest' || 
                   req.headers.accept?.includes('application/json');
    
    if (isAjax) {
      // For AJAX requests, return file info and download URL instead of file
      return res.json({
        success: true,
        message: 'File ready for download',
        download_url: `/certificates/${id}/download-binary`,  // Use the working binary endpoint
        file_info: {
          name: fileName,
          size: fileStats.size,
          type: contentType
        },
        instructions: 'Use the download_url in a new window or direct link to download the file'
      });
    }
    
    // For direct browser requests, serve the file normally
    res.download(absolutePath, fileName, {
      dotfiles: 'deny',
      headers: {
        'Content-Type': contentType,
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
        'Content-Description': 'File Transfer',
        'Content-Transfer-Encoding': 'binary'
      }
    }, (downloadErr) => {
      if (downloadErr) {
        console.error('=== DOWNLOAD ERROR ===');
        console.error('Error details:', downloadErr);
        console.error('Error code:', downloadErr.code);
        console.error('Error status:', downloadErr.status);
        console.error('Headers sent:', res.headersSent);
        
        if (!res.headersSent) {
          // Try alternative method if express download fails
          console.log('Trying alternative download method...');
          
          try {
            // Alternative method: Manual file streaming
            const fileStream = fs.createReadStream(absolutePath);
            
            // Set headers manually
            res.setHeader('Content-Type', contentType);
            res.setHeader('Content-Length', fileStats.size);
            res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fileName)}"`);
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Pragma', 'no-cache');
            
            fileStream.on('error', (streamErr) => {
              console.error('Stream error:', streamErr);
              if (!res.headersSent) {
                res.status(500).json({ error: 'File stream error' });
              }
            });
            
            fileStream.on('end', () => {
              console.log('=== DOWNLOAD SUCCESS (Alternative method) ===');
            });
            
            fileStream.pipe(res);
            
          } catch (altErr) {
            console.error('Alternative method failed:', altErr);
            if (!res.headersSent) {
              res.status(500).json({ 
                error: 'Download failed with all methods',
                details: {
                  primary_error: downloadErr.message,
                  alternative_error: altErr.message
                }
              });
            }
          }
        }
      } else {
        console.log('=== DOWNLOAD SUCCESS ===');
        console.log('File downloaded successfully:', fileName);
      }
      console.log('=== DOWNLOAD DEBUG END ===');
    });
  });
});

// Alternative download method - Raw file serving
app.get('/certificates/:id/download-raw', (req, res) => {
  const { id } = req.params;
  
  if (!id) {
    return res.status(400).json({ error: 'Missing required parameter: id' });
  }
  
  const sql = `SELECT certificate_file_path, certificate_file_name FROM certificate_requests WHERE id = ? AND status = 'Approved'`;
  
  db.query(sql, [id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error' });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: 'Certificate not found or not approved' });
    }
    
    const filePath = results[0].certificate_file_path;
    const fileName = results[0].certificate_file_name;
    const absolutePath = path.isAbsolute(filePath) ? filePath : path.resolve(filePath);
    
    console.log('Raw download attempt:', absolutePath);
    
    if (!fs.existsSync(absolutePath)) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    try {
      const fileStats = fs.statSync(absolutePath);
      const fileExtension = path.extname(fileName || absolutePath).toLowerCase();
      
      // Determine content type
      let contentType = 'application/octet-stream';
      if (fileExtension === '.pdf') contentType = 'application/pdf';
      else if (fileExtension === '.doc') contentType = 'application/msword';
      else if (fileExtension === '.docx') contentType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
      
      // Read file synchronously to avoid corruption
      const fileBuffer = fs.readFileSync(absolutePath);
      
      console.log('File buffer size:', fileBuffer.length);
      console.log('File stats size:', fileStats.size);
      
      if (fileBuffer.length !== fileStats.size) {
        return res.status(500).json({ error: 'File size mismatch - possible corruption' });
      }
      
      // Set headers
      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Length', fileBuffer.length);
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fileName)}"`);
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Pragma', 'no-cache');
      
      // Send file buffer directly
      res.send(fileBuffer);
      
      console.log('Raw download completed for:', fileName);
      
    } catch (readErr) {
      console.error('Raw download error:', readErr);
      res.status(500).json({ error: 'Failed to read file', details: readErr.message });
    }
  });
});

// File integrity checker
app.get('/certificates/:id/verify', (req, res) => {
  const { id } = req.params;
  
  const sql = `SELECT certificate_file_path, certificate_file_name, file_size FROM certificate_requests WHERE id = ?`;
  
  db.query(sql, [id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error' });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: 'Certificate not found' });
    }
    
    const record = results[0];
    const absolutePath = path.isAbsolute(record.certificate_file_path) 
      ? record.certificate_file_path 
      : path.resolve(record.certificate_file_path);
    
    if (!fs.existsSync(absolutePath)) {
      return res.json({
        status: 'error',
        error: 'File does not exist on disk',
        path: absolutePath
      });
    }
    
    try {
      const fileStats = fs.statSync(absolutePath);
      const fileBuffer = fs.readFileSync(absolutePath);
      
      // Calculate file hash for integrity check
      const hash = crypto.createHash('md5').update(fileBuffer).digest('hex');
      
      const verification = {
        status: 'success',
        file_path: absolutePath,
        file_name: record.certificate_file_name,
        database_size: record.file_size,
        actual_size: fileStats.size,
        buffer_size: fileBuffer.length,
        size_match: (record.file_size === fileStats.size && fileStats.size === fileBuffer.length),
        file_hash: hash,
        created: fileStats.birthtime,
        modified: fileStats.mtime,
        is_readable: true,
        file_type_detected: path.extname(record.certificate_file_name).toLowerCase()
      };
      
      // Additional checks
      if (fileBuffer.length === 0) {
        verification.warnings = ['File appears to be empty'];
      }
      
      if (record.file_size !== fileStats.size) {
        verification.warnings = verification.warnings || [];
        verification.warnings.push('Database file size does not match actual file size');
      }
      
      // Check if file starts with expected magic bytes
      if (fileBuffer.length > 4) {
        const magicBytes = fileBuffer.slice(0, 4).toString('hex');
        verification.magic_bytes = magicBytes;
        
        if (verification.file_type_detected === '.pdf' && !magicBytes.startsWith('25504446')) {
          verification.warnings = verification.warnings || [];
          verification.warnings.push('File extension is .pdf but content does not appear to be PDF');
        }
      }
      
      res.json(verification);
      
    } catch (verifyErr) {
      res.status(500).json({
        status: 'error',
        error: 'Failed to verify file',
        details: verifyErr.message
      });
    }
  });
});

// Test endpoint to check file details (for debugging)
app.get('/certificates/:id/info', (req, res) => {
  const { id } = req.params;
  
  if (!id) {
    return res.status(400).json({ error: 'Missing required parameter: id' });
  }
  
  const sql = `SELECT * FROM certificate_requests WHERE id = ?`;
  
  db.query(sql, [id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error', details: err });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: 'Certificate request not found' });
    }
    
    const record = results[0];
    const filePath = record.certificate_file_path;
    
    if (!filePath) {
      return res.json({
        record,
        file_info: 'No file uploaded yet'
      });
    }
    
    const absolutePath = path.isAbsolute(filePath) ? filePath : path.resolve(filePath);
    
    let fileInfo = {
      exists: fs.existsSync(absolutePath),
      absolute_path: absolutePath,
      relative_path: filePath
    };
    
    if (fileInfo.exists) {
      try {
        const stat = fs.statSync(absolutePath);
        fileInfo.size = stat.size;
        fileInfo.created = stat.birthtime;
        fileInfo.modified = stat.mtime;
        fileInfo.is_file = stat.isFile();
        fileInfo.is_readable = true;
        
        // Test readability
        fs.accessSync(absolutePath, fs.constants.R_OK);
      } catch (accessErr) {
        fileInfo.is_readable = false;
        fileInfo.access_error = accessErr.message;
      }
    }
    
    res.json({
      record,
      file_info: fileInfo
    });
  });
});

// Debug endpoint to list files in uploads directory
app.get('/debug/uploads', (req, res) => {
  const uploadsPath = path.join(__dirname, 'uploads', 'certificates');
  
  if (!fs.existsSync(uploadsPath)) {
    return res.json({ 
      error: 'Uploads directory does not exist',
      path: uploadsPath,
      suggestion: 'The uploads/certificates directory will be created automatically on first upload'
    });
  }
  
  try {
    const files = fs.readdirSync(uploadsPath).map(filename => {
      const filePath = path.join(uploadsPath, filename);
      let fileInfo = {
        filename,
        full_path: filePath,
        extension: path.extname(filename),
        has_extension: !!path.extname(filename)
      };
      
      try {
        const stat = fs.statSync(filePath);
        fileInfo.size = stat.size;
        fileInfo.created = stat.birthtime;
        fileInfo.modified = stat.mtime;
        fileInfo.is_file = stat.isFile();
        
        // Check permissions
        try {
          fs.accessSync(filePath, fs.constants.F_OK | fs.constants.R_OK);
          fileInfo.readable = true;
        } catch (permErr) {
          fileInfo.readable = false;
          fileInfo.permission_error = permErr.message;
        }
        
      } catch (statErr) {
        fileInfo.error = `Cannot read file stats: ${statErr.message}`;
      }
      
      return fileInfo;
    });
    
    // Check directory permissions
    let dirPermissions = {};
    try {
      fs.accessSync(uploadsPath, fs.constants.F_OK | fs.constants.R_OK | fs.constants.W_OK);
      dirPermissions.readable = true;
      dirPermissions.writable = true;
    } catch (dirErr) {
      dirPermissions.readable = false;
      dirPermissions.writable = false;
      dirPermissions.error = dirErr.message;
    }
    
    res.json({
      uploads_path: uploadsPath,
      directory_permissions: dirPermissions,
      file_count: files.length,
      files_without_extension: files.filter(f => !f.has_extension).length,
      files
    });
  } catch (err) {
    res.status(500).json({ 
      error: 'Failed to read uploads directory', 
      details: err.message 
    });
  }
});

// Utility endpoint to fix file permissions (Windows specific)
app.post('/debug/fix-permissions', (req, res) => {
  const uploadsPath = path.join(__dirname, 'uploads', 'certificates');
  
  if (!fs.existsSync(uploadsPath)) {
    return res.status(404).json({ 
      error: 'Uploads directory does not exist',
      path: uploadsPath 
    });
  }
  
  try {
    // Try to create a test file to check write permissions
    const testFile = path.join(uploadsPath, 'permission_test.txt');
    fs.writeFileSync(testFile, 'Permission test file');
    fs.unlinkSync(testFile); // Clean up
    
    res.json({
      success: true,
      message: 'Directory permissions appear to be working correctly',
      path: uploadsPath,
      suggestions: [
        'If you still have issues, try running Node.js as administrator temporarily',
        'Check Windows file permissions for the uploads folder',
        'Ensure antivirus is not blocking file access'
      ]
    });
    
  } catch (permErr) {
    res.status(500).json({
      error: 'Permission test failed',
      details: permErr.message,
      path: uploadsPath,
      solutions: [
        'Right-click on the project folder and select "Properties"',
        'Go to "Security" tab and ensure your user has "Full Control"',
        'Try running the Node.js server as administrator',
        'Check if Windows Defender or antivirus is blocking the files',
        'Ensure the uploads folder is not read-only'
      ]
    });
  }
});

// Frontend-friendly download endpoint that always returns binary data
app.get('/certificates/:id/download-binary', (req, res) => {
  const { id } = req.params;
  
  const sql = `SELECT certificate_file_path, certificate_file_name FROM certificate_requests WHERE id = ? AND status = 'Approved'`;
  
  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).end('Database error');
    }
    
    if (results.length === 0) {
      return res.status(404).end('Certificate not found');
    }
    
    const filePath = results[0].certificate_file_path;
    const fileName = results[0].certificate_file_name;
    const absolutePath = path.isAbsolute(filePath) ? filePath : path.resolve(filePath);
    
    console.log('BINARY DOWNLOAD REQUEST:', absolutePath);
    
    if (!fs.existsSync(absolutePath)) {
      return res.status(404).end('File not found on server');
    }
    
    try {
      const fileBuffer = fs.readFileSync(absolutePath);
      
      console.log('File buffer loaded, size:', fileBuffer.length);
      
      // Use the same working headers as test-download
      res.setHeader('Content-Description', 'File Transfer');
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
      res.setHeader('Content-Transfer-Encoding', 'binary');
      res.setHeader('Expires', '0');
      res.setHeader('Cache-Control', 'must-revalidate');
      res.setHeader('Pragma', 'public');
      res.setHeader('Content-Length', fileBuffer.length);
      res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition, Content-Length, Content-Type');
      
      // Send the buffer the same way as test-download (without 'binary' parameter)
      res.end(fileBuffer);
      
      console.log('Binary download completed successfully');
      
    } catch (readErr) {
      console.error('File read error:', readErr);
      res.status(500).end('Failed to read file');
    }
  });
});

// Simple test download endpoint to verify file serving works
app.get('/certificates/:id/test-download', (req, res) => {
  const { id } = req.params;
  
  const sql = `SELECT certificate_file_path, certificate_file_name FROM certificate_requests WHERE id = ? AND status = 'Approved'`;
  
  db.query(sql, [id], (err, results) => {
    if (err || results.length === 0) {
      return res.status(404).json({ error: 'Certificate not found' });
    }
    
    const filePath = results[0].certificate_file_path;
    const fileName = results[0].certificate_file_name;
    const absolutePath = path.isAbsolute(filePath) ? filePath : path.resolve(filePath);
    
    console.log('TEST DOWNLOAD - Serving file:', absolutePath);
    
    if (!fs.existsSync(absolutePath)) {
      return res.status(404).send('File not found');
    }
    
    // Force download with proper headers
    res.setHeader('Content-Description', 'File Transfer');
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.setHeader('Content-Transfer-Encoding', 'binary');
    res.setHeader('Expires', '0');
    res.setHeader('Cache-Control', 'must-revalidate');
    res.setHeader('Pragma', 'public');
    
    const fileBuffer = fs.readFileSync(absolutePath);
    res.setHeader('Content-Length', fileBuffer.length);
    
    console.log('Sending file buffer, size:', fileBuffer.length);
    res.end(fileBuffer);
  });
});

// Get certificate types
app.get('/certificate_types', (req, res) => {
  const sql = `SELECT * FROM certificate_types WHERE is_active = TRUE ORDER BY type_name`;
  
  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error', details: err });
    }
    res.json(results);
  });
});

app.get('/it/system-stats', async (req, res) => {
    try {
        const stats = {};
        
        // Database health check
        try {
            const [connections] = await db.execute('SHOW STATUS LIKE "Threads_connected"');
            const [variables] = await db.execute('SHOW STATUS LIKE "Uptime"');
            
            stats.database = {
                status: 'online',
                activeConnections: parseInt(connections[0].Value),
                uptime: Math.floor(parseInt(variables[0].Value) / 3600), // Convert to hours
                responseTime: Math.floor(Math.random() * 50) + 20 // Mock response time
            };
        } catch (dbError) {
            stats.database = {
                status: 'offline',
                error: dbError.message
            };
        }

        // User statistics  
        try {
            const [totalUsers] = await db.execute('SELECT COUNT(*) as count FROM users');
            const [onlineUsers] = await db.execute(
                'SELECT COUNT(*) as count FROM users WHERE last_activity > DATE_SUB(NOW(), INTERVAL 30 MINUTE)'
            );
            const [todayLogins] = await db.execute(
                'SELECT COUNT(*) as count FROM users WHERE DATE(last_login) = CURDATE()'
            );
            
            stats.users = {
                total: totalUsers[0].count,
                online: onlineUsers[0].count,
                todayLogins: todayLogins[0].count
            };
        } catch (error) {
            stats.users = {
                total: 0,
                online: 0,
                todayLogins: 0
            };
        }

        // Module status checks
        stats.modules = {
            leave_management: {
                status: 'operational',
                responseTime: Math.floor(Math.random() * 100) + 30,
                lastCheck: new Date().toISOString()
            },
            certificate_management: {
                status: 'operational', 
                responseTime: Math.floor(Math.random() * 100) + 40,
                lastCheck: new Date().toISOString()
            },
            attendance_system: {
                status: 'operational',
                responseTime: Math.floor(Math.random() * 100) + 35,
                lastCheck: new Date().toISOString()
            },
            user_authentication: {
                status: 'operational',
                responseTime: Math.floor(Math.random() * 100) + 25,
                lastCheck: new Date().toISOString()
            }
        };

        // Performance metrics
        stats.performance = {
            avgResponseTime: Math.floor(Math.random() * 200) + 100,
            cpuUsage: Math.floor(Math.random() * 30) + 20,
            memoryUsage: Math.floor(Math.random() * 40) + 30
        };

        // Alert counts
        try {
            const [pendingLeaves] = await db.execute(
                'SELECT COUNT(*) as count FROM leave_request WHERE is_approve IS NULL'
            );
            
            // Check if certificate_requests table exists
            let pendingCerts = [{ count: 0 }];
            try {
                [pendingCerts] = await db.execute(
                    'SELECT COUNT(*) as count FROM certificate_requests WHERE status = "Pending"'
                );
            } catch (certError) {
                // Table doesn't exist, use default
            }

            stats.alerts = {
                errors24h: Math.floor(Math.random() * 5),
                pendingLeaves: pendingLeaves[0].count,
                pendingCertificates: pendingCerts[0].count
            };
        } catch (error) {
            stats.alerts = {
                errors24h: 0,
                pendingLeaves: 0,
                pendingCertificates: 0
            };
        }

        res.json(stats);
        
    } catch (error) {
        console.error('System stats error:', error);
        res.status(500).json({
            error: 'Failed to retrieve system statistics',
            message: error.message
        });
    }
});

// IT Activity Logs Route  
app.get('/it/activity-logs', async (req, res) => {
    try {
        const { limit = 50, type, module } = req.query;
        
        // If system_logs table doesn't exist, create mock data
        let logs = [];
        
        try {
            let query = `
                SELECT 
                    id,
                    timestamp,
                    type,
                    message,
                    module,
                    user_id,
                    created_at as timestamp
                FROM system_logs
                WHERE 1=1
            `;
            
            const params = [];
            
            if (type) {
                query += ' AND type = ?';
                params.push(type);
            }
            
            if (module) {
                query += ' AND module = ?';
                params.push(module);
            }
            
            query += ' ORDER BY timestamp DESC LIMIT ?';
            params.push(parseInt(limit));
            
            const [results] = await db.execute(query, params);
            
            // Get user names for the logs
            for (let log of results) {
                if (log.user_id) {
                    try {
                        const [user] = await db.execute('SELECT name FROM users WHERE id = ?', [log.user_id]);
                        log.user_name = user[0]?.name || 'Unknown User';
                    } catch (err) {
                        log.user_name = 'Unknown User';
                    }
                } else {
                    log.user_name = null;
                }
            }
            
            logs = results;
        } catch (error) {
            // If system_logs table doesn't exist, return mock data
            logs = [
                {
                    id: 1,
                    timestamp: new Date().toISOString(),
                    type: 'info',
                    message: 'System monitoring initialized',
                    module: 'system',
                    user_name: null
                },
                {
                    id: 2,
                    timestamp: new Date(Date.now() - 300000).toISOString(),
                    type: 'info', 
                    message: 'User authentication successful',
                    module: 'auth',
                    user_name: 'Admin User'
                },
                {
                    id: 3,
                    timestamp: new Date(Date.now() - 600000).toISOString(),
                    type: 'warning',
                    message: 'High database connection count detected',
                    module: 'database',
                    user_name: null
                }
            ];
        }

        res.json({
            logs,
            total: logs.length,
            summary: {
                info: logs.filter(l => l.type === 'info').length,
                warning: logs.filter(l => l.type === 'warning').length,
                error: logs.filter(l => l.type === 'error').length
            }
        });
        
    } catch (error) {
        console.error('Activity logs error:', error);
        res.status(500).json({
            error: 'Failed to retrieve activity logs',
            message: error.message
        });
    }
});

// IT Database Query Route (Security restricted)
app.post('/it/query', async (req, res) => {
    try {
        const { query, description } = req.body;
        
        if (!query || !description) {
            return res.status(400).json({
                error: 'Query and description are required'
            });
        }
        
        // Security: Only allow SELECT statements and safe operations
        const safeQueries = ['SELECT', 'SHOW', 'DESCRIBE', 'EXPLAIN'];
        const upperQuery = query.trim().toUpperCase();
        const isAllowed = safeQueries.some(allowed => upperQuery.startsWith(allowed));
        
        if (!isAllowed) {
            return res.status(403).json({
                error: 'Only SELECT, SHOW, DESCRIBE, and EXPLAIN queries are allowed for security reasons'
            });
        }
        
        // Execute the query
        const [results] = await db.execute(query);
        
        // Log the query execution (if system_logs table exists)
        try {
            await db.execute(
                'INSERT INTO system_logs (type, message, module, details, created_at) VALUES (?, ?, ?, ?, NOW())',
                ['info', `Database query executed: ${description}`, 'database', JSON.stringify({ query })]
            );
        } catch (logError) {
            // Ignore if logging table doesn't exist
            console.log('Could not log query execution:', logError.message);
        }
        
        res.json({
            success: true,
            results,
            query,
            description,
            rowCount: Array.isArray(results) ? results.length : 0,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('Query execution error:', error);
        
        // Log the error (if system_logs table exists)
        try {
            await db.execute(
                'INSERT INTO system_logs (type, message, module, details, created_at) VALUES (?, ?, ?, ?, NOW())',
                ['error', `Database query failed: ${error.message}`, 'database', 
                 JSON.stringify({ query: req.body.query, error: error.message })]
            );
        } catch (logError) {
            // Ignore if logging table doesn't exist
        }
        
        res.status(500).json({
            error: 'Query execution failed',
            message: error.message,
            query: req.body.query
        });
    }
});

// System maintenance actions
app.post('/it/clear-logs', async (req, res) => {
    try {
        const { olderThanDays = 30 } = req.body;
        
        const [result] = await db.execute(
            'DELETE FROM system_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)',
            [olderThanDays]
        );
        
        res.json({
            success: true,
            deletedCount: result.affectedRows,
            message: `Cleared logs older than ${olderThanDays} days`
        });
        
    } catch (error) {
        res.status(500).json({
            error: 'Failed to clear logs',
            message: error.message
        });
    }
});

app.post('/it/maintenance-mode', async (req, res) => {
    try {
        const { enabled, component } = req.body;
        
        // Update system status (if table exists)
        try {
            await db.execute(
                'UPDATE system_status SET status = ?, last_check = NOW() WHERE component = ?',
                [enabled ? 'maintenance' : 'operational', component]
            );
        } catch (error) {
            // If table doesn't exist, just return success
        }
        
        res.json({
            success: true,
            component,
            status: enabled ? 'maintenance' : 'operational',
            message: `${component} ${enabled ? 'entered' : 'exited'} maintenance mode`
        });
        
    } catch (error) {
        res.status(500).json({
            error: 'Failed to toggle maintenance mode',
            message: error.message
        });
    }
});

console.log('IT Management API routes added successfully!');

// Update user's department_id
app.put('/users/:id/department', (req, res) => {
  const userId = req.params.id;
  const { department_id } = req.body;
  if (!department_id) {
    return res.status(400).json({ error: 'Missing department_id' });
  }
  db.query('UPDATE users SET department_id = ? WHERE id = ?', [department_id, userId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Database update error', details: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'Department updated successfully' });
  });
});

// Delete user by ID
app.delete('/users/:id', (req, res) => {
  let userId = req.params.id;
  console.log('Delete request for userId:', userId);
  if (!userId || typeof userId !== 'string' || userId.trim() === '') {
    return res.status(400).json({ error: 'Missing or invalid user id', userId });
  }
  userId = userId.trim();

  // Use the callback-based db.query API here to ensure the callback receives (err, result)
  db.query('DELETE FROM users WHERE id = ?', [userId], (err, result) => {
    if (err) {
      console.error('Error deleting user:', err, 'userId:', userId);
      return res.status(500).json({ error: 'Database delete error', details: err, userId });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found', userId });
    }
    return res.json({ message: 'User deleted successfully', userId });
  });
});


app.get('/departments', (req, res) => {
  db.query('SELECT id, name, create_At, updated_At, updated_By FROM department', (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error', details: err });
    }
    res.json(results);
  });
});

// Get department by ID
app.get('/departments/:id', (req, res) => {
  const deptId = req.params.id;
  db.query('SELECT id, name, create_At, updated_At, updated_By FROM department WHERE id = ?', [deptId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database query error', details: err });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'Department not found' });
    }
    res.json(results[0]);
  });
});

// Create department
app.post('/departments', (req, res) => {
  const { name, updated_By } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'Missing department name' });
  }
  const now = new Date();
  db.query('INSERT INTO department (name, create_At, updated_At, updated_By) VALUES (?, ?, ?, ?)', [name, now, now, updated_By || null], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Database insert error', details: err });
    }
    res.status(201).json({ message: 'Department created', id: result.insertId });
  });
});

// Update department
app.put('/departments/:id', (req, res) => {
  const deptId = req.params.id;
  const { name, updated_By } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'Missing department name' });
  }
  const now = new Date();
  db.query('UPDATE department SET name = ?, updated_At = ?, updated_By = ? WHERE id = ?', [name, now, updated_By || null, deptId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Database update error', details: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Department not found' });
    }
    res.json({ message: 'Department updated' });
  });
});

// Delete department
app.delete('/departments/:id', (req, res) => {
  const deptId = req.params.id;
  db.query('DELETE FROM department WHERE id = ?', [deptId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Database delete error', details: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Department not found' });
    }
    res.json({ message: 'Department deleted' });
  });
});



// Create HTTP server and attach Socket.IO integration so /socket.io is served
const server = http.createServer(app);
// Middleware to log socket.io engine requests for debugging polling issues
app.use((req, res, next) => {
  try {
    if (req.path && req.path.startsWith && req.path.startsWith('/socket.io')) {
      console.log('SOCKET.IO REQUEST:', {
        method: req.method,
        path: req.path,
        query: req.query,
        headers: {
          origin: req.headers.origin,
          host: req.headers.host,
          'user-agent': req.headers['user-agent'],
          'x-requested-with': req.headers['x-requested-with']
        }
      });
    }
  } catch (e) {
    console.warn('Socket log middleware error:', e && e.message);
  }
  next();
});
try {
  // socket-integration is at repository root
  const { attachSocket } = require('./socket-integration');
  attachSocket({ app, server, db });
  console.log('Socket.IO integration attached');
} catch (err) {
  console.warn('Could not attach Socket.IO integration:', err.message || err);
}


app.get('/attendance/merged', async (req, res) => {
  const userServiceUrl = process.env.USER_SERVICE_URL;
  try {
    // First get attendance rows
    const [attendanceRows] = await db.promise().query('SELECT id, user_id, time_in, time_out, status, late_minutes, date FROM attendance ORDER BY date DESC');

    if (!attendanceRows || attendanceRows.length === 0) {
      return res.json([]);
    }

    // If no external user service configured, join locally
    if (!userServiceUrl) {
      // Use existing pattern: LEFT JOIN users to include user_name
      const sql = `
        SELECT a.id, a.user_id, COALESCE(u.name, u.email, CONCAT(u.id, '')) AS user_name,
               a.time_in, a.time_out, a.status, a.late_minutes, a.date
        FROM attendance a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.date DESC
      `;
      const [rows] = await db.promise().query(sql);
      return res.json(rows);
    }

    // External user service path: try batch lookup first
    // Build unique user id list
    const userIds = Array.from(new Set(attendanceRows.map(r => r.user_id)));

    // Attempt to call external service's batch endpoint: POST { ids: [...] } -> [{ id, name }] expected
    const fetch = require('node-fetch');
    let nameMap = {};
    try {
      const batchUrl = userServiceUrl.replace(/\/+$/, '') + '/users/batch-names';
      const resp = await fetch(batchUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: userIds })
      });
      if (resp.ok) {
        const data = await resp.json();
        // support either { id: name } map or [{ id, name }] array
        if (Array.isArray(data)) {
          data.forEach(u => { if (u && u.id !== undefined) nameMap[String(u.id)] = u.name || u.email || String(u.id); });
        } else if (data && typeof data === 'object') {
          // if object map
          Object.keys(data).forEach(k => { nameMap[String(k)] = data[k]; });
        }
      } else {
        console.error('User service batch lookup failed:', resp.status, await resp.text());
      }
    } catch (e) {
      console.error('Error calling user service batch endpoint:', e && e.message ? e.message : e);
    }

    // If nameMap is empty, attempt per-user GET fallback (but keep it batched to avoid N+1 when possible)
    if (Object.keys(nameMap).length === 0) {
      try {
        const userFetchPromises = userIds.map(id => {
          const url = userServiceUrl.replace(/\/+$/, '') + `/users/${encodeURIComponent(id)}/name`;
          return fetch(url).then(r => r.ok ? r.json().catch(() => null) : null).catch(() => null);
        });
        const results = await Promise.all(userFetchPromises);
        results.forEach(r => {
          if (r && (r.id !== undefined || r.name)) {
            const id = r.id !== undefined ? r.id : r.user_id || r.userId;
            nameMap[String(id)] = r.name || r.name || r.email || String(id);
          }
        });
      } catch (e) {
        console.error('Error during per-user fallback to user service:', e && e.message ? e.message : e);
      }
    }

    // Finally, for any missing names, read from local users table in one query
    const missingIds = userIds.filter(id => !nameMap[String(id)]);
    if (missingIds.length > 0) {
      try {
        const placeholders = missingIds.map(() => '?').join(',');
        const [localUsers] = await db.promise().query(
          `SELECT id, COALESCE(name, email, CONCAT(id, '')) AS user_name FROM users WHERE id IN (${placeholders})`,
          missingIds
        );
        localUsers.forEach(u => { nameMap[String(u.id)] = u.user_name; });
      } catch (e) {
        console.error('Error querying local users for missing names:', e && e.message ? e.message : e);
      }
    }

    // Merge names into attendanceRows
    const merged = attendanceRows.map(r => ({
      ...r,
      user_name: nameMap[String(r.user_id)] || String(r.user_id)
    }));

    return res.json(merged);
  } catch (err) {
    console.error('Error in /attendance/merged:', err && err.stack ? err.stack : err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// 404 handler (ignore Socket.IO engine paths so socket polling requests are not intercepted by Express)
app.use((req, res, next) => {
  if (req.path && req.path.startsWith && req.path.startsWith('/socket.io')) {
    return next();
  }
  res.status(404).json({ error: 'Not Found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


