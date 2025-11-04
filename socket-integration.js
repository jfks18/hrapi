const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');

/**
 * Attach Socket.IO to an existing Express app and HTTP server.
 * Usage:
 *   const { attachSocket } = require('./socket-integration');
 *   attachSocket({ app, server, db });
 */
function attachSocket({ app, server, db }) {
  if (!server) {
    // If caller passed app only, create server from it
    server = http.createServer(app);
  }

   const io = new Server(server, {
    cors: {
      origin: ["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000", "http://127.0.0.1:3001", true],
      methods: ['GET', 'POST', 'OPTIONS'],
      credentials: true,
      allowedHeaders: ['Content-Type', 'Authorization', 'ngrok-skip-browser-warning']
    },
    transports: ['websocket', 'polling']
  });

  // Log incoming /socket.io HTTP requests (helpful to debug engine.io polling via proxies/ngrok)
  try {
    server.on('request', (req, res) => {
      try {
        const url = req.url || '';
        if (url.startsWith('/socket.io/') || url.startsWith('/socket.io?') || url.includes('/socket.io')) {
          console.log('Incoming http request to socket.io:', req.method, url, 'headers:', { origin: req.headers.origin, referer: req.headers.referer, host: req.headers.host, 'access-control-request-headers': req.headers['access-control-request-headers'] });
        }
      } catch (e) { /* ignore logging errors */ }
    });
  } catch (e) { /* ignore if server doesn't support request event */ }
  // Socket auth middleware: more lenient for localhost development
  io.use((socket, next) => {
    const token = socket.handshake?.auth?.token || null;
    // Log minimal token info for debugging
    if (!token) console.warn(`socket handshake: no token provided for socket ${socket.id}`);
    else console.log(`socket handshake: token present for socket ${socket.id} (len=${String(token).length})`);
    
    // Allow connections without strict auth for development or when no JWT_SECRET
    if (!process.env.JWT_SECRET || process.env.NODE_ENV === 'development') {
      console.log(`Socket auth: allowing connection for development mode for socket ${socket.id}`);
      socket.user = token ? { id: 'dev-user', name: 'Dev User' } : { id: 'anonymous', name: 'Anonymous' };
      return next();
    }
    
    if (process.env.JWT_SECRET) {
      if (!token) {
        console.warn(`Socket auth: missing token and JWT_SECRET is set - rejecting socket ${socket.id}`);
        return next(new Error('Authentication error: missing token'));
      }
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        socket.user = decoded;
        return next();
      } catch (err) {
        console.warn('Socket auth failed during handshake for socket', socket.id, 'error:', err && err.message);
        return next(new Error('Authentication error: invalid token'));
      }
    }
    // No JWT_SECRET configured: allow connection but decode token if present
    if (token) {
      try { socket.user = jwt.decode(token); } catch (e) { /* ignore */ }
    }
    return next();
  });

  // Ensure chat_messages table exists
  try {
    const createChatTable = `
      CREATE TABLE IF NOT EXISTS chat_messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        room VARCHAR(255) NOT NULL,
        sender_id VARCHAR(255),
        sender_name VARCHAR(255),
        recipient_id VARCHAR(255),
        cid VARCHAR(255),
        message TEXT NOT NULL,
        read_at TIMESTAMP NULL DEFAULT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `;
    if (db && typeof db.query === 'function') {
      db.query(createChatTable, (ctErr) => {
        if (ctErr) console.error('Failed to ensure chat_messages table:', ctErr);
        else console.log('chat_messages table ensured');
      });
    } else if (db && typeof db.execute === 'function') {
      db.execute(createChatTable).then(() => console.log('chat_messages table ensured')).catch(err => console.error('Failed to ensure chat_messages table:', err));
    } else {
      console.warn('No db provided or db does not support query/execute - chat history persistence will be disabled');
    }
  } catch (ex) {
    console.error('Error creating chat table:', ex);
  }

  // Presence maps to support multi-socket users and private messaging
  const onlineUsers = new Map(); // socketId -> { id, name, room }
  const userSockets = new Map(); // userId -> Set(socketId)

  // Helper to create a safe room name from a display name
  function sanitizeRoomName(name) {
    if (!name) return null;
    return String(name).trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '_');
  }

  io.on('connection', (socket) => {
    console.log('Socket connected:', socket.id);

    // The handshake middleware already attempts to populate socket.user when JWT provided
    const authUser = socket.user || null;
    const authUserId = authUser?.id || authUser?.sub || null;
    const authUserName = authUser?.name || authUser?.username || authUser?.email || null;

    // Helper to announce connection and create user's personal room (based on display name)
    const announceConnected = (sockId, uid, name) => {
      const safeName = sanitizeRoomName(name) || null;
      const personalRoom = safeName ? `user:${safeName}` : null;
      onlineUsers.set(sockId, { id: uid, name, room: personalRoom });
      if (uid) {
        const set = userSockets.get(uid) || new Set();
        set.add(sockId);
        userSockets.set(uid, set);
      }
      // join the socket into their personal room if available
      if (personalRoom) {
        try { socket.join(personalRoom); } catch (e) { /* ignore */ }
      }
      io.emit('user_connected', { socketId: sockId, id: uid, name, room: personalRoom });
    };

    if (authUserId) {
      // If DB available, try to get canonical name; otherwise use token name
      if (db) {
        db.query('SELECT id, name FROM users WHERE id = ?', [authUserId], (qErr, rows) => {
          const finalId = String(authUserId);
          const finalName = (!qErr && rows && rows[0] && rows[0].name) ? rows[0].name : authUserName;
          announceConnected(socket.id, finalId, finalName);
        });
      } else {
        announceConnected(socket.id, String(authUserId), authUserName);
      }
    } else {
      // Anonymous connection
      announceConnected(socket.id, null, null);
    }

    socket.on('join', (room) => {
      if (!room) return;
      socket.join(room);
      console.log(`Socket ${socket.id} joined room ${room}`);
    });

    socket.on('leave', (room) => {
      if (!room) return;
      socket.leave(room);
      console.log(`Socket ${socket.id} left room ${room}`);
    });

    socket.on('get_history', (payload, cb) => {
      const room = payload?.room;
      const limit = parseInt(payload?.limit) || 50;
      if (!room) return cb && cb({ error: 'room required' });
      const sql = 'SELECT id, room, sender_id, sender_name, message, cid, read_at, created_at FROM chat_messages WHERE room = ? ORDER BY created_at DESC LIMIT ?';
      if (!db) return cb && cb({ error: 'no_db' });
      db.query(sql, [room, limit], (err, rows) => {
        if (err) {
          console.error('Chat history db error:', err);
          return cb && cb({ error: 'Database error' });
        }
        cb && cb({ success: true, messages: rows.reverse() });
      });
    });

    socket.on('send_message', (data, ack) => {
      const room = data?.room;
      const message = data?.message;
      let sender_id = data?.sender_id || null;
      let sender_name = data?.sender_name || null;
      const recipient_id = data?.recipient_id || null;
      const cid = data?.cid || null; // client id
      console.log(`send_message received from socket ${socket.id} room=${room} sender=${sender_name || sender_id}`);
      if (!room || !message) return ack && ack({ error: 'room and message required', cid });

      // enforce auth identity when available
      const authId = authUserId;
      const authName = authUserName;
      if (authId) {
        sender_id = String(authId);
        if (!sender_name && authName) sender_name = authName;
      }

      // DM room validation
      if (room && room.startsWith('dm:')) {
        const parts = room.split(':');
        if (parts.length >= 3) {
          const a = String(parts[1]);
          const b = String(parts[2]);
          if (authId && String(authId) !== a && String(authId) !== b) {
            console.warn(`Socket ${socket.id} attempted to send to DM ${room} but is not a participant`);
            return ack && ack({ error: 'not a participant in this DM', cid });
          }
        }
      }

      const insertSql = 'INSERT INTO chat_messages (room, sender_id, sender_name, recipient_id, cid, message) VALUES (?, ?, ?, ?, ?, ?)';
      if (!db) {
        const saved = { id: null, room, sender_id, sender_name, message, created_at: new Date().toISOString(), cid };
        console.log(`Emitting new_message to room=${room} for socket ${socket.id}`);
        io.to(room).emit('new_message', saved);
        return ack && ack({ success: true, message: saved, cid });
      }

      db.query(insertSql, [room, sender_id, sender_name, recipient_id, cid, message], (err, result) => {
        if (err) {
          console.error('Failed to save chat message:', err);
          return ack && ack({ error: 'Database error', cid });
        }
        const saved = { id: result.insertId, room, sender_id, sender_name, recipient_id, message, created_at: new Date().toISOString(), cid };
        console.log(`Emitting new_message to room=${room} for socket ${socket.id}`);
        io.to(room).emit('new_message', saved);
        ack && ack({ success: true, message: saved, cid });
      });
    });

    // typing indicator: broadcast to the room (for DMs it will reach the other participant)
    socket.on('typing', (payload) => {
      try {
        const room = payload?.room;
        const isTyping = !!payload?.typing;
        if (!room) return;
        io.to(room).emit('typing', { room, typing: isTyping, user: { id: authUserId, name: authUserName } });
      } catch (e) { /* ignore */ }
    });

    // mark message(s) as read; client can send { room, messageId }
    socket.on('message_read', (payload, cb) => {
      try {
        const room = payload?.room;
        const messageId = payload?.messageId;
        if (!room || !messageId) return cb && cb({ error: 'room and messageId required' });
        if (!db) return cb && cb({ error: 'no_db' });
        db.query('UPDATE chat_messages SET read_at = NOW() WHERE id = ? AND room = ?', [messageId, room], (err, result) => {
          if (err) return cb && cb({ error: 'db' });
          io.to(room).emit('message_read', { room, messageId, reader: authUserId || null });
          cb && cb({ success: true });
        });
      } catch (e) { cb && cb({ error: 'failed' }); }
    });

    socket.on('get_online_users', (cb) => {
      try {
        const users = [];
        for (const [userId, socketsSet] of userSockets.entries()) {
          // get name and room from one of the sockets
          let name = null;
          let room = null;
          for (const sid of socketsSet) {
            const entry = onlineUsers.get(sid);
            if (entry) {
              if (!name && entry.name) name = entry.name;
              if (!room && entry.room) room = entry.room;
            }
            if (name && room) break;
          }
          users.push({ id: userId, name, room });
        }
        cb && cb({ success: true, users });
      } catch (e) {
        cb && cb({ error: 'failed' });
      }
    });

    // Allow client to re-authenticate mid-connection with a new token (no reconnect required)
    socket.on('authenticate', (data, cb) => {
      const token = data && data.token;
      if (!token) return cb && cb({ error: 'no_token' });
      try {
        const decoded = process.env.JWT_SECRET ? jwt.verify(token, process.env.JWT_SECRET) : jwt.decode(token);
        socket.user = decoded;
        const uid = decoded && (decoded.id || decoded.sub) ? String(decoded.id || decoded.sub) : null;
        const uname = decoded && (decoded.name || decoded.username || decoded.email) ? (decoded.name || decoded.username || decoded.email) : null;
        // Re-announce connection using existing announceConnected helper
        try { announceConnected(socket.id, uid, uname); } catch (e) { /* ignore */ }
        return cb && cb({ success: true });
      } catch (err) {
        return cb && cb({ error: err && err.message });
      }
    });

    // Allow joining another user's personal room by display name (client-side convenience)
    socket.on('join_user', (targetName, cb) => {
      if (!targetName) return cb && cb({ error: 'targetName required' });
      const safe = sanitizeRoomName(targetName);
      if (!safe) return cb && cb({ error: 'invalid name' });
      const room = `user:${safe}`;
      try {
        socket.join(room);
        console.log(`Socket ${socket.id} joined user room ${room}`);
        return cb && cb({ success: true, room });
      } catch (e) {
        return cb && cb({ error: 'failed to join' });
      }
    });

    socket.on('private_message', (data, ack) => {
      const toUserId = data?.toUserId;
      const message = data?.message;
      if (!toUserId || !message) return ack && ack({ error: 'toUserId and message required' });
      console.log(`private_message from socket ${socket.id} to user ${toUserId} message=${message}`);
      const targets = userSockets.get(String(toUserId));
      if (!targets || targets.size === 0) return ack && ack({ error: 'user_offline' });
      const payload = { from: authUserId || null, fromName: authUserName || null, message, created_at: new Date().toISOString() };
      for (const targetSocketId of targets) {
        io.to(targetSocketId).emit('private_message', payload);
      }
      ack && ack({ success: true });
    });

    socket.on('disconnect', (reason) => {
      console.log('Socket disconnected:', socket.id, reason);
      const removed = onlineUsers.get(socket.id) || null;
      onlineUsers.delete(socket.id);
      if (removed && removed.id) {
        const set = userSockets.get(removed.id);
        if (set) {
          set.delete(socket.id);
          if (set.size === 0) {
            userSockets.delete(removed.id);
            io.emit('user_disconnected', { socketId: socket.id, id: removed.id, name: removed.name });
          } else {
            io.emit('user_socket_disconnected', { socketId: socket.id, id: removed.id, name: removed.name });
          }
        } else {
          io.emit('user_disconnected', { socketId: socket.id, id: removed.id, name: removed.name });
        }
      } else {
        io.emit('user_disconnected', { socketId: socket.id, id: removed?.id || null, name: removed?.name || null });
      }
    });
  });

  // HTTP endpoint to fetch chat history if app is provided
  if (app) {
    app.get('/chat/history/:room', (req, res) => {
      const room = req.params.room;
      const limit = parseInt(req.query.limit) || 100;
      if (!room) return res.status(400).json({ error: 'room required' });
      const sql = 'SELECT id, room, sender_id, sender_name, message, created_at FROM chat_messages WHERE room = ? ORDER BY created_at DESC LIMIT ?';
      if (!db) return res.status(500).json({ error: 'no_db' });
      db.query(sql, [room, limit], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database query error', details: err });
        res.json(rows.reverse());
      });
    });

    // Helper: extract JWT user from Authorization header (if JWT_SECRET set)
    function authFromReq(req) {
      try {
        const auth = req.headers && (req.headers.authorization || req.headers.Authorization);
        if (!auth) return null;
        const parts = auth.split(' ');
        if (parts.length !== 2) return null;
        const token = parts[1];
        if (process.env.JWT_SECRET) {
          try { return jwt.verify(token, process.env.JWT_SECRET); } catch (e) { return null; }
        }
        try { return jwt.decode(token); } catch (e) { return null; }
      } catch (ex) {
        return null;
      }
    }

    // Deterministic DM room id helper for two user ids (strings or numbers)
    function dmRoomIdFor(a, b) {
      const sa = String(a);
      const sb = String(b);
      return `dm:${[sa, sb].sort().join(':')}`;
    }

    // List DM conversations for the authenticated user based on message history
    app.get('/chat/dms', (req, res) => {
      const user = authFromReq(req);
      if (!user || (!user.id && !user.sub)) return res.status(401).json({ error: 'unauthorized' });
      const uid = String(user.id || user.sub);
      if (!db) return res.status(500).json({ error: 'no_db' });
      // Find distinct dm rooms where this user participated
      const sql = `SELECT room, MAX(created_at) as last_at, COUNT(*) as msg_count
                   FROM chat_messages
                   WHERE room LIKE 'dm:%' AND (room LIKE CONCAT('%:', ?,) OR room LIKE CONCAT(?, ':%'))
                   GROUP BY room
                   ORDER BY last_at DESC`;
      // Because different SQL dialects handle CONCAT differently, build paramized query simply
      db.query('SELECT room, MAX(created_at) as last_at, COUNT(*) as msg_count FROM chat_messages WHERE room LIKE ? GROUP BY room ORDER BY last_at DESC', [`%:${uid}:%`], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error', details: err });
        // Map rows to peer id and room
        const list = (rows || []).map(r => {
          const parts = String(r.room).split(':');
          const a = parts[1];
          const b = parts[2];
          const other = (String(a) === uid) ? b : a;
          return { room: r.room, other: other, last_at: r.last_at, msg_count: r.msg_count };
        });
        res.json({ success: true, dms: list });
      });
    });

    // Create or return deterministic DM room id for two users
    // Note: rely on the parent app's JSON middleware (express.json())
    app.post('/chat/dm', (req, res) => {
      const user = authFromReq(req);
      if (!user || (!user.id && !user.sub)) return res.status(401).json({ error: 'unauthorized' });
      const uid = String(user.id || user.sub);
      const other = req.body && (req.body.other || req.body.user_id || req.body.userId);
      if (!other) return res.status(400).json({ error: 'other user id required' });
      const room = dmRoomIdFor(uid, other);
      res.json({ success: true, room });
    });
  }

  return { io, server };
}

module.exports = { attachSocket };
