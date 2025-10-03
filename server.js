// server.js
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = process.env.PORT || 3000;

const ACCESS_LOG_FILE = path.join(__dirname, 'access.log'); 
const JWT_SECRET = process.env.JWT_SECRET || 'kunci-rahasia-jwt-anda';

// --- DB pool (mysql2) ---
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'appuser',
  password: process.env.DB_PASS || 'StrongPasswordHere!',
  database: process.env.DB_NAME || 'appdb',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// --- Utilitas Masking yang lebih cerdas ---
const SENSITIVE_KEYS = [
  'password', 'pass', 'pwd', 'token', 'authorization', 'auth', 'access_token',
  'refresh_token', 'credit_card', 'card', 'cc', 'ssn', 'secret', 'api_key', 'apikey'
];

function maskString(s) {
  if (typeof s !== 'string') return s;
  // short strings: fully mask
  if (s.length <= 4) return '*'.repeat(s.length);
  // email: show first char and domain partially
  if (/@/.test(s)) {
    const [local, domain] = s.split('@');
    return local[0] + '***@' + domain;
  }
  // credit card or long token: show last 4
  const visible = 4;
  const maskedLen = Math.max(0, s.length - visible);
  return '*'.repeat(maskedLen) + s.slice(-visible);
}

function maskObject(obj, keysToMask = SENSITIVE_KEYS) {
  if (obj == null) return obj;
  if (typeof obj === 'string') return maskString(obj);
  if (typeof obj !== 'object') return obj;

  if (Array.isArray(obj)) {
    return obj.map(item => maskObject(item, keysToMask));
  }

  const out = {};
  for (const k of Object.keys(obj)) {
    try {
      const v = obj[k];
      const lower = k.toLowerCase();
      if (keysToMask.includes(lower)) {
        out[k] = maskString(String(v));
      } else if (typeof v === 'object' && v !== null) {
        out[k] = maskObject(v, keysToMask);
      } else if (typeof v === 'string') {
        // also try to detect long tokens inside strings (heuristic)
        if (v.length > 50 && /[A-Za-z0-9\-_.=]/.test(v)) {
          out[k] = maskString(v);
        } else {
          out[k] = v;
        }
      } else {
        out[k] = v;
      }
    } catch (e) {
      out[k] = '***UNMASKABLE***';
    }
  }
  return out;
}

// --- WITA time helper ---
const getWitaTime = () => {
  const date = new Date();
  return date.toLocaleString('id-ID', {
      timeZone: 'Asia/Makassar',
      hour12: false,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      fractionalSecondDigits: 3
  }).replace(/(\d+)\/(\d+)\/(\d+),/, '$3-$2-$1T');
};

// --- Middleware Logging (menggunakan maskObject) ---
const logRequestDetails = async (req, res, next) => {
  const startTime = process.hrtime();
  const requestId = uuidv4();
  req.requestId = requestId;

  // prepare masked snapshot for logging
  let safeBody = {};
  try { safeBody = maskObject(req.body || {}); } catch (e) { safeBody = {}; }

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader && authHeader.startsWith('Bearer ')
    ? authHeader.split(' ')[1]
    : null;
  const maskedToken = token ? maskString(token) : 'N/A';

  // proceed request
  next();

  res.on('finish', async () => {
    const diff = process.hrtime(startTime);
    const responseTimeMs = (diff[0] * 1e9 + diff[1]) / 1e6;

    const logData = {
      requestId,
      timestamp: getWitaTime(),
      status: res.statusCode,
      method: req.method,
      path: req.originalUrl,
      ip: req.ip || req.connection?.remoteAddress || 'N/A',
      host: req.headers.host || 'N/A',
      userAgent: req.headers['user-agent'] || 'N/A',
      body: safeBody,
      query: maskObject(req.query || {}),
      params: maskObject(req.params || {}),
      token: maskedToken,
      responseTimeMs: parseFloat(responseTimeMs.toFixed(2))
    };

    const logEntry = JSON.stringify(logData) + '\n';

    // console
    console.log('[ACCESS LOG]', JSON.stringify(logData));

    // append to file (non-blocking)
    fs.appendFile(ACCESS_LOG_FILE, logEntry, (err) => {
      if (err) console.error('Failed to write to access.log:', err);
    });

    // optionally write to DB audit_logs (best-effort, don't crash on error)
    try {
      const conn = await pool.getConnection();
      try {
        await conn.query(
          'INSERT INTO audit_logs (request_id, user_id, event_type, details, ip_address) VALUES (?, ?, ?, ?, ?)',
          [requestId, req.user?.id || null, `${req.method} ${req.originalUrl}`, JSON.stringify(logData), logData.ip]
        );
      } finally {
        conn.release();
      }
    } catch (e) {
      // DB audit failed — log but keep running
      console.warn('Failed to write audit log to DB:', e.message || e);
    }
  });
};

// --- Middleware Check SQL Injection (improved heuristics) ---
const checkSqlInjection = (req, res, next) => {
  // detect suspicious SQL patterns or typical injection payloads
  const suspiciousPattern = /(\b(select|union|insert|update|delete|drop|truncate|alter|create)\b|--|;|\/\*|\b(or|and)\b\s+1\s*=\s*1|0x[0-9a-f]+|exec\s*\(|xp_)/i;

  const check = (obj) => {
    if (!obj) return false;
    for (const k of Object.keys(obj)) {
      const v = obj[k];
      if (typeof v === 'string' && suspiciousPattern.test(v)) {
        return true;
      }
      if (typeof v === 'object' && check(v)) return true;
    }
    return false;
  };

  if (check(req.body) || check(req.query) || check(req.params)) {
    return res.status(403).json({
      status: 'error',
      message: 'Karakter atau pola mencurigakan terdeteksi dalam input.'
    });
  }
  next();
};

// --- Middleware Auth ---
const checkAuthToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ status: 'error', message: 'Token JWT tidak ditemukan atau format salah.' });
  }
  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ status: 'error', message: 'Token JWT tidak valid atau kadaluwarsa.' });
    req.user = decoded;
    next();
  });
};

// --- Setup middleware ---
app.use(express.json());
app.use(logRequestDetails);
app.use(checkSqlInjection);

// --- Routes ---
// Register (example): simpan user dengan password hashed
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password) {
    return res.status(400).json({ status: 'error', message: 'username, email, password required' });
  }

  const hashed = await bcrypt.hash(password, 10);

  try {
    const conn = await pool.getConnection();
    try {
      const [result] = await conn.execute(
        'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
        [username, email, hashed]
      );
      res.status(201).json({ status: 'success', message: 'User registered', userId: result.insertId });
    } finally {
      conn.release();
    }
  } catch (e) {
    if (e && e.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ status: 'error', message: 'Username or email already exists' });
    }
    console.error('Register error:', e);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

// Login: cek ke DB dengan prepared statement (prevent SQL injection)
app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ status: 'error', message: 'username & password required' });
  }

  try {
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.execute(
        'SELECT id, username, password_hash, role FROM users WHERE username = ? LIMIT 1',
        [username]
      );

      if (!rows.length) {
        return res.status(401).json({ status: 'error', message: 'Invalid username or password credentials.' });
      }

      const user = rows[0];
      const passwordMatches = await bcrypt.compare(password, user.password_hash);

      if (!passwordMatches) {
        // optionally log failed attempt to audit_logs (best-effort)
        await conn.execute(
          'INSERT INTO audit_logs (request_id, user_id, event_type, details, ip_address) VALUES (?, ?, ?, ?, ?)',
          [req.requestId, user.id, 'login_failed', JSON.stringify({ username }), req.ip || 'N/A']
        );
        return res.status(401).json({ status: 'error', message: 'Invalid username or password credentials.' });
      }

      const payload = { id: user.id, username: user.username, role: user.role || 'user' };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

      // store successful login to audit_logs
      await conn.execute(
        'INSERT INTO audit_logs (request_id, user_id, event_type, details, ip_address) VALUES (?, ?, ?, ?, ?)',
        [req.requestId, user.id, 'login_success', JSON.stringify({ username }), req.ip || 'N/A']
      );

      return res.json({ status: 'success', message: 'Login successful', token });
    } finally {
      conn.release();
    }
  } catch (e) {
    console.error('Login error:', e);
    return res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

app.get('/', (req, res) => res.send(`Congratulations! Your Express server is running on port ${port}`));

app.get('/dummy-get', (req, res) =>
  res.json({
    status: 'success',
    method: 'GET',
    message: 'API GET for data.',
    data: { id: 1, name: 'important data', description: 'This is data from the server.' },
  })
);

app.post('/dummy-post', checkAuthToken, (req, res) => {
  const { body } = req;
  console.log('Received body (raw):', maskObject(body));
  res.status(201).json({
    status: 'success',
    method: 'POST',
    message: `Data successfully created (Authorized by ${req.user.role}).`,
    data_received: maskObject(body),
  });
});

app.delete('/dummy-delete/:id', checkAuthToken, (req, res) => {
  const { id } = req.params;
  console.log(`Attempting to delete item with ID: ${id}`);
  res.json({
    status: 'success',
    method: 'DELETE',
    message: `Item with ID ${id} successfully deleted (Authorized by ${req.user.role}).`,
  });
});

// --- Start server ---
app.listen(port, () => {
  console.log(`Application running on port ${port}!`);
  console.log(`[LOG FILE LOCATION] Check at: ${ACCESS_LOG_FILE}`);
});
