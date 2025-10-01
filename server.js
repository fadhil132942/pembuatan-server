const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;

// Middleware untuk membaca JSON
app.use(express.json());

// ===== Middleware Autentikasi JWT =====
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Unauthorized, token missing' });

  jwt.verify(token, 'RAHASIA_JWT', (err, user) => {
    if (err) return res.status(403).json({ error: 'Forbidden, token invalid' });
    req.user = user;
    next();
  });
}

// ===== Dummy Login untuk dapat token =====
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Contoh validasi login sederhana (dummy, bukan database)
  if (username === 'admin' && password === '1234') {
    const token = jwt.sign({ name: username }, 'RAHASIA_JWT', { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid username or password' });
  }
});

// ===== Root route =====
app.get('/', (req, res) => {
  res.send(`Congratulations! Your Express server is running on port ${port}`);
});

// ===== Dummy GET (tanpa proteksi) =====
app.get('/dummy-get', (req, res) => {
  res.json({ message: 'This is a dummy GET API' });
});

// ===== Dummy POST (butuh proteksi) =====
app.post('/dummy-post', authenticateToken, (req, res) => {
  const body = req.body;

  // Simulasi proteksi SQL Injection (validasi input, hanya string/angka yang aman)
  if (typeof body.text !== 'string') {
    return res.status(400).json({ error: 'Invalid input format' });
  }

  console.log('Received body:', body);
  res.json({
    message: 'This is a dummy POST API (protected)',
    youSent: body
  });
});

// ===== Dummy DELETE (butuh proteksi) =====
app.delete('/dummy-delete/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  // Validasi ID biar tidak bisa injection
  if (!/^\d+$/.test(id)) {
    return res.status(400).json({ error: 'Invalid ID format' });
  }

  res.json({ message: `Item with id ${id} has been deleted (dummy).` });
});

// ===== Jalankan server =====
app.listen(port, () => {
  console.log(`Example app listening on port ${port}!`);
});
