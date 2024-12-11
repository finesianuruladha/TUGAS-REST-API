const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const app = express();

app.use(express.json());

const users = []; 
const validTokens = new Set();
const invalidTokens = new Set();
const accessLog = [];

const secretKey = 'your_secret_key';

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 100 // batas maksimal permintaan per 15 menit
});

app.use(limiter);

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });
  res.status(201).send('User registered');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ username: user.username }, secretKey, { expiresIn: '1h' });
    validTokens.add(token);
    res.json({ token });
  } else {
    res.status(401).send('Invalid credentials');
  }
});

app.post('/logout', (req, res) => {
  const { token } = req.body;
  invalidTokens.add(token);
  validTokens.delete(token);
  res.send('Logged out');
});

app.use((req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    if (invalidTokens.has(token)) {
      return res.status(403).send('Token revoked');
    }
    try {
      const decoded = jwt.verify(token, secretKey);
      req.user = decoded;
      validTokens.add(token);
      next();
    } catch {
      res.status(401).send('Invalid token');
    }
  } else {
    res.status(401).send('No token provided');
  }
});

app.get('/data', (req, res) => {
  const { username } = req.user;
  accessLog.push({ username, date: new Date() });
  res.send('Data accessed');
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
