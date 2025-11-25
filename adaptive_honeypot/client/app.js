// client/app.js
require('dotenv').config();
const express = require('express');
const path = require('path');

const app = express();

// important: parse JSON BEFORE honeypot middleware so req.body is available
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// tiny helpful startup logs
console.log("Client start - pid:", process.pid);
console.log("HONEYPOT_URL:", process.env.HONEYPOT_URL);

// register honeypot middleware (ensure this path is correct)
const honeypot = require('./middleware/express-honeypot');
app.use(honeypot());

// demo routes
app.get('/', (req, res) => {
  res.send("Client real app running");
});

app.post('/login', (req, res) => {
  console.log("[APP] /login body:", req.body);
  res.send("Normal login response");
});

const PORT = process.env.CLIENT_PORT || 3000;
app.listen(PORT, () => {
  console.log(`Client app listening on port ${PORT}`);
});
