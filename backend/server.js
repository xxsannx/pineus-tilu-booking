require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));
app.use(cookieParser());

// Connect MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

// Session (sederhana)
const sessions = {};

// Middleware login
function requireLogin(req, res, next) {
  const sid = req.cookies.sessionId;
  if (sid && sessions[sid]) return next();
  return res.status(401).json({ success: false, error: 'Harus login' });
}

// Email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS }
});

// Helpers
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
function generateSalt() {
  return crypto.randomBytes(16).toString('hex');
}
function hashOtp(otp, salt) {
  return crypto.createHmac('sha256', salt).update(String(otp)).digest('hex');
}

// ROUTES

// Register
app.post('/api/register', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !password) return res.json({ success: false, error: 'Data tidak lengkap' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const conn = await pool.getConnection();
    await conn.query('INSERT INTO users VALUES (?, ?, ?, ?, ?)', [id, name, email, phone, hash]);
    conn.release();
    res.json({ success: true, message: 'Registrasi berhasil' });
  } catch (err) {
    console.error(err);
    res.json({ success: false, error: 'Email sudah digunakan' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const conn = await pool.getConnection();
  const [rows] = await conn.query('SELECT * FROM users WHERE email = ?', [email]);
  conn.release();
  if (!rows.length) return res.json({ success: false, error: 'Email tidak ditemukan' });
  const user = rows[0];
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.json({ success: false, error: 'Password salah' });
  const sid = uuidv4();
  sessions[sid] = user.id;
  res.cookie('sessionId', sid, { httpOnly: true });
  res.json({ success: true, message: 'Login berhasil' });
});

// Booking
app.post('/api/book', requireLogin, async (req, res) => {
  const { bookingDate, amount, email } = req.body;
  const otp = generateOtp();
  const salt = generateSalt();
  const otpHash = hashOtp(otp, salt);
  const expires = Date.now() + 5 * 60 * 1000;
  const id = uuidv4();
  const conn = await pool.getConnection();
  await conn.query('INSERT INTO bookings (id, user_id, booking_date, amount, otp_hash, otp_salt, otp_expires) VALUES (?, ?, ?, ?, ?, ?, ?)', [
    id, sessions[req.cookies.sessionId], bookingDate, amount, otpHash, salt, expires
  ]);
  conn.release();
  await transporter.sendMail({
    from: process.env.GMAIL_USER,
    to: email,
    subject: 'OTP Booking Pineus Tilu',
    html: `<h2>Kode OTP Anda</h2><h1>${otp}</h1><p>Berlaku 5 menit.</p>`
  });
  res.json({ success: true, message: 'OTP dikirim ke email.', bookingId: id });
});

// Verify
app.post('/api/verify', requireLogin, async (req, res) => {
  const { bookingId, otp } = req.body;
  const conn = await pool.getConnection();
  const [rows] = await conn.query('SELECT * FROM bookings WHERE id = ?', [bookingId]);
  conn.release();
  if (!rows.length) return res.json({ success: false, error: 'Booking tidak ditemukan' });
  const booking = rows[0];
  if (Date.now() > booking.otp_expires) return res.json({ success: false, error: 'OTP kadaluarsa' });
  const hash = hashOtp(otp, booking.otp_salt);
  if (hash === booking.otp_hash) {
    const conn2 = await pool.getConnection();
    await conn2.query('UPDATE bookings SET is_verified = 1 WHERE id = ?', [bookingId]);
    conn2.release();
    res.json({ success: true, message: 'Booking terverifikasi!' });
  } else {
    res.json({ success: false, error: 'OTP salah' });
  }
});

// List Booking
app.get('/api/bookings', requireLogin, async (req, res) => {
  const conn = await pool.getConnection();
  const [rows] = await conn.query('SELECT * FROM bookings WHERE user_id = ?', [sessions[req.cookies.sessionId]]);
  conn.release();
  res.json({ success: true, bookings: rows });
});

app.listen(PORT, () => console.log(`🌲 Pineus Tilu running at http://localhost:${PORT}`));
