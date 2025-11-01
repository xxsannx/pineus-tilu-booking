// =============================================
// 🌲 Pineus Tilu Booking - Backend Server
// =============================================
require('dotenv').config();
const express = require('express');
const path = require('path');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const promBundle = require('express-prom-bundle');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------------------
// 🔧 Middleware
// ---------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(promBundle({ includeMethod: true }));

// ✅ Serve frontend statically (fix ENOENT)
app.use(express.static(path.join(__dirname, '../frontend')));

// ---------------------
// 🗄️ MySQL Connection
// ---------------------
let db;
(async () => {
  try {
    db = await mysql.createPool({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
      connectionLimit: 10,
    });
    console.log('✅ Terhubung ke MySQL');
  } catch (err) {
    console.error('❌ Gagal konek ke database:', err);
    process.exit(1);
  }
})();

// ---------------------
// 🔐 Session Middleware
// ---------------------
const sessions = {}; // { sessionId: userId }

function requireLogin(req, res, next) {
  const sid = req.cookies.sessionId;
  if (sid && sessions[sid]) {
    req.userId = sessions[sid];
    next();
  } else {
    res.status(401).json({ success: false, error: 'Silakan login terlebih dahulu.' });
  }
}

// ---------------------
// 🔢 OTP Helper
// ---------------------
function generateSalt() {
  return crypto.randomBytes(16).toString('hex');
}
function hashOtp(otp, salt) {
  return crypto.createHmac('sha256', salt).update(String(otp)).digest('hex');
}

// ---------------------
// 📧 Email Configuration
// ---------------------
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

async function sendOtpEmail(to, otp) {
  const html = `
  <div style="font-family: Arial; padding: 10px;">
    <h2>Kode OTP Booking Pineus Tilu</h2>
    <p>Gunakan kode berikut untuk verifikasi booking Anda:</p>
    <h1 style="letter-spacing:4px;">${otp}</h1>
    <p>Kode berlaku selama 5 menit.</p>
  </div>`;
  try {
    await transporter.sendMail({
      from: `Pineus Tilu <${process.env.GMAIL_USER}>`,
      to,
      subject: 'Kode OTP Booking Anda',
      html,
    });
    console.log('📩 OTP terkirim ke', to);
  } catch (err) {
    console.error('❌ Gagal kirim email:', err.message);
  }
}

// ---------------------
// 👤 Auth Routes
// ---------------------
app.post('/api/register', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password)
    return res.json({ success: false, error: 'Semua field wajib diisi.' });

  try {
    const [exist] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
    if (exist.length > 0)
      return res.json({ success: false, error: 'Email sudah terdaftar.' });

    const hash = await bcrypt.hash(password, 10);
    const id = uuidv4();
    await db.query(
      'INSERT INTO users (id,name,email,phone,password_hash) VALUES (?,?,?,?,?)',
      [id, name, email, phone, hash]
    );
    res.json({ success: true, message: 'Registrasi berhasil!' });
  } catch (err) {
    console.error('❌ Error register:', err);
    res.json({ success: false, error: 'Terjadi kesalahan server.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0)
      return res.json({ success: false, error: 'Email tidak ditemukan.' });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok)
      return res.json({ success: false, error: 'Password salah.' });

    const sessionId = uuidv4();
    sessions[sessionId] = user.id;
    res.cookie('sessionId', sessionId, { httpOnly: true });
    res.json({ success: true, message: 'Login berhasil!' });
  } catch (err) {
    console.error('❌ Error login:', err);
    res.json({ success: false, error: 'Kesalahan server.' });
  }
});

app.post('/api/logout', (req, res) => {
  const sid = req.cookies.sessionId;
  if (sid) delete sessions[sid];
  res.clearCookie('sessionId');
  res.json({ success: true, message: 'Logout berhasil.' });
});

// ---------------------
// 🏕️ Booking Routes
// ---------------------
app.post('/api/book', requireLogin, async (req, res) => {
  const { bookingDate, amount } = req.body;
  if (!bookingDate || !amount)
    return res.json({ success: false, error: 'Semua field wajib diisi.' });

  try {
    const bookingId = uuidv4();
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const salt = generateSalt();
    const otpHash = hashOtp(otp, salt);
    const otpExpires = Date.now() + 5 * 60 * 1000;

    const [userRows] = await db.query('SELECT email FROM users WHERE id = ?', [req.userId]);
    const userEmail = userRows[0]?.email;

    await db.query(
      `INSERT INTO bookings (id,user_id,booking_date,amount,otp_hash,otp_salt,otp_expires,created_at)
       VALUES (?,?,?,?,?,?,?,NOW())`,
      [bookingId, req.userId, bookingDate, amount, otpHash, salt, otpExpires]
    );

    await sendOtpEmail(userEmail, otp);
    res.json({ success: true, message: 'Booking berhasil. OTP dikirim ke email.', bookingId });
  } catch (err) {
    console.error('❌ Error booking:', err);
    res.json({ success: false, error: 'Gagal membuat booking.' });
  }
});

app.post('/api/verify', requireLogin, async (req, res) => {
  const { bookingId, otp } = req.body;
  try {
    const [rows] = await db.query(
      'SELECT * FROM bookings WHERE id = ? AND user_id = ?',
      [bookingId, req.userId]
    );
    if (rows.length === 0)
      return res.json({ success: false, error: 'Booking tidak ditemukan.' });

    const booking = rows[0];
    if (Date.now() > booking.otp_expires)
      return res.json({ success: false, error: 'OTP kedaluwarsa.' });

    const hash = hashOtp(otp, booking.otp_salt);
    if (hash !== booking.otp_hash)
      return res.json({ success: false, error: 'OTP salah.' });

    await db.query('UPDATE bookings SET is_verified = 1 WHERE id = ?', [bookingId]);
    res.json({ success: true, message: 'Booking terverifikasi!' });
  } catch (err) {
    console.error('❌ Error verify:', err);
    res.json({ success: false, error: 'Gagal verifikasi OTP.' });
  }
});

app.get('/api/bookings', requireLogin, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT id, booking_date, amount, is_verified, created_at FROM bookings WHERE user_id = ? ORDER BY created_at DESC',
      [req.userId]
    );
    res.json({ success: true, bookings: rows });
  } catch (err) {
    res.json({ success: false, error: 'Gagal memuat data booking.' });
  }
});

// ---------------------
// 🧭 Frontend Route
// ---------------------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// ---------------------
// 🚀 Jalankan Server
// ---------------------
app.listen(PORT, () => {
  console.log(`🚀 Pineus Tilu berjalan di http://localhost:${PORT}`);
});
