// ChargEase Backend v3.1 — server.js
// PostGIS + Redis Cache + Socket.IO + Phone/Email Login + OTP + Forgot Password
// npm install express pg cors bcryptjs jsonwebtoken socket.io dotenv ioredis nodemailer

require('dotenv').config();
const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const { Pool }   = require('pg');// ChargEase Backend v3.2 — server.js
// PostGIS + Redis Cache + Socket.IO + Phone/Email Login + OTP + Forgot Password
// npm install express pg cors bcryptjs jsonwebtoken socket.io dotenv ioredis

require('dotenv').config();
const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const { Pool }   = require('pg');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const Redis      = require('ioredis');

// ─── App Setup ───────────────────────────────────────────────────────────────

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());

const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'chargeease-secret';

// ─── PostgreSQL ───────────────────────────────────────────────────────────────

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.connect()
  .then(() => console.log('✅ PostgreSQL + PostGIS connected'))
  .catch(err => console.error('❌ DB error:', err.message));

// ─── Redis Cache ──────────────────────────────────────────────────────────────

const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
  maxRetriesPerRequest: 3,
  lazyConnect: true,
  connectTimeout: 5000,
});

redis.on('connect', () => console.log('✅ Redis connected'));
redis.on('error',   (e) => console.warn('⚠️  Redis unavailable (DB fallback):', e.message));

async function cacheGet(key) {
  try { const v = await redis.get(key); return v ? JSON.parse(v) : null; }
  catch { return null; }
}
async function cacheSet(key, data, ttl = 30) {
  try { await redis.setex(key, ttl, JSON.stringify(data)); } catch {}
}
async function cacheDel(pattern) {
  try { const keys = await redis.keys(pattern); if (keys.length) await redis.del(...keys); } catch {}
}

// ─── Resend Email Setup ───────────────────────────────────────────────────────

const otpStore = {}; // { email: { otp, expiresAt } }

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTPEmail(email, otp, purpose = 'verification') {
  const subject = purpose === 'forgot'
    ? 'ChargEase — Password Reset OTP'
    : 'ChargEase — Email Verification OTP';

  const html = `
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;border:1px solid #e0e0e0;border-radius:12px;">
      <h2 style="color:#00C853;">⚡ ChargEase</h2>
      <p>Tumhara OTP code hai:</p>
      <div style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#333;text-align:center;padding:16px;background:#f5f5f5;border-radius:8px;">
        ${otp}
      </div>
      <p style="color:#888;font-size:13px;margin-top:16px;">Yeh OTP 10 minutes mein expire ho jayega. Kisi ke saath share mat karo.</p>
    </div>
  `;

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: 'ChargEase <onboarding@resend.dev>',
      to: [email],
      subject,
      html,
    }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.message || 'Resend API error');
  }

  console.log('✅ OTP email sent via Resend to:', email);
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

// ─── Health Check ─────────────────────────────────────────────────────────────

app.get('/', (req, res) => res.json({
  status: 'ChargEase API running',
  version: '3.2',
  features: ['PostGIS', 'Redis Cache', 'Socket.IO', 'Phone+Email Login', 'OTP', 'Forgot Password', 'Resend Email']
}));

app.get('/health', (req, res) => res.json({ status: 'ok', version: '3.2' }));

// ════════════════════════════════════════════════════════════════════════════
// OTP ROUTES
// ════════════════════════════════════════════════════════════════════════════

app.post('/api/auth/send-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required hai' });

  const otp = generateOTP();
  otpStore[email.toLowerCase()] = {
    otp,
    expiresAt: Date.now() + 10 * 60 * 1000,
  };

  try {
    await sendOTPEmail(email.toLowerCase(), otp, 'verification');
    res.json({ message: 'OTP bhej diya gaya — email check karo' });
  } catch (err) {
    console.error('OTP send error:', err.message);
    res.status(500).json({ error: 'OTP bhejne mein problem aayi: ' + err.message });
  }
});

app.post('/api/auth/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email aur OTP required hai' });

  const record = otpStore[email.toLowerCase()];
  if (!record)                        return res.status(400).json({ error: 'Pehle OTP mangao' });
  if (Date.now() > record.expiresAt)  return res.status(400).json({ error: 'OTP expire ho gaya' });
  if (record.otp !== otp.toString())  return res.status(400).json({ error: 'OTP galat hai' });

  delete otpStore[email.toLowerCase()];
  res.json({ message: 'OTP verified', verified: true });
});

// ════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════════════════════════════════════════

app.post('/api/auth/register', async (req, res) => {
  const { name, email, phone, password, role, vehicle_type } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Name, email aur password required hai' });
  try {
    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    if (exists.rows.length)
      return res.status(409).json({ error: 'Yeh email already registered hai' });

    if (phone) {
      const phoneExists = await pool.query('SELECT id FROM users WHERE phone=$1', [phone.trim()]);
      if (phoneExists.rows.length)
        return res.status(409).json({ error: 'Yeh phone number already registered hai' });
    }

    const hash   = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (name, email, phone, password_hash, role, vehicle_type)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, name, email, phone, role, vehicle_type`,
      [name.trim(), email.toLowerCase().trim(), phone||null, hash, role||'ev_owner', vehicle_type||null]
    );
    const user  = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user });
  } catch(err) {
    console.error('Register error:', err.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, phone, password } = req.body;
  if ((!email && !phone) || !password)
    return res.status(400).json({ error: 'Email/phone aur password required hai' });

  try {
    let result;
    if (email) {
      result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    } else {
      result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone.trim()]);
    }

    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash)))
      return res.status(401).json({ error: 'Email/phone ya password galat hai' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id:           user.id,
        name:         user.name,
        email:        user.email,
        phone:        user.phone,
        role:         user.role,
        vehicle_type: user.vehicle_type
      }
    });
  } catch(err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, phone, role, vehicle_type, created_at FROM users WHERE id=$1',
      [req.user.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch { res.status(500).json({ error: 'Failed to fetch profile' }); }
});

// ════════════════════════════════════════════════════════════════════════════
// FORGOT PASSWORD ROUTES
// ════════════════════════════════════════════════════════════════════════════

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required hai' });

  try {
    const result = await pool.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    if (!result.rows[0]) {
      return res.json({ message: 'Agar email registered hai toh OTP bhej diya gaya' });
    }

    const otp = generateOTP();
    otpStore[`forgot:${email.toLowerCase()}`] = {
      otp,
      expiresAt: Date.now() + 10 * 60 * 1000,
    };

    await sendOTPEmail(email.toLowerCase(), otp, 'forgot');
    res.json({ message: 'Password reset OTP bhej diya gaya — email check karo' });
  } catch (err) {
    console.error('Forgot password error:', err.message);
    res.status(500).json({ error: 'OTP bhejne mein problem aayi: ' + err.message });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword)
    return res.status(400).json({ error: 'Email, OTP aur naya password required hai' });

  const key    = `forgot:${email.toLowerCase()}`;
  const record = otpStore[key];

  if (!record)                       return res.status(400).json({ error: 'Pehle forgot password request karo' });
  if (Date.now() > record.expiresAt) return res.status(400).json({ error: 'OTP expire ho gaya' });
  if (record.otp !== otp.toString()) return res.status(400).json({ error: 'OTP galat hai' });

  try {
    const hash = await bcrypt.hash(newPassword, 10);
    const result = await pool.query(
      'UPDATE users SET password_hash=$1 WHERE email=$2 RETURNING id',
      [hash, email.toLowerCase().trim()]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });

    delete otpStore[key];
    res.json({ message: 'Password successfully reset ho gaya — ab login karo' });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ error: 'Password reset failed' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// STATIONS ROUTES (PostGIS + Redis Cache)
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/stations', async (req, res) => {
  const { search, status, charger_type, lat, lng, radius } = req.query;
  const cacheKey = `stations:${search||''}:${status||''}:${charger_type||''}:${lat||''}:${lng||''}:${radius||''}`;

  const cached = await cacheGet(cacheKey);
  if (cached) { res.setHeader('X-Cache','HIT'); return res.json(cached); }

  try {
    let query, params = [];

    if (lat && lng) {
      const radiusM = parseFloat(radius) || 10000;
      query = `
        SELECT *,
          ROUND(ST_Distance(
            location::geography,
            ST_MakePoint($1,$2)::geography
          )) AS distance_meters,
          ROUND((available_slots::numeric / NULLIF(total_slots,0)) * 100) AS availability_pct
        FROM stations
        WHERE ST_DWithin(location::geography, ST_MakePoint($1,$2)::geography, $3)
        ${status ? 'AND status=$4' : ''}
        ${charger_type ? `AND charger_types ILIKE $${status?5:4}` : ''}
        ORDER BY distance_meters ASC
      `;
      params = [parseFloat(lng), parseFloat(lat), radiusM];
      if (status)       params.push(status);
      if (charger_type) params.push(`%${charger_type}%`);
    } else {
      query = `
        SELECT *,
          ROUND((available_slots::numeric / NULLIF(total_slots,0)) * 100) AS availability_pct
        FROM stations WHERE 1=1
        ${search       ? `AND (name ILIKE $${params.length+1} OR address ILIKE $${params.length+1})` : ''}
        ${status       ? `AND status=$${params.length+(search?2:1)}` : ''}
        ${charger_type ? `AND charger_types ILIKE $${params.length+(search?1:0)+(status?1:0)+1}` : ''}
        ORDER BY name ASC
      `;
      if (search)       params.push(`%${search}%`);
      if (status)       params.push(status);
      if (charger_type) params.push(`%${charger_type}%`);
    }

    const result = await pool.query(query, params);
    await cacheSet(cacheKey, result.rows, 30);
    res.setHeader('X-Cache','MISS');
    res.json(result.rows);
  } catch(err) {
    console.error('Stations error:', err.message);
    res.status(500).json({ error: 'Failed to fetch stations' });
  }
});

app.get('/api/stations/nearest', async (req, res) => {
  const { lat, lng } = req.query;
  if (!lat || !lng) return res.status(400).json({ error: 'lat and lng required' });

  const cacheKey = `nearest:${parseFloat(lat).toFixed(3)}:${parseFloat(lng).toFixed(3)}`;
  const cached   = await cacheGet(cacheKey);
  if (cached) return res.json(cached);

  try {
    const result = await pool.query(`
      SELECT *,
        ROUND(ST_Distance(location::geography, ST_MakePoint($1,$2)::geography)) AS distance_meters
      FROM stations
      WHERE status != 'offline'
      ORDER BY location <-> ST_MakePoint($1,$2)::geography
      LIMIT 3
    `, [parseFloat(lng), parseFloat(lat)]);
    await cacheSet(cacheKey, result.rows, 15);
    res.json(result.rows);
  } catch(err) {
    console.error('Nearest error:', err.message);
    res.status(500).json({ error: 'Failed to find nearest stations' });
  }
});

app.get('/api/stations/:id', async (req, res) => {
  const cacheKey = `station:${req.params.id}`;
  const cached   = await cacheGet(cacheKey);
  if (cached) return res.json(cached);
  try {
    const result = await pool.query('SELECT * FROM stations WHERE id=$1', [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Station not found' });
    await cacheSet(cacheKey, result.rows[0], 30);
    res.json(result.rows[0]);
  } catch { res.status(500).json({ error: 'Failed to fetch station' }); }
});

app.post('/api/stations', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  const { name, address, latitude, longitude, total_slots, price_per_kwh, charger_types } = req.body;
  if (!name || !address || !latitude || !longitude || !total_slots)
    return res.status(400).json({ error: 'Missing required fields' });
  try {
    const result = await pool.query(
      `INSERT INTO stations (name,address,latitude,longitude,total_slots,available_slots,price_per_kwh,charger_types,location)
       VALUES ($1,$2,$3,$4,$5,$5,$6,$7,ST_SetSRID(ST_MakePoint($8,$9),4326)) RETURNING *`,
      [name, address, latitude, longitude, total_slots, price_per_kwh||8.00, charger_types||'Type 2', longitude, latitude]
    );
    await cacheDel('stations:*');
    io.emit('station_updated', result.rows[0]);
    res.status(201).json(result.rows[0]);
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create station' });
  }
});

app.delete('/api/stations/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  try {
    const result = await pool.query('DELETE FROM stations WHERE id=$1 RETURNING id,name', [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Station not found' });
    await cacheDel(`station:${req.params.id}`);
    await cacheDel('stations:*');
    await cacheDel('nearest:*');
    io.emit('station_deleted', { id: req.params.id });
    res.json({ message: 'Station deleted', station: result.rows[0] });
  } catch(err) {
    console.error('Delete station error:', err.message);
    res.status(500).json({ error: 'Failed to delete station' });
  }
});

app.patch('/api/stations/:id/slots', authMiddleware, async (req, res) => {
  const { available_slots } = req.body;
  if (available_slots === undefined) return res.status(400).json({ error: 'available_slots required' });
  try {
    const result = await pool.query(
      `UPDATE stations SET
         available_slots=$1,
         status=CASE WHEN $1=0 THEN 'full'
                     WHEN $1::float/total_slots<0.4 THEN 'limited'
                     ELSE 'available' END,
         updated_at=NOW()
       WHERE id=$2 RETURNING *`,
      [available_slots, req.params.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Station not found' });
    await cacheDel(`station:${req.params.id}`);
    await cacheDel('stations:*');
    await cacheDel('nearest:*');
    io.emit('station_updated', result.rows[0]);
    res.json(result.rows[0]);
  } catch { res.status(500).json({ error: 'Failed to update slots' }); }
});

// ════════════════════════════════════════════════════════════════════════════
// BOOKINGS ROUTES
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/bookings', authMiddleware, async (req, res) => {
  const cacheKey = `bookings:user:${req.user.id}`;
  const cached   = await cacheGet(cacheKey);
  if (cached) return res.json(cached);
  try {
    const result = await pool.query(
      `SELECT b.*, s.name AS station_name, s.address AS station_address
       FROM bookings b JOIN stations s ON s.id=b.station_id
       WHERE b.user_id=$1 ORDER BY b.created_at DESC`,
      [req.user.id]
    );
    await cacheSet(cacheKey, result.rows, 60);
    res.json(result.rows);
  } catch { res.status(500).json({ error: 'Failed to fetch bookings' }); }
});

app.post('/api/bookings', authMiddleware, async (req, res) => {
  const { station_id, start_time, end_time } = req.body;
  if (!station_id || !start_time || !end_time)
    return res.status(400).json({ error: 'station_id, start_time and end_time required' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const stResult = await client.query('SELECT * FROM stations WHERE id=$1 FOR UPDATE', [station_id]);
    const station  = stResult.rows[0];
    if (!station)                     throw new Error('Station not found');
    if (station.available_slots <= 0) throw new Error('No slots available');

    const hours  = (new Date(end_time) - new Date(start_time)) / 3_600_000;
    const amount = +(hours * 7.4 * station.price_per_kwh).toFixed(2);

    const bookResult = await client.query(
      `INSERT INTO bookings (user_id,station_id,start_time,end_time,status,amount_paid)
       VALUES ($1,$2,$3,$4,'confirmed',$5) RETURNING *`,
      [req.user.id, station_id, start_time, end_time, amount]
    );
    await client.query(
      `UPDATE stations SET
         available_slots=available_slots-1,
         status=CASE WHEN available_slots-1=0 THEN 'full'
                     WHEN (available_slots-1)::float/total_slots<0.4 THEN 'limited'
                     ELSE 'available' END,
         updated_at=NOW()
       WHERE id=$1`,
      [station_id]
    );
    await client.query('COMMIT');

    await cacheDel(`station:${station_id}`);
    await cacheDel('stations:*');
    await cacheDel('nearest:*');
    await cacheDel(`bookings:user:${req.user.id}`);

    const updated = await pool.query('SELECT * FROM stations WHERE id=$1', [station_id]);
    io.emit('station_updated', updated.rows[0]);
    res.status(201).json({ booking: bookResult.rows[0], amount_paid: amount });
  } catch(err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.patch('/api/bookings/:id/cancel', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const bookResult = await client.query(
      'SELECT * FROM bookings WHERE id=$1 AND user_id=$2 FOR UPDATE',
      [req.params.id, req.user.id]
    );
    const booking = bookResult.rows[0];
    if (!booking)                       throw new Error('Booking not found');
    if (booking.status === 'cancelled') throw new Error('Already cancelled');

    await client.query("UPDATE bookings SET status='cancelled' WHERE id=$1", [req.params.id]);
    await client.query(
      `UPDATE stations SET
         available_slots=available_slots+1,
         status=CASE WHEN (available_slots+1)::float/total_slots>=0.4 THEN 'available'
                     ELSE 'limited' END,
         updated_at=NOW()
       WHERE id=$1`,
      [booking.station_id]
    );
    await client.query('COMMIT');

    await cacheDel(`station:${booking.station_id}`);
    await cacheDel('stations:*');
    await cacheDel('nearest:*');
    await cacheDel(`bookings:user:${req.user.id}`);

    const updated = await pool.query('SELECT * FROM stations WHERE id=$1', [booking.station_id]);
    io.emit('station_updated', updated.rows[0]);
    res.json({ message: 'Booking cancelled' });
  } catch(err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ════════════════════════════════════════════════════════════════════════════
// FEEDBACK & COMPLAINTS
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/feedback', async (req, res) => {
  const { station_id } = req.query;
  const cacheKey = `feedback:${station_id||'all'}`;
  const cached   = await cacheGet(cacheKey);
  if (cached) return res.json(cached);
  try {
    const result = await pool.query(
      `SELECT f.*, u.name AS user_name FROM feedback f
       JOIN users u ON u.id=f.user_id
       WHERE ($1::uuid IS NULL OR f.station_id=$1)
       ORDER BY f.created_at DESC LIMIT 50`,
      [station_id||null]
    );
    await cacheSet(cacheKey, result.rows, 120);
    res.json(result.rows);
  } catch(err) {
    console.error('Feedback fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch feedback' });
  }
});

app.post('/api/feedback', authMiddleware, async (req, res) => {
  const { station_id, rating, message } = req.body;
  if (!rating || rating < 1 || rating > 5)
    return res.status(400).json({ error: 'Rating 1-5 ke beech hona chahiye' });
  try {
    const result = await pool.query(
      'INSERT INTO feedback (user_id,station_id,rating,message) VALUES ($1,$2,$3,$4) RETURNING *',
      [req.user.id, station_id||null, rating, message||null]
    );
    await cacheDel('feedback:*');
    res.status(201).json(result.rows[0]);
  } catch(err) {
    console.error('Feedback submit error:', err.message);
    res.status(500).json({ error: 'Failed to submit feedback' });
  }
});

app.post('/api/complaints', authMiddleware, async (req, res) => {
  const { station_id, type, priority, description } = req.body;
  if (!type || !description)
    return res.status(400).json({ error: 'type aur description required hai' });
  try {
    const result = await pool.query(
      'INSERT INTO complaints (user_id,station_id,type,priority,description) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [req.user.id, station_id||null, type, priority||'medium', description]
    );
    res.status(201).json(result.rows[0]);
  } catch(err) {
    console.error('Complaint submit error:', err.message);
    res.status(500).json({ error: 'Failed to file complaint' });
  }
});

app.get('/api/complaints', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  try {
    const result = await pool.query(
      `SELECT c.*, u.name AS user_name, u.email AS user_email, s.name AS station_name
       FROM complaints c
       JOIN users u ON u.id=c.user_id
       LEFT JOIN stations s ON s.id=c.station_id
       ORDER BY c.created_at DESC`
    );
    res.json(result.rows);
  } catch { res.status(500).json({ error: 'Failed to fetch complaints' }); }
});

app.patch('/api/complaints/:id/status', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  const { status } = req.body;
  try {
    const result = await pool.query(
      'UPDATE complaints SET status=$1 WHERE id=$2 RETURNING *',
      [status, req.params.id]
    );
    res.json(result.rows[0]);
  } catch { res.status(500).json({ error: 'Failed to update complaint' }); }
});

// ════════════════════════════════════════════════════════════════════════════
// SOCKET.IO — Real-time slot broadcasting
// ════════════════════════════════════════════════════════════════════════════

io.on('connection', (socket) => {
  console.log(`🔌 Client connected: ${socket.id}`);
  (async () => {
    let stations = await cacheGet('stations:initial');
    if (!stations) {
      const result = await pool.query('SELECT * FROM stations ORDER BY name');
      stations = result.rows;
      await cacheSet('stations:initial', stations, 30);
    }
    socket.emit('stations_initial', stations);
  })();
  socket.on('disconnect', () => console.log(`🔌 Disconnected: ${socket.id}`));
});

setInterval(async () => {
  try {
    const stations = (await pool.query("SELECT * FROM stations WHERE status!='offline'")).rows;
    for (const st of stations) {
      if (Math.random() < 0.3) {
        const delta     = Math.random() < 0.5 ? 1 : -1;
        const newSlots  = Math.max(0, Math.min(st.total_slots, st.available_slots + delta));
        const newStatus = newSlots===0?'full':newSlots/st.total_slots<0.4?'limited':'available';
        await pool.query(
          'UPDATE stations SET available_slots=$1,status=$2,updated_at=NOW() WHERE id=$3',
          [newSlots, newStatus, st.id]
        );
        await cacheDel(`station:${st.id}`);
        await cacheDel('stations:*');
        await cacheDel('nearest:*');
        const updated = (await pool.query('SELECT * FROM stations WHERE id=$1',[st.id])).rows[0];
        io.emit('station_updated', updated);
      }
    }
  } catch(err) { console.error('Slot simulation error:', err.message); }
}, 7000);

// ─── Start ────────────────────────────────────────────────────────────────────

server.listen(PORT, () => {
  console.log(`🚀 ChargEase API v3.2 on http://localhost:${PORT}`);
  console.log(`   ✅ Email + Phone login: enabled`);
  console.log(`   ✅ OTP via Resend: enabled`);
  console.log(`   ✅ Forgot Password: enabled`);
  console.log(`   ✅ PostGIS nearest stations: enabled`);
  console.log(`   ✅ Redis cache: enabled`);
  console.log(`   ✅ Socket.IO real-time: enabled`);
});
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const Redis      = require('ioredis');
const nodemailer = require('nodemailer');

// ─── App Setup ───────────────────────────────────────────────────────────────

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());

const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'chargeease-secret';

// ─── PostgreSQL ───────────────────────────────────────────────────────────────

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.connect()
  .then(() => console.log('✅ PostgreSQL + PostGIS connected'))
  .catch(err => console.error('❌ DB error:', err.message));

// ─── Redis Cache ──────────────────────────────────────────────────────────────

const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
  maxRetriesPerRequest: 3,
  lazyConnect: true,
  connectTimeout: 5000,
});

redis.on('connect', () => console.log('✅ Redis connected'));
redis.on('error',   (e) => console.warn('⚠️  Redis unavailable (DB fallback):', e.message));

async function cacheGet(key) {
  try { const v = await redis.get(key); return v ? JSON.parse(v) : null; }
  catch { return null; }
}
async function cacheSet(key, data, ttl = 30) {
  try { await redis.setex(key, ttl, JSON.stringify(data)); } catch {}
}
async function cacheDel(pattern) {
  try { const keys = await redis.keys(pattern); if (keys.length) await redis.del(...keys); } catch {}
}

// ─── Nodemailer Setup ─────────────────────────────────────────────────────────

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

transporter.verify((err) => {
  if (err) console.error('❌ Gmail error:', err.message);
  else     console.log('✅ Gmail (Nodemailer) ready');
});

// OTP store in memory (Redis better hoga production mein — abhi simple hai)
const otpStore = {}; // { email: { otp, expiresAt } }

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTPEmail(email, otp, purpose = 'verification') {
  const subject = purpose === 'forgot'
    ? 'ChargEase — Password Reset OTP'
    : 'ChargEase — Email Verification OTP';

  const html = `
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;border:1px solid #e0e0e0;border-radius:12px;">
      <h2 style="color:#00C853;">⚡ ChargEase</h2>
      <p>Tumhara OTP code hai:</p>
      <div style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#333;text-align:center;padding:16px;background:#f5f5f5;border-radius:8px;">
        ${otp}
      </div>
      <p style="color:#888;font-size:13px;margin-top:16px;">Yeh OTP 10 minutes mein expire ho jayega. Kisi ke saath share mat karo.</p>
    </div>
  `;

  await transporter.sendMail({
    from: `"ChargEase" <${process.env.GMAIL_USER}>`,
    to: email,
    subject,
    html,
  });
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

// ─── Health Check ─────────────────────────────────────────────────────────────

app.get('/', (req, res) => res.json({
  status: 'ChargEase API running',
  version: '3.1',
  features: ['PostGIS', 'Redis Cache', 'Socket.IO', 'Phone+Email Login', 'OTP', 'Forgot Password']
}));

app.get('/health', (req, res) => res.json({ status: 'ok', version: '3.1' }));

// ════════════════════════════════════════════════════════════════════════════
// OTP ROUTES
// ════════════════════════════════════════════════════════════════════════════

// POST /api/auth/send-otp
// Body: { email }
app.post('/api/auth/send-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required hai' });

  const otp = generateOTP();
  otpStore[email.toLowerCase()] = {
    otp,
    expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
  };

  try {
    await sendOTPEmail(email.toLowerCase(), otp, 'verification');
    res.json({ message: 'OTP bhej diya gaya — email check karo' });
  } catch (err) {
    console.error('OTP send error:', err.message);
    res.status(500).json({ error: 'OTP bhejne mein problem aayi' });
  }
});

// POST /api/auth/verify-otp
// Body: { email, otp }
app.post('/api/auth/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email aur OTP required hai' });

  const record = otpStore[email.toLowerCase()];
  if (!record)                        return res.status(400).json({ error: 'Pehle OTP mangao' });
  if (Date.now() > record.expiresAt)  return res.status(400).json({ error: 'OTP expire ho gaya' });
  if (record.otp !== otp.toString())  return res.status(400).json({ error: 'OTP galat hai' });

  delete otpStore[email.toLowerCase()]; // one-time use
  res.json({ message: 'OTP verified', verified: true });
});

// ════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, phone, password, role, vehicle_type } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Name, email aur password required hai' });
  try {
    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    if (exists.rows.length)
      return res.status(409).json({ error: 'Yeh email already registered hai' });

    if (phone) {
      const phoneExists = await pool.query('SELECT id FROM users WHERE phone=$1', [phone.trim()]);
      if (phoneExists.rows.length)
        return res.status(409).json({ error: 'Yeh phone number already registered hai' });
    }

    const hash   = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (name, email, phone, password_hash, role, vehicle_type)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, name, email, phone, role, vehicle_type`,
      [name.trim(), email.toLowerCase().trim(), phone||null, hash, role||'ev_owner', vehicle_type||null]
    );
    const user  = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user });
  } catch(err) {
    console.error('Register error:', err.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, phone, password } = req.body;
  if ((!email && !phone) || !password)
    return res.status(400).json({ error: 'Email/phone aur password required hai' });

  try {
    let result;
    if (email) {
      result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    } else {
      result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone.trim()]);
    }

    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash)))
      return res.status(401).json({ error: 'Email/phone ya password galat hai' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id:           user.id,
        name:         user.name,
        email:        user.email,
        phone:        user.phone,
        role:         user.role,
        vehicle_type: user.vehicle_type
      }
    });
  } catch(err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, phone, role, vehicle_type, created_at FROM users WHERE id=$1',
      [req.user.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch { res.status(500).json({ error: 'Failed to fetch profile' }); }
});

// ════════════════════════════════════════════════════════════════════════════
// FORGOT PASSWORD ROUTES
// ════════════════════════════════════════════════════════════════════════════

// POST /api/auth/forgot-password
// Body: { email }
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required hai' });

  try {
    const result = await pool.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    // Security: user exist kare ya na kare — same response dete hain
    if (!result.rows[0]) {
      return res.json({ message: 'Agar email registered hai toh OTP bhej diya gaya' });
    }

    const otp = generateOTP();
    otpStore[`forgot:${email.toLowerCase()}`] = {
      otp,
      expiresAt: Date.now() + 10 * 60 * 1000,
    };

    await sendOTPEmail(email.toLowerCase(), otp, 'forgot');
    res.json({ message: 'Password reset OTP bhej diya gaya — email check karo' });
  } catch (err) {
    console.error('Forgot password error:', err.message);
    res.status(500).json({ error: 'OTP bhejne mein problem aayi' });
  }
});

// POST /api/auth/reset-password
// Body: { email, otp, newPassword }
app.post('/api/auth/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword)
    return res.status(400).json({ error: 'Email, OTP aur naya password required hai' });

  const key    = `forgot:${email.toLowerCase()}`;
  const record = otpStore[key];

  if (!record)                       return res.status(400).json({ error: 'Pehle forgot password request karo' });
  if (Date.now() > record.expiresAt) return res.status(400).json({ error: 'OTP expire ho gaya' });
  if (record.otp !== otp.toString()) return res.status(400).json({ error: 'OTP galat hai' });

  try {
    const hash = await bcrypt.hash(newPassword, 10);
    const result = await pool.query(
      'UPDATE users SET password_hash=$1 WHERE email=$2 RETURNING id',
      [hash, email.toLowerCase().trim()]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });

    delete otpStore[key];
    res.json({ message: 'Password successfully reset ho gaya — ab login karo' });
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.status(500).json({ error: 'Password reset failed' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// STATIONS ROUTES (PostGIS + Redis Cache)
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/stations', async (req, res) => {
  const { search, status, charger_type, lat, lng, radius } = req.query;
  const cacheKey = `stations:${search||''}:${status||''}:${charger_type||''}:${lat||''}:${lng||''}:${radius||''}`;

  const cached = await cacheGet(cacheKey);
  if (cached) { res.setHeader('X-Cache','HIT'); return res.json(cached); }

  try {
    let query, params = [];

    if (lat && lng) {
      const radiusM = parseFloat(radius) || 10000;
      query = `
        SELECT *,
          ROUND(ST_Distance(
            location::geography,
            ST_MakePoint($1,$2)::geography
          )) AS distance_meters,
          ROUND((available_slots::numeric / NULLIF(total_slots,0)) * 100) AS availability_pct
        FROM stations
        WHERE ST_DWithin(location::geography, ST_MakePoint($1,$2)::geography, $3)
        ${status ? 'AND status=$4' : ''}
        ${charger_type ? `AND charger_types ILIKE $${status?5:4}` : ''}
        ORDER BY distance_meters ASC
      `;
      params = [parseFloat(lng), parseFloat(lat), radiusM];
      if (status)       params.push(status);
      if (charger_type) params.push(`%${charger_type}%`);
    } else {
      query = `
        SELECT *,
          ROUND((available_slots::numeric / NULLIF(total_slots,0)) * 100) AS availability_pct
        FROM stations WHERE 1=1
        ${search       ? `AND (name ILIKE $${params.length+1} OR address ILIKE $${params.length+1})` : ''}
        ${status       ? `AND status=$${params.length+(search?2:1)}` : ''}
        ${charger_type ? `AND charger_types ILIKE $${params.length+(search?1:0)+(status?1:0)+1}` : ''}
        ORDER BY name ASC
      `;
      if (search)       params.push(`%${search}%`);
      if (status)       params.push(status);
      if (charger_type) params.push(`%${charger_type}%`);
    }

    const result = await pool.query(query, params);
    await cacheSet(cacheKey, result.rows, 30);
    res.setHeader('X-Cache','MISS');
    res.json(result.rows);
  } catch(err) {
    console.error('Stations error:', err.message);
    res.status(500).json({ error: 'Failed to fetch stations' });
  }
});

app.get('/api/stations/nearest', async (req, res) => {
  const { lat, lng } = req.query;
  if (!lat || !lng) return res.status(400).json({ error: 'lat and lng required' });

  const cacheKey = `nearest:${parseFloat(lat).toFixed(3)}:${parseFloat(lng).toFixed(3)}`;
  const cached   = await cacheGet(cacheKey);
  if (cached) return res.json(cached);

  try {
    const result = await pool.query(`
      SELECT *,
        ROUND(ST_Distance(location::geography, ST_MakePoint($1,$2)::geography)) AS distance_meters
      FROM stations
      WHERE status != 'offline'
      ORDER BY location <-> ST_MakePoint($1,$2)::geography
      LIMIT 3
    `, [parseFloat(lng), parseFloat(lat)]);
    await cacheSet(cacheKey, result.rows, 15);
    res.json(result.rows);
  } catch(err) {
    console.error('Nearest error:', err.message);
    res.status(500).json({ error: 'Failed to find nearest stations' });
  }
});

app.get('/api/stations/:id', async (req, res) => {
  const cacheKey = `station:${req.params.id}`;
  const cached   = await cacheGet(cacheKey);
  if (cached) return res.json(cached);
  try {
    const result = await pool.query('SELECT * FROM stations WHERE id=$1', [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Station not found' });
    await cacheSet(cacheKey, result.rows[0], 30);
    res.json(result.rows[0]);
  } catch { res.status(500).json({ error: 'Failed to fetch station' }); }
});

app.post('/api/stations', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  const { name, address, latitude, longitude, total_slots, price_per_kwh, charger_types } = req.body;
  if (!name || !address || !latitude || !longitude || !total_slots)
    return res.status(400).json({ error: 'Missing required fields' });
  try {
    const result = await pool.query(
      `INSERT INTO stations (name,address,latitude,longitude,total_slots,available_slots,price_per_kwh,charger_types,location)
       VALUES ($1,$2,$3,$4,$5,$5,$6,$7,ST_SetSRID(ST_MakePoint($8,$9),4326)) RETURNING *`,
      [name, address, latitude, longitude, total_slots, price_per_kwh||8.00, charger_types||'Type 2', longitude, latitude]
    );
    await cacheDel('stations:*');
    io.emit('station_updated', result.rows[0]);
    res.status(201).json(result.rows[0]);
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create station' });
  }
});

app.delete('/api/stations/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  try {
    const result = await pool.query('DELETE FROM stations WHERE id=$1 RETURNING id,name', [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Station not found' });
    await cacheDel(`station:${req.params.id}`);
    await cacheDel('stations:*');
    await cacheDel('nearest:*');
    io.emit('station_deleted', { id: req.params.id });
    res.json({ message: 'Station deleted', station: result.rows[0] });
  } catch(err) {
    console.error('Delete station error:', err.message);
    res.status(500).json({ error: 'Failed to delete station' });
  }
});

app.patch('/api/stations/:id/slots', authMiddleware, async (req, res) => {
  const { available_slots } = req.body;
  if (available_slots === undefined) return res.status(400).json({ error: 'available_slots required' });
  try {
    const result = await pool.query(
      `UPDATE stations SET
         available_slots=$1,
         status=CASE WHEN $1=0 THEN 'full'
                     WHEN $1::float/total_slots<0.4 THEN 'limited'
                     ELSE 'available' END,
         updated_at=NOW()
       WHERE id=$2 RETURNING *`,
      [available_slots, req.params.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Station not found' });
    await cacheDel(`station:${req.params.id}`);
    await cacheDel('stations:*');
    await cacheDel('nearest:*');
    io.emit('station_updated', result.rows[0]);
    res.json(result.rows[0]);
  } catch { res.status(500).json({ error: 'Failed to update slots' }); }
});

// ════════════════════════════════════════════════════════════════════════════
// BOOKINGS ROUTES
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/bookings', authMiddleware, async (req, res) => {
  const cacheKey = `bookings:user:${req.user.id}`;
  const cached   = await cacheGet(cacheKey);
  if (cached) return res.json(cached);
  try {
    const result = await pool.query(
      `SELECT b.*, s.name AS station_name, s.address AS station_address
       FROM bookings b JOIN stations s ON s.id=b.station_id
       WHERE b.user_id=$1 ORDER BY b.created_at DESC`,
      [req.user.id]
    );
    await cacheSet(cacheKey, result.rows, 60);
    res.json(result.rows);
  } catch { res.status(500).json({ error: 'Failed to fetch bookings' }); }
});

app.post('/api/bookings', authMiddleware, async (req, res) => {
  const { station_id, start_time, end_time } = req.body;
  if (!station_id || !start_time || !end_time)
    return res.status(400).json({ error: 'station_id, start_time and end_time required' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const stResult = await client.query('SELECT * FROM stations WHERE id=$1 FOR UPDATE', [station_id]);
    const station  = stResult.rows[0];
    if (!station)                     throw new Error('Station not found');
    if (station.available_slots <= 0) throw new Error('No slots available');

    const hours  = (new Date(end_time) - new Date(start_time)) / 3_600_000;
    const amount = +(hours * 7.4 * station.price_per_kwh).toFixed(2);

    const bookResult = await client.query(
      `INSERT INTO bookings (user_id,station_id,start_time,end_time,status,amount_paid)
       VALUES ($1,$2,$3,$4,'confirmed',$5) RETURNING *`,
      [req.user.id, station_id, start_time, end_time, amount]
    );
    await client.query(
      `UPDATE stations SET
         available_slots=available_slots-1,
         status=CASE WHEN available_slots-1=0 THEN 'full'
                     WHEN (available_slots-1)::float/total_slots<0.4 THEN 'limited'
                     ELSE 'available' END,
         updated_at=NOW()
       WHERE id=$1`,
      [station_id]
    );
    await client.query('COMMIT');

    await cacheDel(`station:${station_id}`);
    await cacheDel('stations:*');
    await cacheDel('nearest:*');
    await cacheDel(`bookings:user:${req.user.id}`);

    const updated = await pool.query('SELECT * FROM stations WHERE id=$1', [station_id]);
    io.emit('station_updated', updated.rows[0]);
    res.status(201).json({ booking: bookResult.rows[0], amount_paid: amount });
  } catch(err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.patch('/api/bookings/:id/cancel', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const bookResult = await client.query(
      'SELECT * FROM bookings WHERE id=$1 AND user_id=$2 FOR UPDATE',
      [req.params.id, req.user.id]
    );
    const booking = bookResult.rows[0];
    if (!booking)                       throw new Error('Booking not found');
    if (booking.status === 'cancelled') throw new Error('Already cancelled');

    await client.query("UPDATE bookings SET status='cancelled' WHERE id=$1", [req.params.id]);
    await client.query(
      `UPDATE stations SET
         available_slots=available_slots+1,
         status=CASE WHEN (available_slots+1)::float/total_slots>=0.4 THEN 'available'
                     ELSE 'limited' END,
         updated_at=NOW()
       WHERE id=$1`,
      [booking.station_id]
    );
    await client.query('COMMIT');

    await cacheDel(`station:${booking.station_id}`);
    await cacheDel('stations:*');
    await cacheDel('nearest:*');
    await cacheDel(`bookings:user:${req.user.id}`);

    const updated = await pool.query('SELECT * FROM stations WHERE id=$1', [booking.station_id]);
    io.emit('station_updated', updated.rows[0]);
    res.json({ message: 'Booking cancelled' });
  } catch(err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ════════════════════════════════════════════════════════════════════════════
// FEEDBACK & COMPLAINTS
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/feedback', async (req, res) => {
  const { station_id } = req.query;
  const cacheKey = `feedback:${station_id||'all'}`;
  const cached   = await cacheGet(cacheKey);
  if (cached) return res.json(cached);
  try {
    const result = await pool.query(
      `SELECT f.*, u.name AS user_name FROM feedback f
       JOIN users u ON u.id=f.user_id
       WHERE ($1::uuid IS NULL OR f.station_id=$1)
       ORDER BY f.created_at DESC LIMIT 50`,
      [station_id||null]
    );
    await cacheSet(cacheKey, result.rows, 120);
    res.json(result.rows);
  } catch(err) {
    console.error('Feedback fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch feedback' });
  }
});

app.post('/api/feedback', authMiddleware, async (req, res) => {
  const { station_id, rating, message } = req.body;
  if (!rating || rating < 1 || rating > 5)
    return res.status(400).json({ error: 'Rating 1-5 ke beech hona chahiye' });
  try {
    const result = await pool.query(
      'INSERT INTO feedback (user_id,station_id,rating,message) VALUES ($1,$2,$3,$4) RETURNING *',
      [req.user.id, station_id||null, rating, message||null]
    );
    await cacheDel('feedback:*');
    res.status(201).json(result.rows[0]);
  } catch(err) {
    console.error('Feedback submit error:', err.message);
    res.status(500).json({ error: 'Failed to submit feedback' });
  }
});

app.post('/api/complaints', authMiddleware, async (req, res) => {
  const { station_id, type, priority, description } = req.body;
  if (!type || !description)
    return res.status(400).json({ error: 'type aur description required hai' });
  try {
    const result = await pool.query(
      'INSERT INTO complaints (user_id,station_id,type,priority,description) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [req.user.id, station_id||null, type, priority||'medium', description]
    );
    res.status(201).json(result.rows[0]);
  } catch(err) {
    console.error('Complaint submit error:', err.message);
    res.status(500).json({ error: 'Failed to file complaint' });
  }
});

app.get('/api/complaints', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  try {
    const result = await pool.query(
      `SELECT c.*, u.name AS user_name, u.email AS user_email, s.name AS station_name
       FROM complaints c
       JOIN users u ON u.id=c.user_id
       LEFT JOIN stations s ON s.id=c.station_id
       ORDER BY c.created_at DESC`
    );
    res.json(result.rows);
  } catch { res.status(500).json({ error: 'Failed to fetch complaints' }); }
});

app.patch('/api/complaints/:id/status', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  const { status } = req.body;
  try {
    const result = await pool.query(
      'UPDATE complaints SET status=$1 WHERE id=$2 RETURNING *',
      [status, req.params.id]
    );
    res.json(result.rows[0]);
  } catch { res.status(500).json({ error: 'Failed to update complaint' }); }
});

// ════════════════════════════════════════════════════════════════════════════
// SOCKET.IO — Real-time slot broadcasting
// ════════════════════════════════════════════════════════════════════════════

io.on('connection', (socket) => {
  console.log(`🔌 Client connected: ${socket.id}`);
  (async () => {
    let stations = await cacheGet('stations:initial');
    if (!stations) {
      const result = await pool.query('SELECT * FROM stations ORDER BY name');
      stations = result.rows;
      await cacheSet('stations:initial', stations, 30);
    }
    socket.emit('stations_initial', stations);
  })();
  socket.on('disconnect', () => console.log(`🔌 Disconnected: ${socket.id}`));
});

setInterval(async () => {
  try {
    const stations = (await pool.query("SELECT * FROM stations WHERE status!='offline'")).rows;
    for (const st of stations) {
      if (Math.random() < 0.3) {
        const delta     = Math.random() < 0.5 ? 1 : -1;
        const newSlots  = Math.max(0, Math.min(st.total_slots, st.available_slots + delta));
        const newStatus = newSlots===0?'full':newSlots/st.total_slots<0.4?'limited':'available';
        await pool.query(
          'UPDATE stations SET available_slots=$1,status=$2,updated_at=NOW() WHERE id=$3',
          [newSlots, newStatus, st.id]
        );
        await cacheDel(`station:${st.id}`);
        await cacheDel('stations:*');
        await cacheDel('nearest:*');
        const updated = (await pool.query('SELECT * FROM stations WHERE id=$1',[st.id])).rows[0];
        io.emit('station_updated', updated);
      }
    }
  } catch(err) { console.error('Slot simulation error:', err.message); }
}, 7000);

// ─── Start ────────────────────────────────────────────────────────────────────

server.listen(PORT, () => {
  console.log(`🚀 ChargEase API v3.1 on http://localhost:${PORT}`);
  console.log(`   ✅ Email + Phone login: enabled`);
  console.log(`   ✅ OTP via Gmail: enabled`);
  console.log(`   ✅ Forgot Password: enabled`);
  console.log(`   ✅ PostGIS nearest stations: enabled`);
  console.log(`   ✅ Redis cache: enabled`);
  console.log(`   ✅ Socket.IO real-time: enabled`);
});
