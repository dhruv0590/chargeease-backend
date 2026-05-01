// ChargEase Backend — server.js
// Run: node server.js
// Requires: npm install express pg cors bcryptjs jsonwebtoken socket.io dotenv

require('dotenv').config();
const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const { Pool }   = require('pg');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');

// ─── App setup ───────────────────────────────────────────────────────────────

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());

const PORT      = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'chargeease-secret-change-in-production';

// ─── Database connection ──────────────────────────────────────────────────────

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.connect()
  .then(() => console.log('✅ Connected to PostgreSQL'))
  .catch(err => console.error('❌ DB connection error:', err.message));

// ─── Auth middleware ──────────────────────────────────────────────────────────

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ─── Health check ─────────────────────────────────────────────────────────────

app.get('/', (req, res) => res.json({ status: 'ChargEase API running' }));

// ════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, phone, password, role, vehicle_type } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email and password are required' });
  }

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (name, email, phone, password_hash, role, vehicle_type)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, role`,
      [name, email, phone || null, hashed, role || 'ev_owner', vehicle_type || null]
    );

    const user  = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user   = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role, vehicle_type: user.vehicle_type },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// GET /api/auth/me  — get current user profile
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, phone, role, vehicle_type, created_at FROM users WHERE id = $1',
      [req.user.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// STATIONS ROUTES
// ════════════════════════════════════════════════════════════════════════════

// GET /api/stations  — list all stations (with optional search & filter)
app.get('/api/stations', async (req, res) => {
  const { search, status, charger_type } = req.query;

  let query  = `SELECT *, ROUND((available_slots::numeric / NULLIF(total_slots,0)) * 100) AS availability_pct FROM stations WHERE 1=1`;
  const params = [];

  if (search) {
    params.push(`%${search}%`);
    query += ` AND (name ILIKE $${params.length} OR address ILIKE $${params.length})`;
  }
  if (status) {
    params.push(status);
    query += ` AND status = $${params.length}`;
  }
  if (charger_type) {
    params.push(`%${charger_type}%`);
    query += ` AND charger_types ILIKE $${params.length}`;
  }

  query += ' ORDER BY name ASC';

  try {
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch stations' });
  }
});

// GET /api/stations/:id — single station detail
app.get('/api/stations/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM stations WHERE id = $1', [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Station not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch station' });
  }
});

// POST /api/stations  — add a new station (admin only)
app.post('/api/stations', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });

  const { name, address, latitude, longitude, total_slots, price_per_kwh, charger_types } = req.body;
  if (!name || !address || !latitude || !longitude || !total_slots) {
    return res.status(400).json({ error: 'Missing required station fields' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO stations (name, address, latitude, longitude, total_slots, available_slots, price_per_kwh, charger_types)
       VALUES ($1,$2,$3,$4,$5,$5,$6,$7) RETURNING *`,
      [name, address, latitude, longitude, total_slots, price_per_kwh || 8.00, charger_types || 'Type 2']
    );
    const station = result.rows[0];
    io.emit('station_updated', station);   // notify all connected clients
    res.status(201).json(station);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create station' });
  }
});

// PATCH /api/stations/:id/slots  — update available slots (called by station hardware / admin)
app.patch('/api/stations/:id/slots', authMiddleware, async (req, res) => {
  const { available_slots } = req.body;
  if (available_slots === undefined) return res.status(400).json({ error: 'available_slots required' });

  try {
    const result = await pool.query(
      `UPDATE stations
       SET available_slots = $1,
           status = CASE WHEN $1 = 0 THEN 'full'
                         WHEN $1::float / total_slots < 0.4 THEN 'limited'
                         ELSE 'available' END,
           updated_at = NOW()
       WHERE id = $2 RETURNING *`,
      [available_slots, req.params.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Station not found' });

    const station = result.rows[0];
    io.emit('station_updated', station);   // push live update to all clients
    res.json(station);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update slots' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// BOOKINGS ROUTES
// ════════════════════════════════════════════════════════════════════════════

// GET /api/bookings  — my bookings
app.get('/api/bookings', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT b.*, s.name AS station_name, s.address AS station_address
       FROM bookings b
       JOIN stations s ON s.id = b.station_id
       WHERE b.user_id = $1
       ORDER BY b.created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch bookings' });
  }
});

// POST /api/bookings  — create a booking
app.post('/api/bookings', authMiddleware, async (req, res) => {
  const { station_id, start_time, end_time } = req.body;
  if (!station_id || !start_time || !end_time) {
    return res.status(400).json({ error: 'station_id, start_time and end_time are required' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Lock and check the station
    const stResult = await client.query(
      'SELECT * FROM stations WHERE id = $1 FOR UPDATE',
      [station_id]
    );
    const station = stResult.rows[0];
    if (!station)                     throw new Error('Station not found');
    if (station.available_slots <= 0) throw new Error('No slots available');

    // Compute amount (assume kWh based on hours × avg 7.4kW charger)
    const hours  = (new Date(end_time) - new Date(start_time)) / 3_600_000;
    const amount = +(hours * 7.4 * station.price_per_kwh).toFixed(2);

    // Create booking
    const bookResult = await client.query(
      `INSERT INTO bookings (user_id, station_id, start_time, end_time, status, amount_paid)
       VALUES ($1,$2,$3,$4,'confirmed',$5) RETURNING *`,
      [req.user.id, station_id, start_time, end_time, amount]
    );

    // Decrement available slots
    await client.query(
      `UPDATE stations SET available_slots = available_slots - 1,
         status = CASE WHEN available_slots - 1 = 0 THEN 'full'
                       WHEN (available_slots - 1)::float / total_slots < 0.4 THEN 'limited'
                       ELSE 'available' END,
         updated_at = NOW()
       WHERE id = $1`,
      [station_id]
    );

    await client.query('COMMIT');

    const booking = bookResult.rows[0];

    // Fetch updated station and broadcast
    const updated = await pool.query('SELECT * FROM stations WHERE id = $1', [station_id]);
    io.emit('station_updated', updated.rows[0]);

    res.status(201).json({ booking, amount_paid: amount });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: err.message });
  } finally {
    client.release();
  }
});

// PATCH /api/bookings/:id/cancel  — cancel a booking
app.patch('/api/bookings/:id/cancel', authMiddleware, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const bookResult = await client.query(
      'SELECT * FROM bookings WHERE id = $1 AND user_id = $2 FOR UPDATE',
      [req.params.id, req.user.id]
    );
    const booking = bookResult.rows[0];
    if (!booking)                          throw new Error('Booking not found');
    if (booking.status === 'cancelled')    throw new Error('Already cancelled');

    await client.query(
      "UPDATE bookings SET status = 'cancelled' WHERE id = $1",
      [req.params.id]
    );

    // Return the slot
    await client.query(
      `UPDATE stations SET available_slots = available_slots + 1,
         status = CASE WHEN available_slots + 1 = total_slots THEN 'available'
                       WHEN (available_slots + 1)::float / total_slots < 0.4 THEN 'limited'
                       ELSE 'available' END,
         updated_at = NOW()
       WHERE id = $1`,
      [booking.station_id]
    );

    await client.query('COMMIT');

    const updated = await pool.query('SELECT * FROM stations WHERE id = $1', [booking.station_id]);
    io.emit('station_updated', updated.rows[0]);

    res.json({ message: 'Booking cancelled' });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: err.message });
  } finally {
    client.release();
  }
});

// ════════════════════════════════════════════════════════════════════════════
// FEEDBACK ROUTES
// ════════════════════════════════════════════════════════════════════════════

// GET /api/feedback?station_id=...  — get feedback for a station
app.get('/api/feedback', async (req, res) => {
  const { station_id } = req.query;
  try {
    const result = await pool.query(
      `SELECT f.*, u.name AS user_name
       FROM feedback f JOIN users u ON u.id = f.user_id
       WHERE ($1::uuid IS NULL OR f.station_id = $1)
       ORDER BY f.created_at DESC LIMIT 50`,
      [station_id || null]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch feedback' });
  }
});

// POST /api/feedback  — submit feedback
app.post('/api/feedback', authMiddleware, async (req, res) => {
  const { station_id, rating, message } = req.body;
  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'Rating must be 1–5' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO feedback (user_id, station_id, rating, message)
       VALUES ($1,$2,$3,$4) RETURNING *`,
      [req.user.id, station_id || null, rating, message || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to submit feedback' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// COMPLAINTS ROUTES
// ════════════════════════════════════════════════════════════════════════════

// POST /api/complaints  — file a complaint
app.post('/api/complaints', authMiddleware, async (req, res) => {
  const { station_id, type, priority, description } = req.body;
  if (!type || !description) {
    return res.status(400).json({ error: 'type and description are required' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO complaints (user_id, station_id, type, priority, description)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [req.user.id, station_id || null, type, priority || 'medium', description]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to file complaint' });
  }
});

// GET /api/complaints  — admin: view all complaints
app.get('/api/complaints', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  try {
    const result = await pool.query(
      `SELECT c.*, u.name AS user_name, u.email AS user_email, s.name AS station_name
       FROM complaints c
       JOIN users u ON u.id = c.user_id
       LEFT JOIN stations s ON s.id = c.station_id
       ORDER BY c.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch complaints' });
  }
});

// PATCH /api/complaints/:id/status  — admin: update complaint status
app.patch('/api/complaints/:id/status', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  const { status } = req.body;
  try {
    const result = await pool.query(
      `UPDATE complaints SET status = $1 WHERE id = $2 RETURNING *`,
      [status, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update complaint' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// SOCKET.IO — real-time slot broadcasting
// ════════════════════════════════════════════════════════════════════════════

io.on('connection', (socket) => {
  console.log(`🔌 Client connected: ${socket.id}`);

  // Send current station data immediately on connect
  pool.query('SELECT * FROM stations ORDER BY name')
    .then(r => socket.emit('stations_initial', r.rows))
    .catch(console.error);

  socket.on('disconnect', () => {
    console.log(`🔌 Client disconnected: ${socket.id}`);
  });
});

// Simulate real-time slot fluctuations (remove in production — use real hardware data)
setInterval(async () => {
  try {
    const stations = (await pool.query("SELECT * FROM stations WHERE status != 'offline'")).rows;
    for (const st of stations) {
      if (Math.random() < 0.3) {
        const delta     = Math.random() < 0.5 ? 1 : -1;
        const newSlots  = Math.max(0, Math.min(st.total_slots, st.available_slots + delta));
        const newStatus = newSlots === 0 ? 'full' : newSlots / st.total_slots < 0.4 ? 'limited' : 'available';
        await pool.query(
          'UPDATE stations SET available_slots=$1, status=$2, updated_at=NOW() WHERE id=$3',
          [newSlots, newStatus, st.id]
        );
        const updated = (await pool.query('SELECT * FROM stations WHERE id=$1', [st.id])).rows[0];
        io.emit('station_updated', updated);
      }
    }
  } catch (err) {
    console.error('Slot simulation error:', err.message);
  }
}, 7000);

// ─── Start server ─────────────────────────────────────────────────────────────

server.listen(PORT, () => console.log(`🚀 ChargEase API running on http://localhost:${PORT}`));
