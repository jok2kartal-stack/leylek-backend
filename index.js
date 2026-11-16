const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "leylek_super_secret_key_2026";
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "admin@leylek.com").toLowerCase();
const ADMIN_PASS = process.env.ADMIN_PASS || "Leylek2026!";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      banned INTEGER NOT NULL DEFAULT 0,
      email_verified BOOLEAN NOT NULL DEFAULT TRUE,
      verification_code TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS tours (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      price NUMERIC NOT NULL DEFAULT 0,
      duration TEXT NOT NULL DEFAULT '',
      seller_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS reviews (
      id SERIAL PRIMARY KEY,
      tour_id INTEGER REFERENCES tours(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
      comment TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  const adminCheck = await pool.query("SELECT id FROM users WHERE email = $1", [ADMIN_EMAIL]);
  if (adminCheck.rows.length === 0) {
    const hash = await bcrypt.hash(ADMIN_PASS, 10);
    await pool.query(
      "INSERT INTO users (name, email, password_hash, role, email_verified) VALUES ($1, $2, $3, 'admin', TRUE)",
      ["Leylek Admin", ADMIN_EMAIL, hash]
    );
    console.log("Varsayilan admin olusturuldu:", ADMIN_EMAIL);
  }
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Oturum gerekli" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Gecersiz oturum" });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "Admin yetkisi gerekli" });
  next();
}

app.get("/", (_req, res) => {
  res.json({ status: "ok", service: "Leylek API", version: "1.0.0" });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "Tum alanlar zorunludur" });
    const cleanEmail = email.trim().toLowerCase();
    const safeRole = role === "seller" ? "seller" : "user";
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (name, email, password_hash, role, email_verified) VALUES ($1, $2, $3, $4, TRUE) RETURNING id, name, email, role, email_verified",
      [name.trim(), cleanEmail, hash, safeRole]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user, verification_required: false, email_sent: false });
  } catch (err) {
    if (err.code === "23505") return res.status(400).json({ error: "Bu e-posta zaten kayitli" });
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = (email || "").trim().toLowerCase();
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [cleanEmail]);
    const row = result.rows[0];
    if (!row) return res.status(401).json({ error: "E-posta veya sifre hatali" });
    if (row.banned) return res.status(403).json({ error: "Hesabiniz askiya alinmistir" });
    const valid = await bcrypt.compare(password || "", row.password_hash);
    if (!valid) return res.status(401).json({ error: "E-posta veya sifre hatali" });
    const user = { id: row.id, name: row.name, email: row.email, role: row.role, email_verified: row.email_verified };
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user, verification_required: false });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/auth/verify-email", authMiddleware, async (req, res) => {
  await pool.query("UPDATE users SET email_verified = TRUE WHERE id = $1", [req.user.id]);
  res.json({ success: true, message: "E-posta dogrulandi" });
});

app.post("/api/auth/resend-code", authMiddleware, (_req, res) => {
  res.json({ success: true, message: "Dogrulama kodu gonderildi" });
});

app.get("/api/tours", async (_req, res) => {
  try {
    const result = await pool.query(`
      SELECT t.*, u.name AS seller_name,
        COALESCE(ROUND(AVG(r.rating)::numeric, 1), 0)::float AS rating_avg,
        COUNT(r.id)::int AS review_count
      FROM tours t
      LEFT JOIN users u ON u.id = t.seller_id
      LEFT JOIN reviews r ON r.tour_id = t.id
      GROUP BY t.id, u.name
      ORDER BY t.created_at DESC
    `);
    res.json(result.rows.map((r) => ({ ...r, price: Number(r.price) })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/tours/:id", async (req, res) => {
  try {
    const tourRes = await pool.query(`
      SELECT t.*, u.name AS seller_name,
        COALESCE(ROUND(AVG(r.rating)::numeric, 1), 0)::float AS rating_avg,
        COUNT(r.id)::int AS review_count
      FROM tours t
      LEFT JOIN users u ON u.id = t.seller_id
      LEFT JOIN reviews r ON r.tour_id = t.id
      WHERE t.id = $1
      GROUP BY t.id, u.name
    `, [req.params.id]);
    if (tourRes.rows.length === 0) return res.status(404).json({ error: "Tur bulunamadi" });
    const revRes = await pool.query(`
      SELECT r.*, u.name AS user_name FROM reviews r
      LEFT JOIN users u ON u.id = r.user_id
      WHERE r.tour_id = $1 ORDER BY r.created_at DESC
    `, [req.params.id]);
    res.json({ ...tourRes.rows[0], price: Number(tourRes.rows[0].price), reviews: revRes.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/tours", authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== "seller" && req.user.role !== "admin") {
      return res.status(403).json({ error: "Yetkisiz islem" });
    }
    const { title, description, price, duration } = req.body;
    const result = await pool.query(
      "INSERT INTO tours (title, description, price, duration, seller_id) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [title, description, price, duration, req.user.id]
    );
    res.json({ ...result.rows[0], price: Number(result.rows[0].price), rating_avg: 0, review_count: 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/tours/:id", authMiddleware, async (req, res) => {
  try {
    const { title, description, price, duration } = req.body;
    const result = await pool.query(
      "UPDATE tours SET title = COALESCE($1, title), description = COALESCE($2, description), price = COALESCE($3, price), duration = COALESCE($4, duration) WHERE id = $5 RETURNING *",
      [title, description, price, duration, req.params.id]
    );
    res.json({ ...result.rows[0], price: Number(result.rows[0].price) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/tours/:id", authMiddleware, async (req, res) => {
  await pool.query("DELETE FROM tours WHERE id = $1", [req.params.id]);
  res.json({ success: true });
});

app.get("/api/reviews", authMiddleware, async (_req, res) => {
  const result = await pool.query(`
    SELECT r.*, u.name AS user_name, t.title AS tour_title
    FROM reviews r
    LEFT JOIN users u ON u.id = r.user_id
    LEFT JOIN tours t ON t.id = r.tour_id
    ORDER BY r.created_at DESC
  `);
  res.json(result.rows);
});

app.post("/api/reviews", authMiddleware, async (req, res) => {
  const { tour_id, rating, comment } = req.body;
  const result = await pool.query(
    "INSERT INTO reviews (tour_id, user_id, rating, comment) VALUES ($1, $2, $3, $4) RETURNING *",
    [tour_id, req.user.id, rating, comment]
  );
  res.json(result.rows[0]);
});

app.delete("/api/reviews/:id", authMiddleware, async (req, res) => {
  await pool.query("DELETE FROM reviews WHERE id = $1", [req.params.id]);
  res.json({ success: true });
});

app.get("/api/users", authMiddleware, adminOnly, async (_req, res) => {
  const result = await pool.query(
    "SELECT id, name, email, role, banned, CASE WHEN email_verified THEN 1 ELSE 0 END AS email_verified, created_at FROM users ORDER BY id ASC"
  );
  res.json(result.rows);
});

app.patch("/api/users/:id/ban", authMiddleware, adminOnly, async (req, res) => {
  const banned = req.body.banned ? 1 : 0;
  const result = await pool.query(
    "UPDATE users SET banned = $1 WHERE id = $2 RETURNING id, name, email, role, banned, created_at",
    [banned, req.params.id]
  );
  res.json(result.rows[0]);
});

app.patch("/api/users/:id/role", authMiddleware, adminOnly, async (req, res) => {
  const result = await pool.query(
    "UPDATE users SET role = $1 WHERE id = $2 RETURNING id, name, email, role, banned, created_at",
    [req.body.role, req.params.id]
  );
  res.json(result.rows[0]);
});

const port = parseInt(process.env.PORT || "3000", 10);
initDb()
  .then(() => {
    app.listen(port, "0.0.0.0", () => console.log(`Leylek API ${port} portunda calisiyor`));
  })
  .catch((err) => {
    console.error("Veritabani baslatma hatasi:", err);
    process.exit(1);
  });
