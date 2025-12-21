import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import { register, login } from "./auth.js";
import { pool } from "./db.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// AUTH MIDDLEWARE
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.sendStatus(401);

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.sendStatus(403);
  }
}

// ROUTES
app.get("/", (req, res) => {
  res.send("TheLogoPage API running");
});

app.post("/register", register);
app.post("/login", login);

// SUBMIT LOGO
app.post("/submit-logo", auth, async (req, res) => {
  const { logo_url, website_url } = req.body;

  await pool.query(
    "INSERT INTO logos(user_id,logo_url,website_url) VALUES($1,$2,$3)",
    [req.user.id, logo_url, website_url]
  );

  res.json({ message: "Logo submitted for approval" });
});

// ADMIN APPROVAL
app.post("/admin/approve/:id", auth, async (req, res) => {
  if (req.user.role !== "admin") return res.sendStatus(403);

  await pool.query(
    `UPDATE logos
     SET approved=true,
         expires_at = now() + interval '90 days'
     WHERE id=$1`,
    [req.params.id]
  );

  res.json({ message: "Approved" });
});

// PUBLIC LOGOS
app.get("/logos", async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, logo_url, website_url
     FROM logos
     WHERE approved=true AND expires_at > now()
     ORDER BY created_at DESC
     LIMIT 50`
  );

  res.json(rows);
});

// CLICK TRACKING
app.get("/click/:id", async (req, res) => {
  await pool.query(
    "INSERT INTO clicks(logo_id, ip, user_agent) VALUES($1,$2,$3)",
    [req.params.id, req.ip, req.headers["user-agent"]]
  );

  const { rows } = await pool.query(
    "SELECT website_url FROM logos WHERE id=$1",
    [req.params.id]
  );

  res.redirect(rows[0].website_url);
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
