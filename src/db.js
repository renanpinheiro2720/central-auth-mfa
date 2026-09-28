const Database = require("better-sqlite3");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const dbFile = process.env.DB_FILE || "./data/auth.db";
const absolute = path.resolve(dbFile);
fs.mkdirSync(path.dirname(absolute), { recursive: true });

const db = new Database(absolute);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  mfa_enabled INTEGER NOT NULL DEFAULT 0,
  mfa_secret_enc TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS refresh_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  jti TEXT NOT NULL UNIQUE,
  token_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_refresh_jti ON refresh_sessions(jti);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_sessions(user_id);
`);

module.exports = db;
