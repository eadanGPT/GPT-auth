-- common/schema.sql
-- Database schema: clients, keys, sessions, logs, connections, stats

PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS keys (
  key_id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_value TEXT UNIQUE NOT NULL,
  created_at INTEGER NOT NULL,
  used_by_client_id INTEGER,
  used_at INTEGER,
  unused INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS clients (
  client_id TEXT PRIMARY KEY,
  key_value TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  ip_allowlist TEXT NOT NULL, -- JSON array of IPs (max 3)
  hwid_whitelist TEXT NOT NULL, -- JSON array of hwids (logged/optional)
  last_seen INTEGER,
  banned INTEGER NOT NULL DEFAULT 0,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  token TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  ip TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  last_heartbeat INTEGER,
  stats_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS logs (
  log_id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id TEXT,
  level TEXT NOT NULL, -- 'auth' | 'log' | 'error'
  message TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id TEXT,
  ip TEXT NOT NULL,
  connected_at INTEGER NOT NULL,
  disconnected_at INTEGER
);

CREATE TABLE IF NOT EXISTS user_stats (
  client_id TEXT PRIMARY KEY,
  last10_json TEXT NOT NULL, -- ring buffer of last 10 connections
  totals_json TEXT NOT NULL
);
