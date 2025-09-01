
import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';

const DB_DIR = path.join(process.cwd(), 'server', 'sqlite');
fs.mkdirSync(DB_DIR, { recursive: true });
const dbPath = path.join(DB_DIR, 'db.sqlite');
export const db = new Database(dbPath);

db.pragma('journal_mode = WAL');

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  key_hash TEXT UNIQUE,
  hwid_perm TEXT,
  banned INTEGER DEFAULT 0,
  created_at INTEGER
);
CREATE TABLE IF NOT EXISTS keys (
  key_hash TEXT PRIMARY KEY,
  owner_user_id TEXT,
  blacklisted INTEGER DEFAULT 0,
  created_at INTEGER
);
CREATE TABLE IF NOT EXISTS tokens (
  token_id TEXT PRIMARY KEY,
  user_id TEXT,
  key_hash TEXT,
  hwid_perm TEXT,
  issued_at INTEGER,
  expires_at INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  user_id TEXT,
  key_hash TEXT,
  hwid_perm TEXT,
  temp_hwid TEXT,
  ip TEXT,
  started_at INTEGER,
  last_seen INTEGER,
  heartbeats INTEGER,
  challenges_ok INTEGER,
  challenges_fail INTEGER,
  disconnected_at INTEGER
);
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER,
  level TEXT,
  user_id TEXT,
  key_hash TEXT,
  hwid_perm TEXT,
  msg TEXT
);
CREATE TABLE IF NOT EXISTS analytics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  total_logins INTEGER,
  total_time INTEGER,
  total_challenges_ok INTEGER,
  total_challenges_fail INTEGER
);
CREATE TABLE IF NOT EXISTS ip_whitelist (
  user_id TEXT,
  ip TEXT,
  last_seen INTEGER,
  PRIMARY KEY (user_id, ip)
);
`;

db.exec(schema);

export const q = {
  log: db.prepare('INSERT INTO logs (ts, level, user_id, key_hash, hwid_perm, msg) VALUES (?, ?, ?, ?, ?, ?)'),
  userByKeyHash: db.prepare('SELECT * FROM users WHERE key_hash = ?'),
  insertUser: db.prepare('INSERT INTO users (id, key_hash, hwid_perm, created_at) VALUES (?, ?, ?, ?)'),
  tokenByUser: db.prepare('SELECT * FROM tokens WHERE user_id = ? ORDER BY issued_at DESC LIMIT 1'),
  insertToken: db.prepare('INSERT INTO tokens (token_id, user_id, key_hash, hwid_perm, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)'),
  insertSession: db.prepare(`INSERT INTO sessions (session_id, user_id, key_hash, hwid_perm, temp_hwid, ip, started_at, last_seen, heartbeats, challenges_ok, challenges_fail)
    VALUES (@session_id, @user_id, @key_hash, @hwid_perm, @temp_hwid, @ip, @started_at, @last_seen, 0, 0, 0)`),
  updateSessionSeen: db.prepare('UPDATE sessions SET last_seen = ?, heartbeats = heartbeats + 1 WHERE session_id = ?'),
  incChallengeOk: db.prepare('UPDATE sessions SET challenges_ok = challenges_ok + 1 WHERE session_id = ?'),
  incChallengeFail: db.prepare('UPDATE sessions SET challenges_fail = challenges_fail + 1 WHERE session_id = ?'),
  endSession: db.prepare('UPDATE sessions SET disconnected_at = ? WHERE session_id = ?'),
  upsertIP: db.prepare(`INSERT INTO ip_whitelist (user_id, ip, last_seen) VALUES (?, ?, ?)
    ON CONFLICT(user_id, ip) DO UPDATE SET last_seen = excluded.last_seen`),
};

export function log({ level = 'info', user_id = null, key_hash = null, hwid_perm = null, msg = '' }) {
  q.log.run(Date.now(), level, user_id, key_hash, hwid_perm, msg);
}
