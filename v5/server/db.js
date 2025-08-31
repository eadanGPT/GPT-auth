'use strict';
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const db = new sqlite3.Database(path.join(__dirname, 'auth.sqlite'));

db.serialize(() => {
  db.run(`PRAGMA journal_mode=WAL`);
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      user_key TEXT PRIMARY KEY,
      version TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      banned INTEGER NOT NULL DEFAULT 0
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS user_ips (
      user_key TEXT NOT NULL,
      ip TEXT NOT NULL,
      first_seen INTEGER NOT NULL,
      last_seen INTEGER NOT NULL,
      UNIQUE(user_key, ip)
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS user_hwids (
      user_key TEXT NOT NULL,
      hwid TEXT NOT NULL,
      added_at INTEGER NOT NULL,
      UNIQUE(user_key, hwid)
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS tokens (
      user_key TEXT NOT NULL,
      jwt TEXT NOT NULL,
      issued_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS auth_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_key TEXT,
      ip TEXT,
      hwid TEXT,
      data_encrypted BLOB NOT NULL,
      created_at INTEGER NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS integrity_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_key TEXT,
      data_encrypted BLOB NOT NULL,
      created_at INTEGER NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS analytics_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_key TEXT NOT NULL,
      connected_time INTEGER NOT NULL,
      challenges_solved INTEGER NOT NULL,
      challenges_failed INTEGER NOT NULL,
      login_time INTEGER NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS analytics_global (
      user_key TEXT PRIMARY KEY,
      total_connected_time INTEGER NOT NULL,
      total_challenges_solved INTEGER NOT NULL,
      total_challenges_failed INTEGER NOT NULL,
      sessions INTEGER NOT NULL
    )
  `);
});

function upsertUser(user_key, version) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO users (user_key, version, created_at) VALUES (?, ?, ?)
       ON CONFLICT(user_key) DO UPDATE SET version=excluded.version`,
      [user_key, version, Date.now()],
      (err) => err ? reject(err) : resolve()
    );
  });
}

function updateIP(user_key, ip) {
  const ts = Date.now();
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO user_ips (user_key, ip, first_seen, last_seen)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(user_key, ip) DO UPDATE SET last_seen=excluded.last_seen`,
      [user_key, ip, ts, ts],
      (err) => err ? reject(err) : resolve()
    );
  });
}

function pruneOldIPs() {
  const cutoff = Date.now() - 30 * 24 * 3600 * 1000;
  return new Promise((resolve, reject) => {
    db.run(`DELETE FROM user_ips WHERE last_seen < ?`, [cutoff], (err) => err ? reject(err) : resolve());
  });
}

function countIPs(user_key) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT COUNT(*) as c FROM user_ips WHERE user_key = ?`, [user_key], (err, row) => {
      if (err) return reject(err);
      resolve(row.c || 0);
    });
  });
}

function addHWID(user_key, hwid) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT OR IGNORE INTO user_hwids (user_key, hwid, added_at) VALUES (?, ?, ?)`,
      [user_key, hwid, Date.now()],
      (err) => err ? reject(err) : resolve()
    );
  });
}

function isBanned(user_key) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT banned FROM users WHERE user_key = ?`, [user_key], (err, row) => {
      if (err) return reject(err);
      resolve(row && row.banned === 1);
    });
  });
}

function saveToken(user_key, jwt, exp) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO tokens (user_key, jwt, issued_at, expires_at) VALUES (?, ?, ?, ?)`,
      [user_key, jwt, Date.now(), exp],
      (err) => err ? reject(err) : resolve()
    );
  });
}

function saveAuthLog(user_key, ip, hwid, data_encrypted) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO auth_logs (user_key, ip, hwid, data_encrypted, created_at) VALUES (?, ?, ?, ?, ?)`,
      [user_key, ip, hwid, data_encrypted, Date.now()],
      (err) => err ? reject(err) : resolve()
    );
  });
}

function saveIntegrityLog(user_key, data_encrypted) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO integrity_logs (user_key, data_encrypted, created_at) VALUES (?, ?, ?)`,
      [user_key, data_encrypted, Date.now()],
      (err) => err ? reject(err) : resolve()
    );
  });
}

function saveSessionAnalytics(row) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO analytics_sessions (user_key, connected_time, challenges_solved, challenges_failed, login_time)
       VALUES (?, ?, ?, ?, ?)`,
      [row.user_key, row.connected_time, row.challenges_solved, row.challenges_failed, row.login_time],
      (err) => err ? reject(err) : resolve()
    );
  });
}

function upsertGlobalAnalytics(row) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO analytics_global (user_key, total_connected_time, total_challenges_solved, total_challenges_failed, sessions)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(user_key) DO UPDATE SET
         total_connected_time = analytics_global.total_connected_time + excluded.total_connected_time,
         total_challenges_solved = analytics_global.total_challenges_solved + excluded.total_challenges_solved,
         total_challenges_failed = analytics_global.total_challenges_failed + excluded.total_challenges_failed,
         sessions = analytics_global.sessions + 1`,
      [row.user_key, row.connected_time, row.challenges_solved, row.challenges_failed, 1],
      (err) => err ? reject(err) : resolve()
    );
  });
}

function getAnalytics(user_key) {
  return new Promise((resolve, reject) => {
    db.all(`SELECT * FROM analytics_sessions WHERE user_key = ? ORDER BY id DESC LIMIT 10`, [user_key], (err, sessions) => {
      if (err) return reject(err);
      db.get(`SELECT * FROM analytics_global WHERE user_key = ?`, [user_key], (err2, global) => {
        if (err2) return reject(err2);
        resolve({ sessions, global });
      });
    });
  });
}

module.exports = {
  db,
  upsertUser,
  updateIP,
  pruneOldIPs,
  countIPs,
  addHWID,
  isBanned,
  saveToken,
  saveAuthLog,
  saveIntegrityLog,
  saveSessionAnalytics,
  upsertGlobalAnalytics,
  getAnalytics
};
