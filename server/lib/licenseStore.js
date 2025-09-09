import Database from 'better-sqlite3';
import crypto from 'crypto';

const db = new Database('server/db.sqlite');

db.prepare(`CREATE TABLE IF NOT EXISTS license_keys (
  id TEXT PRIMARY KEY,
  secret TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL DEFAULT 'unused', -- unused | claimed | revoked
  plan TEXT DEFAULT 'trial',
  scopes TEXT DEFAULT '[]',
  createdAt INTEGER NOT NULL,
  claimedByUserId TEXT,
  claimedAt INTEGER
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  pwHash TEXT NOT NULL
)`).run();

// --- User functions ---
function createUser(username, password) {
  const id = crypto.randomUUID();
  const pwHash = crypto.createHash('sha256').update(password).digest('hex');
  db.prepare('INSERT INTO users(id,username,pwHash) VALUES(?,?,?)').run(id, username, pwHash);
  return { id, username };
}

function checkPassword(username, password) {
  const row = db.prepare('SELECT pwHash FROM users WHERE username=?').get(username);
  if (!row) return false;
  const pwHash = crypto.createHash('sha256').update(password).digest('hex');
  return pwHash === row.pwHash;
}

// --- License key functions ---
function createKey(secret, plan='trial', scopes=['user']) {
  const id = crypto.randomUUID();
  const createdAt = Date.now();
  db.prepare('INSERT INTO license_keys(id,secret,status,plan,scopes,createdAt) VALUES(?,?,?,?,?,?)')
    .run(id, secret, 'unused', plan, JSON.stringify(scopes), createdAt);
  return { id, secret, plan, scopes, status:'unused', createdAt };
}

function getKey(secret) {
  return db.prepare('SELECT * FROM license_keys WHERE secret=?').get(secret);
}

function claimKey(secret, userId) {
  const row = getKey(secret);
  if (!row) throw new Error('unknown_key');
  if (row.status !== 'unused') throw new Error('already_claimed');
  const claimedAt = Date.now();
  db.prepare('UPDATE license_keys SET status=?, claimedByUserId=?, claimedAt=? WHERE secret=?')
    .run('claimed', userId, claimedAt, secret);
  return { ok:true, claimedAt };
}

export const LicenseStore = {
  createUser,
  checkPassword,
  createKey,
  getKey,
  claimKey,
  db
};
