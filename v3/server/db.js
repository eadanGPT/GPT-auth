// server/db.js
// SQLite wrapper for keys, clients, IPs, bans, challenges, file digests.

const sqlite3 = require('better-sqlite3');
const crypto = require('crypto');

class DB {
  constructor(file, serverPrivate) {
    this.db = new sqlite3(file);
    this.serverPrivate = serverPrivate;
    this.init();
  }

  init() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS clients (
        id TEXT PRIMARY KEY,
        key TEXT,
        ips TEXT,
        banned_until INTEGER,
        hwid TEXT
      );
      CREATE TABLE IF NOT EXISTS connections (
        client_id TEXT,
        ip TEXT,
        time INTEGER
      );
      CREATE TABLE IF NOT EXISTS challenges (
        client_id TEXT,
        id TEXT,
        expr TEXT,
        nonce TEXT
      );
      CREATE TABLE IF NOT EXISTS keys (
        key TEXT PRIMARY KEY,
        used INTEGER DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS file_digests (
        path TEXT PRIMARY KEY,
        digest TEXT
      );
    `);
  }

  // --- Key management ---
  generateKeys(n) {
    const keys = [];
    const stmt = this.db.prepare('INSERT INTO keys (key, used) VALUES (?, 0)');
    for (let i = 0; i < n; i++) {
      const k = crypto.randomBytes(16).toString('hex');
      stmt.run(k);
      keys.push(k);
    }
    return keys;
  }

  addKey(k) {
    this.db.prepare('INSERT INTO keys (key, used) VALUES (?, 0)').run(k);
  }

  listUnusedKeys() {
    return this.db.prepare('SELECT key FROM keys WHERE used=0').all().map(r => r.key);
  }

  // --- Client management ---
  findClientByKeyHMAC(hmac, nonce) {
    const keys = this.db.prepare('SELECT key FROM keys').all();
    for (const row of keys) {
      const testHmac = crypto.createHmac('sha256', row.key).update(nonce).digest('hex');
      if (testHmac === hmac) {
        // Mark key used if not already
        this.db.prepare('UPDATE keys SET used=1 WHERE key=?').run(row.key);
        // Find or create client
        let client = this.db.prepare('SELECT * FROM clients WHERE key=?').get(row.key);
        if (!client) {
          const id = crypto.randomUUID();
          this.db.prepare('INSERT INTO clients (id, key, ips) VALUES (?, ?, ?)').run(id, row.key, JSON.stringify([]));
          client = this.db.prepare('SELECT * FROM clients WHERE id=?').get(id);
        }
        return client;
      }
    }
    return null;
  }

  updateClientIPs(clientId, ip) {
    const rec = this.db.prepare('SELECT ips FROM clients WHERE id=?').get(clientId);
    let ips = rec.ips ? JSON.parse(rec.ips) : [];
    if (!ips.includes(ip)) {
      if (ips.length >= 3) return false;
      ips.push(ip);
      this.db.prepare('UPDATE clients SET ips=? WHERE id=?').run(JSON.stringify(ips), clientId);
    }
    return true;
  }

  getBanUntil(clientId) {
    const rec = this.db.prepare('SELECT banned_until FROM clients WHERE id=?').get(clientId);
    return rec?.banned_until || null;
  }

  banClient(clientId, minutes) {
    const until = Date.now() + minutes * 60000;
    this.db.prepare('UPDATE clients SET banned_until=? WHERE id=?').run(until, clientId);
  }

  updateClientHWID(clientId, interfaces) {
    this.db.prepare('UPDATE clients SET hwid=? WHERE id=?').run(JSON.stringify(interfaces), clientId);
  }

  recordConnection(clientId, ip) {
    this.db.prepare('INSERT INTO connections (client_id, ip, time) VALUES (?, ?, ?)').run(clientId, ip, Date.now());
  }

  getClientById(id) {
    const rec = this.db.prepare('SELECT * FROM clients WHERE id=?').get(id);
    if (rec) rec.ips = rec.ips ? JSON.parse(rec.ips) : [];
    return rec;
  }

  listClients() {
    return this.db.prepare('SELECT id, key, ips, banned_until FROM clients').all().map(c => ({
      id: c.id,
      keyMasked: c.key.replace(/.(?=.{4})/g, '*'),
      ips: c.ips ? JSON.parse(c.ips) : [],
      banned_until: c.banned_until
    }));
  }

  listActiveSessions() {
    return this.db.prepare('SELECT DISTINCT client_id FROM connections WHERE time > ?').all(Date.now() - 60000);
  }

  getClientStats(clientId) {
    const lastConnections = this.db.prepare('SELECT ip, time FROM connections WHERE client_id=? ORDER BY time DESC LIMIT 10').all(clientId);
    return { lastConnections, userStats: {} };
  }

  // --- Challenges ---
  storeChallengeDigest(clientId, id, expr, nonce) {
    this.db.prepare('INSERT INTO challenges (client_id, id, expr, nonce) VALUES (?, ?, ?, ?)').run(clientId, id, expr, nonce);
  }

  // --- File digests ---
  getFileDigests() {
    return this.db.prepare('SELECT path, digest FROM file_digests').all();
  }

  flushCritical() {
    this.db.pragma('wal_checkpoint(FULL)');
  }
}

module.exports = DB;
