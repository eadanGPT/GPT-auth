// server/db.js
// SQLite initialization, prepared statements, and helper methods. Auto-backup timer.

import fs from 'fs';
import path from 'path';
import Database from 'better-sqlite3';
import { monoNowMs } from '../common/util.js';

export class DB {
  constructor(cfg, logger) {
    this.cfg = cfg;
    this.logger = logger;
    fs.mkdirSync(path.dirname(cfg.persistence.dbPath), { recursive: true });
    this.db = new Database(cfg.persistence.dbPath);
    const schema = fs.readFileSync('common/schema.sql', 'utf8');
    this.db.exec(schema);
    this.prepare();
    this.installBackupTimer();
  }

  prepare() {
    // Prepare commonly used statements for efficiency and atomicity
    this.stmts = {
      addKey: this.db.prepare('INSERT INTO keys (key_value, created_at, unused) VALUES (?, ?, 1)'),
      listUnused: this.db.prepare('SELECT key_value, created_at FROM keys WHERE unused=1'),
      markKeyUsed: this.db.prepare('UPDATE keys SET unused=0, used_by_client_id=?, used_at=? WHERE key_value=?'),
      getKey: this.db.prepare('SELECT * FROM keys WHERE key_value=?'),
      getClientByKey: this.db.prepare('SELECT * FROM clients WHERE key_value=?'),
      getClientById: this.db.prepare('SELECT * FROM clients WHERE client_id=?'),
      createClient: this.db.prepare('INSERT INTO clients (client_id, key_value, created_at, ip_allowlist, hwid_whitelist, last_seen, banned, notes) VALUES (?, ?, ?, ?, ?, ?, 0, "")'),
      updateClientSeen: this.db.prepare('UPDATE clients SET last_seen=? WHERE client_id=?'),
      saveSession: this.db.prepare('INSERT INTO sessions (session_id, client_id, token, issued_at, expires_at, ip, active, last_heartbeat, stats_json) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)'),
      deactivateSession: this.db.prepare('UPDATE sessions SET active=0 WHERE session_id=?'),
      log: this.db.prepare('INSERT INTO logs (client_id, level, message, created_at) VALUES (?, ?, ?, ?)'),
      addConnection: this.db.prepare('INSERT INTO connections (client_id, ip, connected_at) VALUES (?, ?, ?)'),
      endConnection: this.db.prepare('UPDATE connections SET disconnected_at=? WHERE id=?'),
      getActiveSessions: this.db.prepare('SELECT * FROM sessions WHERE active=1'),
      listActiveByClient: this.db.prepare('SELECT * FROM sessions WHERE active=1 AND client_id=?'),
      saveUserStats: this.db.prepare('INSERT INTO user_stats (client_id, last10_json, totals_json) VALUES (?, ?, ?) ON CONFLICT(client_id) DO UPDATE SET last10_json=excluded.last10_json, totals_json=excluded.totals_json'),
      getUserStats: this.db.prepare('SELECT * FROM user_stats WHERE client_id=?'),
      banClient: this.db.prepare('UPDATE clients SET banned=1 WHERE client_id=?'),
      unbanClient: this.db.prepare('UPDATE clients SET banned=0 WHERE client_id=?'),
      listClients: this.db.prepare('SELECT client_id, key_value, last_seen, banned FROM clients')
    };
  }

  criticalSaveBackup(reason) {
    // Immediate backup on critical changes (e.g., key claim, permanent data change)
    try {
      const dir = this.cfg.persistence.backupDir;
      fs.mkdirSync(dir, { recursive: true });
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      const dest = path.join(dir, `backup-${ts}.sqlite`);
      fs.copyFileSync(this.cfg.persistence.dbPath, dest);
      this.logger.info(`DB backup saved (${reason}) -> ${dest}`);
    } catch (e) {
      this.logger.error(`Backup failed: ${e.message}`);
    }
  }

  installBackupTimer() {
    // Periodic backup every N ms
    const ms = this.cfg.persistence.backupEveryMs;
    setInterval(() => this.criticalSaveBackup('periodic'), ms).unref();
  }

  addLog(clientId, level, message) {
    // Append a log entry to the DB
    this.stmts.log.run(clientId || null, level, message, Date.now());
  }
}
