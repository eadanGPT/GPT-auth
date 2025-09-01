
// server/db.js
import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

const dbPath = path.join(process.cwd(), 'data.sqlite');
export const db = new Database(dbPath);

export function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kind TEXT,
      level TEXT,
      owner TEXT,
      ip TEXT,
      client_keyhash TEXT,
      permanent_hwid TEXT,
      payload BLOB,
      message TEXT,
      created_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS keys(
      license_key TEXT PRIMARY KEY,
      owner TEXT,
      blacklisted INTEGER DEFAULT 0,
      created_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS users(
      owner TEXT PRIMARY KEY,
      banned INTEGER DEFAULT 0,
      created_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS sessions(
      id TEXT PRIMARY KEY,
      owner TEXT,
      client_keyhash TEXT,
      permanent_hwid TEXT,
      temp_hwid TEXT,
      ip TEXT,
      wsid TEXT,
      jwt TEXT,
      started_at INTEGER,
      last_heartbeat INTEGER,
      challenges_ok INTEGER DEFAULT 0,
      challenges_fail INTEGER DEFAULT 0,
      heartbeats INTEGER DEFAULT 0,
      connected_time_ms INTEGER DEFAULT 0,
      active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS analytics(
      owner TEXT,
      total_sessions INTEGER DEFAULT 0,
      total_time_ms INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS settings(
      key TEXT PRIMARY KEY,
      value TEXT
    );
  `);
}

export function logEvent({kind='info', level='info', owner=null, ip=null, client_keyhash=null, permanent_hwid=null, message='', payload=null}){
  db.prepare(`INSERT INTO logs(kind,level,owner,ip,client_keyhash,permanent_hwid,payload,message,created_at) VALUES (?,?,?,?,?,?,?,?,?)`)
    .run(kind,level,owner,ip,client_keyhash,permanent_hwid,payload,message,Date.now());
}

export default { db, initDb, logEvent };
