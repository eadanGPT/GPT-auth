
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import crypto from 'node:crypto';
import path from 'node:path';
import { env } from './config.js';
import { db, q } from './db.js';

let adminPassword = crypto.randomBytes(12).toString('base64url');
let adminPasswordExpiresAt = Date.now() + env.ADMIN_PASSWORD_ROTATE_MIN * 60 * 1000;

export function getAdminState() { return { adminPassword, adminPasswordExpiresAt }; }
export function rotateAdminPassword() {
  adminPassword = crypto.randomBytes(12).toString('base64url');
  adminPasswordExpiresAt = Date.now() + env.ADMIN_PASSWORD_ROTATE_MIN * 60 * 1000;
}

function basicAuth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Basic ')) return res.status(401).set('WWW-Authenticate','Basic realm="admin"').end('Auth required');
  const [user, pass] = Buffer.from(header.replace('Basic ',''), 'base64').toString('utf8').split(':');
  if (user === 'admin' && pass === adminPassword && Date.now() < adminPasswordExpiresAt) return next();
  return res.status(403).end('Forbidden');
}

// Data access helpers
function listSessions() {
  return db.prepare('SELECT * FROM sessions WHERE disconnected_at IS NULL ORDER BY started_at DESC').all();
}
function allLogs(limit=200) {
  return db.prepare('SELECT * FROM logs ORDER BY ts DESC LIMIT ?').all(limit);
}
function settingsGet() {
  return { allowConnections: env.ALLOW_CONNECTIONS, maxConnections: env.MAX_CONNECTIONS };
}

export function startAdminServer() {
  const app = express();
  app.use(helmet());
  app.use(express.json());
  app.use(cookieParser());

  // Static Admin Panel
  app.get('/admin', (_req,res) => res.sendFile(path.join(process.cwd(),'server','public','admin','index.html')));
  app.use('/admin/assets', express.static(path.join(process.cwd(),'server','public','admin')));

  // Authenticated API
  app.get('/admin/api/health', basicAuth, (_req,res)=> res.json({ ok:true, ts: Date.now(), expiresAt: adminPasswordExpiresAt }));
  app.get('/admin/api/meta', basicAuth, (_req,res)=> res.json({ uptime: process.uptime(), now: Date.now(), expiresAt: adminPasswordExpiresAt }));

  // Sessions
  app.get('/admin/api/sessions', basicAuth, (_req,res)=> res.json({ sessions: listSessions() }));
  app.post('/admin/api/sessions/:id/disconnect', basicAuth, (req,res)=>{
    const id = req.params.id;
    const row = db.prepare('SELECT * FROM sessions WHERE session_id=?').get(id);
    if (!row) return res.status(404).json({ error:'not_found' });
    db.prepare('UPDATE sessions SET disconnected_at = ? WHERE session_id = ?').run(Date.now(), id);
    res.json({ ok:true });
  });

  // Keys
  app.get('/admin/api/keys', basicAuth, (_req,res)=>{
    const rows = db.prepare('SELECT * FROM keys').all();
    res.json({ keys: rows });
  });
  app.post('/admin/api/keys', basicAuth, (req,res)=>{
    const { key_hash, owner_user_id } = req.body||{};
    if (!key_hash) return res.status(400).json({ error:'key_hash required' });
    try {
      db.prepare('INSERT INTO keys (key_hash, owner_user_id, created_at) VALUES (?, ?, ?)').run(key_hash, owner_user_id||null, Date.now());
      res.json({ ok:true });
    } catch (e) { res.status(409).json({ error:'duplicate_or_error', detail:e.message }); }
  });
  app.post('/admin/api/keys/:key_hash/blacklist', basicAuth, (req,res)=>{
    const { key_hash } = req.params;
    db.prepare('UPDATE keys SET blacklisted=1 WHERE key_hash=?').run(key_hash);
    res.json({ ok:true });
  });
  app.delete('/admin/api/keys/:key_hash', basicAuth, (req,res)=>{
    const { key_hash } = req.params;
    db.prepare('DELETE FROM keys WHERE key_hash=?').run(key_hash);
    res.json({ ok:true });
  });

  // Users
  app.get('/admin/api/users', basicAuth, (_req,res)=>{
    const rows = db.prepare('SELECT * FROM users').all();
    res.json({ users: rows });
  });
  app.post('/admin/api/users/:id/ban', basicAuth, (req,res)=>{
    db.prepare('UPDATE users SET banned=1 WHERE id=?').run(req.params.id);
    res.json({ ok:true });
  });
  app.post('/admin/api/users/:id/unban', basicAuth, (req,res)=>{
    db.prepare('UPDATE users SET banned=0 WHERE id=?').run(req.params.id);
    res.json({ ok:true });
  });
  app.get('/admin/api/users/:id/stats', basicAuth, (req,res)=>{
    const a = db.prepare('SELECT * FROM analytics WHERE user_id=?').get(req.params.id) || null;
    res.json({ analytics: a });
  });

  // Logs
  app.get('/admin/api/logs', basicAuth, (req,res)=>{
    const limit = Math.max(1, Math.min(1000, Number(req.query.limit||200)));
    res.json({ logs: allLogs(limit) });
  });

  // Settings
  app.get('/admin/api/settings', basicAuth, (_req,res)=> res.json(settingsGet()));
  app.post('/admin/api/settings', basicAuth, (req,res)=>{
    const { allowConnections, maxConnections } = req.body||{};
    if (typeof allowConnections === 'boolean') process.env.ALLOW_CONNECTIONS = String(allowConnections);
    if (Number.isFinite(Number(maxConnections))) process.env.MAX_CONNECTIONS = String(Number(maxConnections));
    res.json(settingsGet());
  });

  return app;
}
