import Database from 'better-sqlite3';
import crypto from 'crypto';
const db = new Database('auth.db');
const schema = `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS keys (keyhash TEXT PRIMARY KEY, key_enc BLOB, created_at INTEGER, blacklisted INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS users (keyhash TEXT PRIMARY KEY, note TEXT, banned_until INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS ips (keyhash TEXT, ip TEXT, last_seen INTEGER, PRIMARY KEY(keyhash,ip));
CREATE TABLE IF NOT EXISTS hwids (keyhash TEXT, type TEXT, value TEXT, first_seen INTEGER, last_seen INTEGER, PRIMARY KEY(keyhash,type));
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, keyhash TEXT, ip TEXT, connected_at INTEGER, login_time INTEGER, disconnected_at INTEGER, challenges_solved INTEGER DEFAULT 0, challenges_failed INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS analytics_global (keyhash TEXT PRIMARY KEY, total_connected_time INTEGER DEFAULT 0, total_sessions INTEGER DEFAULT 0, total_challenges_solved INTEGER DEFAULT 0, total_challenges_failed INTEGER DEFAULT 0, first_login INTEGER, last_login INTEGER);
CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, level TEXT, kind TEXT, keyhash TEXT, session_id TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS manifest (k TEXT PRIMARY KEY, v TEXT, signed_by TEXT, sig BLOB);
`;
function init(){ db.exec(schema); if(!db.prepare('SELECT v FROM settings WHERE k=?').get('admin_password')) db.prepare('INSERT INTO settings (k,v) VALUES (?,?)').run('admin_password','change-me'); }
function getSetting(k){ const r=db.prepare('SELECT v FROM settings WHERE k=?').get(k); return r?r.v:null; }
function setSetting(k,v){ db.prepare('INSERT OR REPLACE INTO settings (k,v) VALUES (?,?)').run(k,String(v)); }
const MASTER = (()=>{ let key=getSetting('server_master_key'); if(!key){ key=crypto.randomBytes(32).toString('hex'); setSetting('server_master_key',key);} return Buffer.from(key,'hex'); })();
function aesEnc(plain){ const iv=crypto.randomBytes(12); const c=crypto.createCipheriv('aes-256-gcm',MASTER,iv); const enc=Buffer.concat([c.update(plain),c.final()]); const tag=c.getAuthTag(); return Buffer.concat([iv,tag,enc]); }
function aesDec(blob){ const b=Buffer.from(blob); const iv=b.slice(0,12), tag=b.slice(12,28), enc=b.slice(28); const d=crypto.createDecipheriv('aes-256-gcm',MASTER,iv); d.setAuthTag(tag); return Buffer.concat([d.update(enc),d.final()]); }
function addKey(key){ const hash=crypto.createHash('sha256').update(key).digest('hex'); const enc=aesEnc(Buffer.from(key)); const now=Date.now(); db.prepare('INSERT OR REPLACE INTO keys (keyhash,key_enc,created_at,blacklisted) VALUES (?,?,?,0)').run(hash,enc,now); return hash; }
function listKeys(){ return db.prepare('SELECT keyhash,created_at,blacklisted FROM keys').all(); }
function getKeyPlain(keyhash){ const r=db.prepare('SELECT key_enc FROM keys WHERE keyhash=?').get(keyhash); return r?aesDec(r.key_enc).toString('utf8'):null; }
function removeKey(keyhash){ db.prepare('DELETE FROM keys WHERE keyhash=?').run(keyhash); }
function blacklistKey(keyhash){ db.prepare('UPDATE keys SET blacklisted=1 WHERE keyhash=?').run(keyhash); }
function unusedKeys(){ return db.prepare('SELECT keyhash,created_at FROM keys WHERE keyhash NOT IN (SELECT DISTINCT keyhash FROM sessions)').all(); }
function upsertIP(keyhash,ip){ const now=Date.now(); db.prepare('INSERT OR REPLACE INTO ips (keyhash,ip,last_seen) VALUES (?,?,?)').run(keyhash,ip,now); const cutoff=now-30*24*60*60*1000; db.prepare('DELETE FROM ips WHERE keyhash=? AND last_seen<?').run(keyhash,cutoff); const list=db.prepare('SELECT ip,last_seen FROM ips WHERE keyhash=? ORDER BY last_seen DESC').all(keyhash); if(list.length>3){ for(const r of list.slice(3)){ db.prepare('DELETE FROM ips WHERE keyhash=? AND ip=?').run(keyhash,r.ip);} } }
function upsertHWID(keyhash,type,value){ const r=db.prepare('SELECT value FROM hwids WHERE keyhash=? AND type=?').get(keyhash,type); const now=Date.now(); if(r){ db.prepare('UPDATE hwids SET value=?, last_seen=? WHERE keyhash=? AND type=?').run(value,now,keyhash,type); } else { db.prepare('INSERT INTO hwids (keyhash,type,value,first_seen,last_seen) VALUES (?,?,?,?,?)').run(keyhash,type,value,now,now); } }
function log(level,kind,keyhash,session_id,data){ const ts=Date.now(); db.prepare('INSERT INTO logs (ts,level,kind,keyhash,session_id,data) VALUES (?,?,?,?,?,?)').run(ts,level,kind,keyhash||'',session_id||'',JSON.stringify(data||{})); }
function createSession(id,keyhash,ip){ db.prepare('INSERT OR REPLACE INTO sessions (id,keyhash,ip,connected_at) VALUES (?,?,?,?)').run(id,keyhash,ip,Date.now()); }
function finalizeSession(id,fields){ const sets=[],vals=[]; for(const k of Object.keys(fields)){ sets.push(`${k}=?`); vals.push(fields[k]); } vals.push(id); db.prepare(`UPDATE sessions SET ${sets.join(',')} WHERE id=?`).run(...vals); }
function bumpAnalytics(keyhash,d){ const row=db.prepare('SELECT * FROM analytics_global WHERE keyhash=?').get(keyhash); if(!row){ db.prepare('INSERT INTO analytics_global (keyhash,total_connected_time,total_sessions,total_challenges_solved,total_challenges_failed,first_login,last_login) VALUES (?,?,?,?,?,?,?)').run(keyhash,d.connected||0,1,d.solved||0,d.failed||0,Date.now(),Date.now()); } else { db.prepare('UPDATE analytics_global SET total_connected_time=total_connected_time+?, total_sessions=total_sessions+?, total_challenges_solved=total_challenges_solved+?, total_challenges_failed=total_challenges_failed+?, last_login=? WHERE keyhash=?').run(d.connected||0,d.sessions||0,d.solved||0,d.failed||0,Date.now(),keyhash); } }
export default { init, addKey, listKeys, getKeyPlain, removeKey, blacklistKey, unusedKeys, upsertIP, upsertHWID, createSession, finalizeSession, bumpAnalytics, getSetting, setSetting, log, db };
