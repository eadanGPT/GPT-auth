
// server/server.js
import http from 'http';
import express from 'express';
import { WebSocketServer } from 'ws';
import { v4 as uuidv4 } from 'uuid';
import { db, initDb, logEvent } from './db.js';
import adminRouter from './admin.js';
import { adminState } from './admin_state.js';
import {
  getServerKeys, rsaDecryptOAEP,
  hkdf, aesGcmEncrypt, aesGcmDecrypt,
  issueJwt, deterministicTokenId,
  validateLicense, enforceSingleSession, saveToken
} from './auth.js';
import { buildChallenge, verifyChallenge } from './challenge.js';
import { buildFileManifest } from './manifests.js';

initDb();

const app = express();
app.use(express.json());
app.use(adminRouter);

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const sessions = new Map();

buildFileManifest(process.cwd());

function touchClientIp(owner, ip){
  db.exec(`CREATE TABLE IF NOT EXISTS client_ips(owner TEXT, ip TEXT, last_seen INTEGER, PRIMARY KEY(owner,ip));`);
  const now = Date.now();
  db.prepare('INSERT OR REPLACE INTO client_ips(owner,ip,last_seen) VALUES (?,?,?)').run(owner, ip, now);
  const rows = db.prepare('SELECT ip,last_seen FROM client_ips WHERE owner=? ORDER BY last_seen DESC').all(owner);
  for (let i=3;i<rows.length;i++){
    db.prepare('DELETE FROM client_ips WHERE owner=? AND ip=?').run(owner, rows[i].ip);
  }
}

wss.on('connection', (ws, req) => {
  const ip = req.socket.remoteAddress;
  const wsid = uuidv4();
  let heartbeatTimer = null;
  let integrityTimer = null;

  function safeSend(obj){ try{ ws.send(JSON.stringify(obj)); }catch{} }

  function scheduleHeartbeat(){
    clearTimeout(heartbeatTimer);
    heartbeatTimer = setTimeout(()=>{
      const ch = buildChallenge();
      safeSend({ event:'challenge', id: ch.id, expression: ch.expression, ts: Date.now() });
    }, 2*60*1000);
  }
  function scheduleIntegrity(){
    clearTimeout(integrityTimer);
    integrityTimer = setTimeout(()=>{
      safeSend({ event:'integrity-check', manifestVersion: Date.now(), ts: Date.now() });
    }, 5*60*1000);
  }

  ws.on('message', (data)=>{
    let msg; try{ msg = JSON.parse(data.toString()); }catch{ return; }

    if (msg.event === 'hello') {
      const { version, client_keyhash, permanent_hwid, temp_hwid, license_key, ephemeral_b64, ping } = msg;
      const { priv, pub, logsPub } = getServerKeys();
      logEvent({kind:'auth', ip, client_keyhash, permanent_hwid, temp_hwid, message:`Ping ${ping}ms; Version ${version}`});

      if (!license_key) { safeSend({ event:'need-license', server_pubkey: pub }); return; }
      let ephemeral;
      try { ephemeral = rsaDecryptOAEP(priv, ephemeral_b64); } catch { safeSend({event:'auth-failed',reason:'ephemeral'}); try{ws.close();}catch{}; return; }

      const val = validateLicense(license_key);
      if (!val.ok) { logEvent({kind:'auth', level:'warn', ip, client_keyhash, permanent_hwid, message:`Invalid license: ${val.reason}`}); safeSend({event:'auth-failed',reason:val.reason}); ws.close(); return; }
      const owner = val.owner;
      enforceSingleSession(owner);
      touchClientIp(owner, ip);

      const jwtTok = issueJwt({ owner, client_keyhash, permanent_hwid });
      saveToken({ token: jwtTok, owner, client_keyhash });
      const tokenId = deterministicTokenId(jwtTok);
      const sessionKey = hkdf(ephemeral, Buffer.from(tokenId,'hex'), Buffer.from(permanent_hwid), 32);

      sessions.set(wsid, { owner, client_keyhash, permanent_hwid, temp_hwid, jwtTok, sessionKey, ip, started_at: Date.now(), heartbeats: 0, wsid, last_ts: Date.now() });
      db.prepare(`INSERT OR REPLACE INTO sessions(id, owner, client_keyhash, permanent_hwid, temp_hwid, ip, wsid, jwt, started_at, last_heartbeat, active)
        VALUES (?,?,?,?,?,?,?,?,?,?,1)`).run(wsid, owner, client_keyhash, permanent_hwid, temp_hwid, ip, wsid, jwtTok, Date.now(), Date.now());

      const aad = Buffer.from(jwtTok.split('.')[2] || '', 'base64url');
      const payload = Buffer.from(JSON.stringify({ ok:true, logs_pubkey: logsPub }), 'utf8');
      const edata = aesGcmEncrypt(sessionKey, payload, aad);
      safeSend({ event:'auth-ok', token: jwtTok, data: edata });
      scheduleHeartbeat(); scheduleIntegrity();
      return;
    }

    const sess = sessions.get(wsid); if (!sess) return;

    if (msg.event === 'challenge-answer') {
      const { id, answersEnc, token, clientTs } = msg;
      if (token !== sess.jwtTok) { safeSend({event:'fatal'}); ws.close(); return; }
      const aad = Buffer.from(token.split('.')[2] || '', 'base64url');
      try {
        const dec = JSON.parse(Buffer.from(aesGcmDecrypt(sess.sessionKey, answersEnc, aad)).toString('utf8'));
        const ok = (dec.answers||[]).length>0; // simplified
        if (!ok) { db.prepare('UPDATE sessions SET challenges_fail=challenges_fail+1 WHERE id=?').run(sess.wsid); safeSend({event:'fatal',reason:'challenge_failed'}); ws.close(); return; }
        db.prepare('UPDATE sessions SET challenges_ok=challenges_ok+1, heartbeats=heartbeats+1, last_heartbeat=? WHERE id=?').run(Date.now(), sess.wsid);
        safeSend({ event:'challenge-ok' }); scheduleHeartbeat();
      } catch { safeSend({event:'fatal',reason:'decrypt_error'}); ws.close(); }
      return;
    }

    if (msg.event === 'integrity-report') {
      const { token, reportEnc } = msg;
      if (token !== sess.jwtTok) { safeSend({event:'fatal'}); ws.close(); return; }
      const aad = Buffer.from(token.split('.')[2] || '', 'base64url');
      try {
        const rep = JSON.parse(Buffer.from(aesGcmDecrypt(sess.sessionKey, reportEnc, aad)).toString('utf8'));
        logEvent({ kind:'integrity', owner:sess.owner, client_keyhash:sess.client_keyhash, permanent_hwid:sess.permanent_hwid, ip:sess.ip, message:'Integrity report' });
      } catch {}
      scheduleIntegrity(); return;
    }

    if (msg.event === 'client-logs') {
      const { token, encLogsB64 } = msg;
      if (token !== sess.jwtTok) { safeSend({event:'fatal'}); ws.close(); return; }
      logEvent({ kind:'session', owner:sess.owner, client_keyhash:sess.client_keyhash, permanent_hwid:sess.permanent_hwid, ip:sess.ip, message:'Client logs bundle' });
      return;
    }
  });

  ws.on('close', ()=>{
    clearTimeout(heartbeatTimer); clearTimeout(integrityTimer);
    const sess = sessions.get(wsid);
    if (sess) {
      const elapsed = Date.now()-sess.started_at;
      db.prepare('UPDATE sessions SET active=0, connected_time_ms=? WHERE id=?').run(elapsed, sess.wsid);
      sessions.delete(wsid);
    }
  });
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, ()=> {
  console.log(`Server listening on ${PORT}. Admin at /admin`);
  console.log(`[ADMIN] Current admin password: ${adminState.getMeta().password}`);
});
