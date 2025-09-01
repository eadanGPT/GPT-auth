
import { WebSocketServer } from 'ws';
import crypto from 'node:crypto';
import { env } from './config.js';
import { db, q, log } from './db.js';
import { createSession, endSession, sessions } from './session.js';
import { newChallenge } from './challenges.js';
import { rsaPublicKeyPem, rsaDecryptOAEP, aesGcmEncrypt, aesGcmDecrypt, signJWT, tokenFingerprint } from './crypto.js';

const HEARTBEAT_MS = 2 * 60 * 1000; // 2 min
const INTEGRITY_MS = 5 * 60 * 1000; // 5 min

export function startWSServer(httpServer) {
  const wss = new WebSocketServer({ server: httpServer, path: env.WS_PATH });

  wss.on('connection', (ws, req) => {
    if (!env.ALLOW_CONNECTIONS || wss.clients.size > env.MAX_CONNECTIONS) { ws.close(); return; }

    const ip = req.socket.remoteAddress;
    let sessionKey = null;
    let sessionIv = null;
    let user_id = null, key_hash = null, hwid_perm = null, temp_hwid = null;
    let session = null;
    let jwtToken = null;
    let lastChallenge = null;
    let heartbeatTimer = null, integrityTimer = null;

    function sendJSON(obj) { try { ws.send(JSON.stringify(obj)); } catch {} }

    // Step 1: send server RSA public key
    sendJSON({ type:'hello', pubkey: rsaPublicKeyPem() });

    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString());
        if (msg.type === 'handshake') {
          // Expect: { ek: base64(RSA[32B sessionKey | 12B iv]), info: {key_hash, hwid_perm, temp_hwid} }
          const buf = rsaDecryptOAEP(msg.ek);
          sessionKey = buf.subarray(0,32);
          sessionIv = buf.subarray(32,44);
          ({ key_hash, hwid_perm, temp_hwid } = msg.info || {});
          user_id = key_hash; // deterministic simple mapping
          q.upsertIP.run(user_id, ip, Date.now());
          log({ level:'info', user_id, key_hash, hwid_perm, msg: 'Auth handshake received' });
          // Issue JWT
          jwtToken = signJWT({ sub: user_id, kh: key_hash, hw: hwid_perm });
          const tokenHash = tokenFingerprint(jwtToken);
          session = createSession({ user_id, key_hash, hwid_perm, temp_hwid, ip });
          const payload = Buffer.from(JSON.stringify({ ok:true, token: jwtToken, fpr: tokenHash }));
          const out = aesGcmEncrypt(sessionKey, sessionIv, payload);
          sendJSON({ type:'handshake_ok', data: out.toString('base64') });

          // Start schedules
          lastChallenge = newChallenge();
          scheduleHeartbeat();
          scheduleIntegrity();
        }
        else if (msg.type === 'packet') {
          // Expect encrypted: { data: base64(aesGcm(enc)) }
          if (!sessionKey) return ws.close();
          const buf = Buffer.from(msg.data, 'base64');
          const dec = JSON.parse(aesGcmDecrypt(sessionKey, sessionIv, buf).toString('utf8'));
          // dec: { token, answer, kind }
          if (!dec || !dec.token || dec.kind !== 'heartbeat') { ws.close(); return; }
          // verify challenge
          if (!lastChallenge || Number(dec.answer) !== Number(lastChallenge.answer)) {
            q.incChallengeFail.run(session.session_id);
            log({ level:'warn', user_id, key_hash, hwid_perm, msg:'Challenge failed' });
            ws.close(); return;
          }
          q.incChallengeOk.run(session.session_id);
          session.last_seen = Date.now();
          q.updateSessionSeen.run(Date.now(), session.session_id);
          // reply with next challenge
          lastChallenge = newChallenge();
          const reply = Buffer.from(JSON.stringify({ ok:true, next: lastChallenge }));
          const out = aesGcmEncrypt(sessionKey, sessionIv, reply);
          sendJSON({ type:'packet_ok', data: out.toString('base64') });
        }
      } catch (e) {
        log({ level:'error', user_id, key_hash, hwid_perm, msg:`Error: ${e.message}` });
        try { ws.close(); } catch {}
      }
    });

    ws.on('close', () => {
      try {
        if (session) {
          q.endSession.run(Date.now(), session.session_id);
          endSession(session.session_id);
        }
      } catch {}
      clearInterval(heartbeatTimer); clearInterval(integrityTimer);
    });

    function scheduleHeartbeat(){
      heartbeatTimer = setInterval(()=>{
        // push a challenge prompt (optional ping)
        try {
          lastChallenge = newChallenge();
          const reply = Buffer.from(JSON.stringify({ ping: Date.now(), ch: lastChallenge }));
          const out = aesGcmEncrypt(sessionKey, sessionIv, reply);
          sendJSON({ type:'hb', data: out.toString('base64') });
        } catch {}
      }, HEARTBEAT_MS);
    }
    function scheduleIntegrity(){
      integrityTimer = setInterval(()=>{
        try {
          const reply = Buffer.from(JSON.stringify({ integrity:'check' }));
          const out = aesGcmEncrypt(sessionKey, sessionIv, reply);
          sendJSON({ type:'integrity', data: out.toString('base64') });
        } catch {}
      }, INTEGRITY_MS);
    }
  });

  return wss;
}
