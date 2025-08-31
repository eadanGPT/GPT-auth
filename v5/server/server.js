'use strict';
const fs = require('fs');
const path = require('path');
const http = require('http');
const express = require('express');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken'); // ES256
const {
  genRandom, aesGcmEncrypt, aesGcmDecrypt, hash256, nowTicks,
  signEd25519, verifyEd25519, ecdhX25519, wrapSecret, unwrapSecret, serialize, deserialize
} = require('./utils/crypto');
const { pickChallenge, solve, deadline, timedOut } = require('./utils/challenges');
const {
  upsertUser, updateIP, pruneOldIPs, countIPs, addHWID, isBanned, saveToken,
  saveAuthLog, saveIntegrityLog, saveSessionAnalytics, upsertGlobalAnalytics, getAnalytics
} = require('./db');

const app = express();
const httpServer = http.createServer(app);
const wss = new WebSocket.Server({ server: httpServer });

const SERVER_KEYS_DIR = path.join(__dirname, 'keys');
const serverEdPriv = fs.readFileSync(path.join(SERVER_KEYS_DIR, 'server-ed25519.key'), 'utf8');
const serverEdPub = fs.readFileSync(path.join(SERVER_KEYS_DIR, 'server-ed25519.pub'), 'utf8');
const serverXPriv = fs.readFileSync(path.join(SERVER_KEYS_DIR, 'server-x25519.key'), 'utf8');
const serverXPub = fs.readFileSync(path.join(SERVER_KEYS_DIR, 'server-x25519.pub'), 'utf8');
const logVerifyPub = fs.readFileSync(path.join(SERVER_KEYS_DIR, 'log-ed25519.pub'), 'utf8'); // For verifying client log signatures

// Manifest signing
function signManifest(manifest) {
  const clone = { ...manifest, signature: "", signedAt: Date.now() };
  const payload = Buffer.from(JSON.stringify({ clientVersion: clone.clientVersion, functions: clone.functions, signedAt: clone.signedAt }));
  const sig = signEd25519(serverEdPriv, payload).toString('base64');
  clone.signature = sig;
  return clone;
}
let manifest = signManifest(require('./manifest.json'));

function encryptForSession(sessionKey, obj) {
  const body = serialize(obj);
  const aad = hash256(Buffer.from('WS-AAD-v1'));
  const { iv, enc, tag } = aesGcmEncrypt(sessionKey, body, aad);
  return { iv: iv.toString('base64'), tag: tag.toString('base64'), enc: enc.toString('base64') };
}
function decryptFromSession(sessionKey, packet) {
  const aad = hash256(Buffer.from('WS-AAD-v1'));
  return deserialize(aesGcmDecrypt(
    sessionKey,
    Buffer.from(packet.iv, 'base64'),
    Buffer.from(packet.enc, 'base64'),
    Buffer.from(packet.tag, 'base64'),
    aad
  ));
}

// Per-connection runtime memory cache (ephemeral, cleared on close)
const sessions = new Map(); // socket -> { user_key, sessionKey, analytics, startTicks, heartbeatTicks }

function immediateClose(ws, code = 4001, reason = 'bye') {
  try { ws.close(code, reason); } catch {}
  try { ws.terminate(); } catch {}
}

function issueJWT(user_key) {
  const expSeconds = Math.floor(Date.now() / 1000) + (3 * 24 * 3600);
  const token = jwt.sign(
    { sub: user_key, iat: Math.floor(Date.now() / 1000), exp: expSeconds },
    serverEdPriv,
    { algorithm: 'EdDSA' } // Ed25519 JWT (node-jose/modern jsonwebtoken supports EdDSA)
  );
  return { token, expMs: expSeconds * 1000 };
}

// Analytics helper
function newAnalytics(user_key) {
  return {
    user_key,
    connected_time: 0,
    challenges_solved: 0,
    challenges_failed: 0,
    login_time: Number(nowTicks()) // ns
  };
}

// Web page: /clients/:user_key shows analytics
app.get('/clients/:user_key', async (req, res) => {
  try {
    const data = await getAnalytics(req.params.user_key);
    res.setHeader('Content-Type', 'text/html');
    const sessionsHtml = (data.sessions || []).map(s => `
      <li>
        connected_time: ${s.connected_time} ms,
        challenges_solved: ${s.challenges_solved},
        challenges_failed: ${s.challenges_failed},
        login_time: ${new Date(s.login_time).toISOString()}
      </li>
    `).join('');
    const g = data.global || { total_connected_time: 0, total_challenges_solved: 0, total_challenges_failed: 0, sessions: 0 };
    res.end(`
      <html><body>
        <h3>Session analytics (${req.params.user_key})</h3>
        <ul>${sessionsHtml}</ul>
        <h3>Global analytics</h3>
        <ul>
          <li>total_connected_time: ${g.total_connected_time} ms</li>
          <li>total_challenges_solved: ${g.total_challenges_solved}</li>
          <li>total_challenges_failed: ${g.total_challenges_failed}</li>
          <li>sessions: ${g.sessions}</li>
        </ul>
      </body></html>
    `);
  } catch (e) {
    res.status(500).send('error');
  }
});

// WebSocket
wss.on('connection', async (ws, req) => {
  const ip = req.socket.remoteAddress;
  const startTicks = nowTicks();
  let sessionKey = null;
  let user_key = null;
  let heartbeats = { last: nowTicks(), timer: null };

  // Per-connection helper to send encrypted payloads
  function sendJSON(obj) {
    if (!sessionKey) { ws.send(JSON.stringify(obj)); return; }
    ws.send(JSON.stringify({ sec: encryptForSession(sessionKey, obj) }));
  }

  // Kick off: send server public keys and signed banner
  const banner = {
    msg: 'server-hello',
    serverEdPub: serverEdPub,
    serverXPub: serverXPub,
    signed: signEd25519(serverEdPriv, Buffer.from(serverXPub)).toString('base64'),
    logVerifyPub: logVerifyPub,
    manifest: manifest
  };
  ws.send(JSON.stringify(banner));

  // Heartbeat supervision
  heartbeats.timer = setInterval(() => {
    try {
      ws.ping();
      const since = Number(nowTicks() - heartbeats.last) / 1e9;
      if (since > 10) {
        immediateClose(ws, 4002, 'heartbeat-timeout');
      }
    } catch {
      immediateClose(ws, 4002, 'heartbeat-failed');
    }
  }, 3000);

  ws.on('pong', () => { heartbeats.last = nowTicks(); });

  ws.on('message', async (raw) => {
    try {
      const m = JSON.parse(raw.toString());
      let msg = m;
      if (m.sec && sessionKey) {
        msg = decryptFromSession(sessionKey, m.sec);
      }

      // 1) ECDH session establishment (client provides its X25519 pub and signature proving it owns its key)
      if (msg.msg === 'client-ecdh') {
        const { user_key_claim, clientXPub, sig, version, hwid } = msg;
        user_key = user_key_claim; // never sent key material; just an identifier
        // Verify client signature: sig over (clientXPub || serverXPub) with the client's stored public key
        // Lookup client public key by user_key from your secured auth DB (not shown fully here). Example placeholder:
        const clientPubKeyPem = await new Promise((resolve, reject) => {
          // Replace with real DB for client authentication keys
          // For demo, store a PEM file per user_key in keys/clients/<user_key>.pub
          const p = path.join(__dirname, 'keys', 'clients', `${user_key}.pub`);
          fs.readFile(p, 'utf8', (err, data) => err ? reject(new Error('unknown-user')) : resolve(data));
        });

        const ok = verifyEd25519(clientPubKeyPem, Buffer.from(clientXPub + serverXPub, 'utf8'), Buffer.from(sig, 'base64'));
        if (!ok) {
          await saveAuthLog(user_key, ip, hwid || '', Buffer.from('sig-verify-failed'));
          immediateClose(ws, 4010, 'failed-auth'); return;
        }

        // Enforce bans
        if (await isBanned(user_key)) { immediateClose(ws, 4030, 'banned'); return; }

        // ECDH derive session key
        sessionKey = ecdhX25519(serverXPriv, clientXPub);

        // Update user/ip/hwid records and enforce IP limit
        await upsertUser(user_key, version || 'unknown');
        await pruneOldIPs();
        await updateIP(user_key, ip);
        const ipCount = await countIPs(user_key);
        if (ipCount > 3) { immediateClose(ws, 4012, 'ip-limit'); return; }
        if (hwid) await addHWID(user_key, hwid);

        // Record successful handshake log (encrypted blob)
        const { iv, enc, tag } = aesGcmEncrypt(sessionKey, serialize({ time: Number(nowTicks()), ip, hwid, event: 'handshake-ok', clientXPub }));
        await saveAuthLog(user_key, ip, hwid || '', Buffer.concat([iv, tag, enc]));

        // Challenge both ways
        const chS = pickChallenge();
        const chDeadline = deadline(3000);
        sendJSON({ msg: 'challenge', payload: chS, deadlineNs: String(chDeadline.limit) });

        // Seed analytics
        sessions.set(ws, { user_key, sessionKey, startTicks, analytics: newAnalytics(user_key), heartbeatTicks: heartbeats.last });

        return;
      }

      // 2) Client challenge answer
      if (msg.msg === 'challenge-answer') {
        const st = sessions.get(ws);
        if (!st) { immediateClose(ws, 4015, 'no-session'); return; }
        const { payload, answer, deadlineNs } = msg;
        if (nowTicks() > BigInt(deadlineNs)) { st.analytics.challenges_failed++; immediateClose(ws, 4016, 'challenge-timeout'); return; }
        const sol = solve(payload);
        const ok = JSON.stringify(sol) === JSON.stringify(answer);
        if (!ok) { st.analytics.challenges_failed++; immediateClose(ws, 4017, 'challenge-failed'); return; }
        st.analytics.challenges_solved++;

        // Server responds with its own answer to client-issued challenge if any shipped in the same message
        if (msg.backChallenge) {
          const sol2 = solve(msg.backChallenge);
          sendJSON({ msg: 'challenge-answer-back', answer: sol2, echo: hash256(Buffer.from(JSON.stringify(msg.backChallenge))).toString('hex') });
        }

        // Issue JWT
        const { token, expMs } = issueJWT(st.user_key);
        await saveToken(st.user_key, token, expMs);
        sendJSON({ msg: 'jwt', tokenEncrypted: encryptForSession(st.sessionKey, { token }) });

        // Send manifest
        sendJSON({ msg: 'manifest', manifest });

        return;
      }

      // 3) Client asks for raw code by hash
      if (msg.msg === 'code-request') {
        const st = sessions.get(ws);
        if (!st) { immediateClose(ws, 4015, 'no-session'); return; }
        const { file, sha256 } = msg;
        const filePath = path.join(__dirname, 'client-code', file);
        if (!fs.existsSync(filePath)) { immediateClose(ws, 4040, 'no-file'); return; }
        const code = fs.readFileSync(filePath);
        const digest = hash256(code).toString('hex');
        if (digest !== sha256) {
          // Provide authoritative code anyway (client will replace)
          sendJSON({ msg: 'code', file, sha256: digest, code: code.toString('utf8') });
        } else {
          sendJSON({ msg: 'code', file, sha256: digest, code: code.toString('utf8') });
        }
        return;
      }

      // 4) Integrity logs upload (one encrypted log at a time)
      if (msg.msg === 'integrity-log') {
        const st = sessions.get(ws);
        if (!st) { immediateClose(ws, 4015, 'no-session'); return; }
        await saveIntegrityLog(st.user_key, Buffer.from(msg.blob, 'base64'));
        sendJSON({ msg: 'integrity-log-ack' });
        return;
      }

      // 5) Client session analytics flush (on close or periodically)
      if (msg.msg === 'analytics-flush') {
        const st = sessions.get(ws);
        if (!st) return;
        const connectedMs = Math.floor(Number(nowTicks() - st.startTicks) / 1000000);
        const row = {
          user_key: st.user_key,
          connected_time: connectedMs,
          challenges_solved: st.analytics.challenges_solved,
          challenges_failed: st.analytics.challenges_failed,
          login_time: Date.now() // also persisted ms for webpage
        };
        await saveSessionAnalytics(row);
        await upsertGlobalAnalytics(row);
        return;
      }

      // 6) Client integrity fail alert
      if (msg.msg === 'integrity-failed') {
        const st = sessions.get(ws);
        if (!st) { immediateClose(ws, 4015, 'no-session'); return; }
        // Immediate log and keep connection to allow uploads
        const blob = Buffer.from(JSON.stringify({ time: Number(nowTicks()), detail: msg.detail }), 'utf8');
        const { iv, enc, tag } = aesGcmEncrypt(st.sessionKey, blob);
        await saveIntegrityLog(st.user_key, Buffer.concat([iv, tag, enc]));
      }

    } catch (e) {
      immediateClose(ws, 5001, 'error');
    }
  });

  ws.on('close', async () => {
    clearInterval(heartbeats.timer);
    const st = sessions.get(ws);
    if (st) {
      try {
        // Calculate connected time in ms
        const connectedMs = Math.floor(Number(nowTicks() - st.startTicks) / 1e6);

        // Prepare analytics row
        const row = {
          user_key: st.user_key,
          connected_time: connectedMs,
          challenges_solved: st.analytics.challenges_solved,
          challenges_failed: st.analytics.challenges_failed,
          login_time: Date.now()
        };

        // Save per-session analytics
        await saveSessionAnalytics(row);

        // Update global analytics
        await upsertGlobalAnalytics(row);

        // Remove sensitive data from memory
        if (st.sessionKey) {
          st.sessionKey.fill(0);
        }
        st.analytics = null;
      } catch (err) {
        console.error('Error saving analytics on close:', err);
      } finally {
        sessions.delete(ws);
      }
    }
  });

  ws.on('error', (err) => {
    console.error('WebSocket error:', err);
    immediateClose(ws, 5002, 'ws-error');
  });
});

// Start HTTP + WS server
const PORT = 8081;
httpServer.listen(PORT, () => {
  console.log(`Auth server listening on http://localhost:${PORT}`);
});
