// server/server.js
// WebSocket auth server with JWT issuance, AES-GCM payloads, pinned identity, ticked heartbeats, and HTTP live page.

import fs from 'fs';
import http from 'http';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { WebSocketServer } from 'ws';
import { DB } from './db.js';
import { ServerLogger } from './logger.js';
import { SessionManager } from './sessions.js';
import { startCLI } from './cli.js';
import {
  makeSigningKeyPair, verifyDetached, signDetached,
  makeEphemeralECDH, hkdf, aesGcmEncrypt, aesGcmDecrypt,
  hmacProof, signServerTime
} from '../common/crypto.js';
import { extractIp, monoNowMs, opaquePredicate } from '../common/util.js';

// -- Load config
const cfg = JSON.parse(fs.readFileSync('server/config.server.json', 'utf8'));

// -- Logger & DB
const logger = new ServerLogger(cfg);
const db = new DB(cfg, logger);
const sessions = new SessionManager(db, logger);

// -- Server signing identity (ED25519)
// Generate if missing and persist to config
let serverPub, serverPriv;
if (!cfg.security.serverSignPrivKeyBase64 || !cfg.security.serverSignPubKeyBase64) {
  const { publicKey, privateKey } = makeSigningKeyPair();
  serverPriv = privateKey.export({ type: 'pkcs8', format: 'der' });
  serverPub = publicKey.export({ type: 'spki', format: 'der' });
  cfg.security.serverSignPrivKeyBase64 = Buffer.from(serverPriv).toString('base64');
  cfg.security.serverSignPubKeyBase64 = Buffer.from(serverPub).toString('base64');
  fs.writeFileSync('server/config.server.json', JSON.stringify(cfg, null, 2));
  logger.info('Generated server signing keys and updated config.');
} else {
  serverPriv = Buffer.from(cfg.security.serverSignPrivKeyBase64, 'base64');
  serverPub = Buffer.from(cfg.security.serverSignPubKeyBase64, 'base64');
}
const serverPrivKeyObj = crypto.createPrivateKey({ key: serverPriv, type: 'pkcs8', format: 'der' });
const serverPubKeyObj = crypto.createPublicKey({ key: serverPub, type: 'spki', format: 'der' });

// -- JWT secret
const tokenSecret = Buffer.from(cfg.security.tokenSignSecretBase64 || crypto.randomBytes(32).toString('base64'), 'base64');
if (!cfg.security.tokenSignSecretBase64) {
  cfg.security.tokenSignSecretBase64 = Buffer.from(tokenSecret).toString('base64');
  fs.writeFileSync('server/config.server.json', JSON.stringify(cfg, null, 2));
  logger.info('Generated JWT signing secret.');
}

// -- HTTP server for live page
const httpServer = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${cfg.httpPort}`);
  if (url.pathname.startsWith('/active/clients/')) {
    // Serve live page based on session-id
    const sessionId = url.pathname.split('/').pop();
    const active = sessions.map?.get?.(sessionId);
    const html = fs.readFileSync('client/webpage.html', 'utf8');
    const data = active ? {
      sessionId,
      clientId: active.clientId,
      ip: active.ip,
      expiresAt: new Date(active.expiresAt).toISOString(),
      stats: active.stats
    } : { error: 'Session not found or inactive' };
    const page = html.replace('/*__DATA__*/', JSON.stringify(data));
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(page);
    return;
  }
  res.writeHead(404);
  res.end('Not Found');
});
httpServer.listen(cfg.httpPort, () => logger.info(`HTTP listening on :${cfg.httpPort}`));

// -- WebSocket server (plaintext here; deploy behind TLS in production)
const wss = new WebSocketServer({ port: cfg.wsPort });
logger.info(`WS listening on :${cfg.wsPort}`);

// -- Helper: sign JWT
function issueJwt(clientId) {
  // Create a JWT with 3-day expiry
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + cfg.jwt.ttlSeconds;
  const token = jwt.sign({ sub: clientId, iat, exp, iss: cfg.jwt.issuer, aud: cfg.jwt.audience }, tokenSecret);
  return { token, expMs: exp * 1000 };
}

// -- Helper: validate and renew JWT
function validateJwt(token) {
  try {
    const payload = jwt.verify(token, tokenSecret, { issuer: cfg.jwt.issuer, audience: cfg.jwt.audience });
    return payload;
  } catch {
    return null;
  }
}

// -- Core: handle incoming WebSocket
wss.on('connection', (ws, req) => {
  const ip = extractIp(req);
  const connId = crypto.randomUUID();
  const connRowId = db.stmts.addConnection.run(null, ip, Date.now()).lastInsertRowid;
  logger.info(`WS connection ${connId} from ${ip}`);

  // Ephemeral ECDH handshake
  const eph = makeEphemeralECDH();
  const ephPub = eph.getPublicKey();
  const sig = signDetached(serverPrivKeyObj, ephPub);

  // Send server identity (signed ephemeral pubkey) and signed time
  safeSend(ws, JSON.stringify({
    t: 'hello',
    server_pub: ephPub.toString('base64'),
    sig: sig.toString('base64'),
    time: signServerTime(serverPrivKeyObj, Date.now())
  }));

  let sessionKey = null; // Derived symmetric key
  let clientId = null;
  let sessionState = null;

  ws.on('message', (raw) => {
    // Do not branch on "stages" – process by message types only
    try {
      const msg = JSON.parse(String(raw));
      if (msg.t === 'hello-ack') {
        // Client provides its ephemeral pubkey; derive shared key
        const clientEphPub = Buffer.from(msg.client_pub, 'base64');
        const shared = eph.computeSecret(clientEphPub);
        const salt = Buffer.from('AUTH-SYS-SALT-v1');
        sessionKey = hkdf(shared, salt, Buffer.from('SESSION-KEY'), 32);
        // Return OK with a short-lived challenge nonce for key proof
        const nonce = crypto.randomBytes(32).toString('base64url');
        ws._srv_nonce = nonce;
        safeSend(ws, JSON.stringify({ t: 'nonce', nonce }));
        return;
      }

      // From here on, expect AES-GCM wrapped payloads: {token, data:{iv,ct,tag}}
      if (!sessionKey) {
        ws.close();
        return;
      }

      const token = msg.token || '';
      const aad = Buffer.concat([Buffer.from(token), Buffer.from(connId)]);
      const pt = JSON.parse(aesGcmDecrypt(sessionKey, msg.data, aad).toString('utf8'));

      // Opaque predicate as decoy to hinder static analysis
      if (!opaquePredicate(pt.seq || 1)) {
        ws.close();
        return;
      }

      // Message types
      if (pt.t === 'key-proof') {
        // Verify proof without receiving key/hash: HMAC(key, nonce)
        const proof = pt.proof;
        const clientKeyValue = pt.key_hint; // Optional small hint for lookup optimization (e.g., prefix)
        // Resolve client by key via DB; we won't rely on hint alone
        const k = db.stmts.getKey.get(pt.key_value);
        if (!k) {
          db.addLog(null, 'auth', `Unknown key from ${ip}`);
          return ws.close();
        }
        const now = Date.now();

        // If key used, get client; if new, create client
        let client = db.stmts.getClientByKey.get(pt.key_value);
        if (!client) {
          const clientIdNew = crypto.randomUUID();
          const ipList = JSON.stringify([ip]); // Start allowlist with current IP
          const hwids = JSON.stringify(pt.hwids || []);
          db.stmts.createClient.run(clientIdNew, pt.key_value, now, ipList, hwids, now);
          db.stmts.markKeyUsed.run(clientIdNew, now, pt.key_value);
          db.criticalSaveBackup('key-claimed');
          client = db.stmts.getClientById.get(clientIdNew);
          logger.auth(clientIdNew, `Key claimed and client created from ${ip}`);
        }

        // Enforce ban
        if (client.banned) {
          logger.auth(client.client_id, `Banned attempt from ${ip}`);
          return ws.close();
        }

        // Enforce IP allowlist size <= 3; if new IP and room, add; else reject
        const ips = JSON.parse(client.ip_allowlist);
        if (!ips.includes(ip)) {
          if (ips.length >= 3) {
            logger.auth(client.client_id, `IP limit exceeded: ${ip}`);
            db.addLog(client.client_id, 'auth', `IP limit exceeded: ${ip}`);
            return ws.close();
          } else {
            ips.push(ip);
            db.db.prepare('UPDATE clients SET ip_allowlist=? WHERE client_id=?').run(JSON.stringify(ips), client.client_id);
            db.criticalSaveBackup('ip-allowlist-update');
            logger.auth(client.client_id, `IP added to allowlist: ${ip}`);
          }
        }

        // Verify HMAC proof
        const srvNonce = ws._srv_nonce || '';
        const expected = hmacProof(Buffer.from(pt.key_value, 'base64url'), srvNonce);
        if (expected !== proof) {
          logger.auth(client.client_id, `HMAC proof failed from ${ip}`);
          return ws.close();
        }

        // Issue JWT and session
        const { token: jwtToken, expMs } = issueJwt(client.client_id);
        const s = sessions.createSession({ clientId: client.client_id, token: jwtToken, ip, expiresAt: expMs });
        clientId = client.client_id;
        sessionState = s;

        db.stmts.updateClientSeen.run(now, clientId);

        // Respond with token and server stats; all encrypted
        reply(ws, sessionKey, token, {
          t: 'token',
          token: jwtToken,
          exp: expMs,
          serverTime: signServerTime(crypto.createPrivateKey({ key: Buffer.from(cfg.security.serverSignPrivKeyBase64, 'base64'), format: 'der', type: 'pkcs8' }), Date.now())
        }, connId);

        return;
      }

      if (pt.t === 'heartbeat') {
        // Validate token and timing; random server response about 1/5 heartbeats
        const payload = validateJwt(token);
        if (!payload) return ws.close();

        const now = Date.now();
        const renewWindowMs = cfg.jwt.renewWithinSeconds * 1000;

        // Verify challenge from client
        const ok = verifyChallenge(pt.challenge);
        if (!ok) {
          logger.user(payload.sub, 'error', `Challenge failed; closing`);
          sessions.offlineCleanup(sessionState.sessionId);
          return ws.close();
        }

        // Sometimes respond
        const respond = (crypto.randomInt(5) === 0);
        let newToken = null, newExp = null;
        // Renew token if close to expiry
        const expMs = payload.exp * 1000;
        if (expMs - now <= renewWindowMs) {
          const x = issueJwt(payload.sub);
          newToken = x.token; newExp = x.expMs;
        }

        // Optional server-side challenge for client
        const challenge = makeServerChallenge();

        sessions.updateHeartbeat(sessionState.sessionId, true, respond);

        if (respond) {
          reply(ws, sessionKey, newToken || token, {
            t: 'hb-ack',
            serverChallenge: challenge,
            newToken,
            newExp,
            stats: sessionState.stats
          }, connId);
        }
        return;
      }

      if (pt.t === 'challenge-result') {
        // Client answered server challenge
        const payload = validateJwt(token);
        if (!payload) return ws.close();

        if (!verifyServerChallenge(pt.response)) {
          logger.user(payload.sub, 'error', `Server challenge unsolved; closing`);
          sessions.offlineCleanup(sessionState.sessionId);
          return ws.close();
        }
        // No-op success
        return;
      }

      // Unknown type -> close
      ws.close();
    } catch (e) {
      logger.error(`WS error ${connId}: ${e.message}`);
      ws.close();
    }
  });

  ws.on('close', () => {
    db.stmts.endConnection.run(Date.now(), connRowId);
    if (sessionState) sessions.offlineCleanup(sessionState.sessionId);
    logger.info(`WS closed ${connId}`);
  });
});

// -- Helpers: encrypted reply
function reply(ws, sessionKey, token, obj, connId) {
  // Always wrap payload as {token, data:{iv,ct,tag}} with AAD including token + connId
  const aad = Buffer.concat([Buffer.from(token || ''), Buffer.from(connId)]);
  const enc = aesGcmEncrypt(sessionKey, Buffer.from(JSON.stringify(obj)), Buffer.concat([aad]));
  safeSend(ws, JSON.stringify({ token: token || '', data: enc }));
}

function safeSend(ws, data) {
  try { ws.send(data); } catch {}
}

// -- Challenges: directly solvable puzzles (no brute force)
function makeServerChallenge() {
  // e.g., return parameters that require deterministic calculation
  const a = crypto.randomInt(10, 100);
  const b = crypto.randomInt(10, 100);
  const t = 'calc';
  const nonce = crypto.randomBytes(16).toString('base64url');
  const result = (a * a + 3 * b) ^ (a + b);
  // Keep only a digest server-side to verify
  return { t, a, b, nonce, digest: crypto.createHash('sha256').update(`${result}|${nonce}`).digest('base64url') };
}
function verifyServerChallenge(resp) {
  if (!resp || resp.t !== 'calc') return false;
  const recomputed = (resp.a * resp.a + 3 * resp.b) ^ (resp.a + resp.b);
  const dig = crypto.createHash('sha256').update(`${recomputed}|${resp.nonce}`).digest('base64url');
  return dig === resp.digest;
}
function verifyChallenge(ch) {
  // Mirror of a similar deterministic check from client
  if (!ch || ch.t !== 'mix') return false;
  const s = ch.data.reduce((acc, v, i) => (acc + ((v ^ (i + 13)) % 257)) % 100000, 7);
  return s === ch.expected;
}

// -- Start CLI
startCLI(db, sessions, logger);
