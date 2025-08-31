// server.js
// Node >=18
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const readline = require('readline');

const CONFIG = {
  host: '0.0.0.0',
  port: 8081,
  jwtSecret: crypto.randomBytes(32).toString('hex'),
  tokenTTLms: 3 * 24 * 60 * 60 * 1000, // 3 days
  renewWindowMs: 6 * 60 * 60 * 1000,    // 6 hours
  maxIPsPerClient: 3,
  tickIntervalMs: 30_000,
  tickTimeoutMs: 60_000,
  dbPath: path.join(__dirname, 'auth.sqlite'),
  backupPath: path.join(__dirname, 'backup', `auth-backup-${Date.now()}.sqlite`),
};

// Create backup folder if not exists
fs.mkdirSync(path.join(__dirname, 'backup'), { recursive: true });

// Long-term Ed25519 keypair for server identity (pin this pubkey on clients)
const keyDir = path.join(__dirname, 'keys');
fs.mkdirSync(keyDir, { recursive: true });
const edSkPath = path.join(keyDir, 'server-ed25519-sk.pem');
const edPkPath = path.join(keyDir, 'server-ed25519-pk.pem');

function ensureServerKeys() {
  if (!fs.existsSync(edSkPath) || !fs.existsSync(edPkPath)) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    fs.writeFileSync(edSkPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
    fs.writeFileSync(edPkPath, publicKey.export({ type: 'spki', format: 'pem' }));
  }
}
ensureServerKeys();

const serverSK = crypto.createPrivateKey(fs.readFileSync(edSkPath));
const serverPK = crypto.createPublicKey(fs.readFileSync(edPkPath));
const pinnedServerPubPem = serverPK.export({ type: 'spki', format: 'pem' }); // print for client config
console.log('Server Ed25519 public key (pin on clients):\n', pinnedServerPubPem);

// SQLite schema
const db = new Database(CONFIG.dbPath);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS keys(
  keyId TEXT PRIMARY KEY,
  keyHash TEXT NOT NULL,
  used INTEGER DEFAULT 0,
  createdAt INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS clients(
  clientId TEXT PRIMARY KEY,
  keyId TEXT NOT NULL,
  createdAt INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  sessionId TEXT PRIMARY KEY,
  clientId TEXT NOT NULL,
  token TEXT NOT NULL,
  issuedAt INTEGER NOT NULL,
  expiresAt INTEGER NOT NULL,
  ip TEXT NOT NULL,
  valid INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS ips(
  clientId TEXT NOT NULL,
  ip TEXT NOT NULL,
  lastSeen INTEGER NOT NULL,
  UNIQUE(clientId, ip)
);
CREATE TABLE IF NOT EXISTS hwids(
  clientId TEXT NOT NULL,
  hwidHash TEXT NOT NULL,
  lastSeen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS bans(
  clientId TEXT PRIMARY KEY,
  until INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  clientId TEXT,
  event TEXT NOT NULL,
  data TEXT
);
`);

// Prepared statements
const stmt = {
  insertKey: db.prepare('INSERT INTO keys(keyId, keyHash, createdAt) VALUES(?, ?, ?)'),
  getKey: db.prepare('SELECT * FROM keys WHERE keyId=?'),
  markKeyUsed: db.prepare('UPDATE keys SET used=1 WHERE keyId=?'),
  getClientByKey: db.prepare('SELECT * FROM clients WHERE keyId=?'),
  createClient: db.prepare('INSERT INTO clients(clientId, keyId, createdAt) VALUES(?, ?, ?)'),
  insertSession: db.prepare('INSERT INTO sessions(sessionId, clientId, token, issuedAt, expiresAt, ip) VALUES(?, ?, ?, ?, ?, ?)'),
  invalidateSession: db.prepare('UPDATE sessions SET valid=0 WHERE sessionId=?'),
  getActiveSessions: db.prepare('SELECT sessionId, clientId, ip, issuedAt, expiresAt, valid FROM sessions WHERE valid=1'),
  listUnusedKeys: db.prepare('SELECT keyId, createdAt FROM keys WHERE used=0'),
  setIP: db.prepare('INSERT OR REPLACE INTO ips(clientId, ip, lastSeen) VALUES(?, ?, ?)'),
  countIPs: db.prepare('SELECT COUNT(*) as c FROM ips WHERE clientId=?'),
  banUpsert: db.prepare('INSERT INTO bans(clientId, until) VALUES(?, ?) ON CONFLICT(clientId) DO UPDATE SET until=excluded.until'),
  getBan: db.prepare('SELECT until FROM bans WHERE clientId=?'),
  addHWID: db.prepare('INSERT INTO hwids(clientId, hwidHash, lastSeen) VALUES(?, ?, ?)'),
  log: db.prepare('INSERT INTO logs(ts, clientId, event, data) VALUES(?, ?, ?, ?)'),
};

function now() { return Date.now(); }
function logEv(event, clientId, data) {
  stmt.log.run(now(), clientId || null, event, data ? JSON.stringify(data) : null);
}

// HKDF-SHA256
function hkdf(key, salt, info, length = 32) {
  return crypto.hkdfSync('sha256', key, salt, info, length);
}

function aesEncrypt(key, plaintextObj) {
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from('v1');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: undefined });
  const pt = Buffer.from(JSON.stringify(plaintextObj));
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('base64'), ct: ct.toString('base64'), tag: tag.toString('base64') };
}

function aesDecrypt(key, ivB64, ctB64, tagB64) {
  const iv = Buffer.from(ivB64, 'base64');
  const ct = Buffer.from(ctB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const aad = Buffer.from('v1');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  decipher.setAAD(aad, { plaintextLength: undefined });
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return JSON.parse(pt.toString('utf8'));
}

function signEd25519(dataBuf) {
  return crypto.sign(null, dataBuf, serverSK);
}

function verifyHMACKeyHash(serverStoredKeyHashHex, nonceBuf, providedHmacHex) {
  const key = Buffer.from(serverStoredKeyHashHex, 'hex'); // hk (32 bytes)
  const h = crypto.createHmac('sha256', key).update(nonceBuf).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(providedHmacHex, 'hex'));
}

function makeJWT(clientId, sessionId, ttlMs) {
  const iat = Math.floor(now() / 1000);
  const exp = iat + Math.floor(ttlMs / 1000);
  return jwt.sign({ sub: clientId, sid: sessionId }, CONFIG.jwtSecret, { algorithm: 'HS256', iat, expiresIn: exp - iat });
}

function verifyJWT(token) {
  try { return jwt.verify(token, CONFIG.jwtSecret, { algorithms: ['HS256'] }); }
  catch { return null; }
}

// Active session manager
class ActiveSession {
  constructor(ws, clientId, sessionId, ip, aesKey) {
    this.ws = ws;
    this.clientId = clientId;
    this.sessionId = sessionId;
    this.ip = ip;
    this.aesKey = aesKey;
    this.lastSeenMono = process.hrtime.bigint();
    this.stats = { ticksRcvd: 0, ticksSent: 0, challengesOk: 0, challengesFail: 0 };
    this.pendingChallenge = null;
    this.closed = false;
  }
  sendEncrypted(token, obj) {
    const env = aesEncrypt(this.aesKey, obj);
    const packet = {
      token,
      iv: env.iv,
      ct: env.ct,
      tag: env.tag,
      ts: now(),
    };
    this.ws.send(JSON.stringify(packet));
  }
  close(reason) {
    if (this.closed) return;
    this.closed = true;
    try { this.ws.close(1000, reason || 'bye'); } catch {}
    stmt.invalidateSession.run(this.sessionId);
    logEv('session_closed', this.clientId, { sessionId: this.sessionId, reason });
  }
}

const sessions = new Map(); // sessionId -> ActiveSession

// HTTP + WS
const server = http.createServer();
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws, req) => {
  const remoteIP = req.socket.remoteAddress;
  // Ephemeral ECDH
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const srvPub = ecdh.getPublicKey(); // Buffer
  const handshakeNonce = crypto.randomBytes(32);
  const toSign = Buffer.concat([Buffer.from('HSK1'), srvPub, handshakeNonce]);
  const sig = signEd25519(toSign);

  // Stage: send server handshake
  ws.send(JSON.stringify({
    hello: srvPub.toString('base64'),
    nonce: handshakeNonce.toString('base64'),
    sig: sig.toString('base64'),
    pk: pinnedServerPubPem, // For client pin print/verification convenience
  }));

  let aesKey = null;
  let authComplete = false;
  let clientId = null;
  let sessionId = null;
  let jwtToken = null;
  let authNonce = crypto.randomBytes(32);

  const monoStart = process.hrtime.bigint();
  const tickTimers = new Set();

  function scheduleTimeoutCheck() {
    const timer = setTimeout(() => {
      // If no ticks or missed answers, close
      const sess = sessions.get(sessionId);
      if (!sess || sess.stats.ticksRcvd === 0) {
        try { ws.close(1011, 'timeout'); } catch {}
      }
    }, CONFIG.tickTimeoutMs + 5_000);
    tickTimers.add(timer);
  }

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      // Expect ECDH client share first
      if (!aesKey) {
        if (!msg.clientPub || !msg.nonce) { ws.close(1002, 'bad handshake'); return; }
        const cliPub = Buffer.from(msg.clientPub, 'base64');
        const shared = ecdh.computeSecret(cliPub);
        // Optional client signature verification can be added if you have client identities
        const salt = Buffer.from('SALT1');
        aesKey = hkdf(shared, salt, Buffer.concat([Buffer.from('WS-AES'), handshakeNonce, Buffer.from([1])]), 32);
        // Send encrypted auth nonce
        const env = aesEncrypt(aesKey, { type: 'auth_nonce', n: authNonce.toString('base64') });
        ws.send(JSON.stringify({ token: null, iv: env.iv, ct: env.ct, tag: env.tag, ts: now() }));
        scheduleTimeoutCheck();
        return;
      }

      // From here on, decrypt envelope
      const { token, iv, ct, tag, ts } = msg;
      // Skew check (allow ±5 min)
      if (typeof ts !== 'number' || Math.abs(now() - ts) > 5 * 60 * 1000) { ws.close(1002, 'ts skew'); return; }
      const inner = aesDecrypt(aesKey, iv, ct, tag);

      if (!authComplete) {
        if (inner.type !== 'auth') { ws.close(1002, 'expected auth'); return; }
        const { keyId, h, hwids = [] } = inner;
        const rec = stmt.getKey.get(keyId);
        if (!rec) { ws.close(1008, 'no key'); return; }

        const hOk = verifyHMACKeyHash(rec.keyHash, authNonce, h);
        if (!hOk) { ws.close(1008, 'bad key'); return; }

        // Bind/create client
        let client = stmt.getClientByKey.get(keyId);
        if (!client) {
          clientId = crypto.randomUUID();
          stmt.createClient.run(clientId, keyId, now());
          stmt.markKeyUsed.run(keyId);
          logEv('client_created', clientId, { keyId });
        } else {
          clientId = client.clientId;
        }

        // Ban check
        const ban = stmt.getBan.get(clientId);
        if (ban && ban.until > now()) { ws.close(1008, 'banned'); return; }

        // IP cap
        stmt.setIP.run(clientId, remoteIP, now());
        const { c } = stmt.countIPs.get(clientId);
        if (c > CONFIG.maxIPsPerClient) { ws.close(1008, 'ip-limit'); return; }

        // Record HWIDs (log only)
        const seen = new Set();
        for (const hw of hwids.slice(0, 64)) {
          if (typeof hw === 'string' && hw.length <= 128 && !seen.has(hw)) {
            stmt.addHWID.run(clientId, hw, now());
            seen.add(hw);
          }
        }

        // Issue session + token
        sessionId = crypto.randomUUID();
        const tokenNew = makeJWT(clientId, sessionId, CONFIG.tokenTTLms);
        const decoded = jwt.decode(tokenNew);
        jwtToken = tokenNew;
        stmt.insertSession.run(sessionId, clientId, tokenNew, decoded.iat * 1000, decoded.exp * 1000, remoteIP);
        logEv('session_started', clientId, { sessionId, ip: remoteIP });

        // Send welcome + seed for challenges
        const challengeSeed = crypto.randomBytes(32).toString('base64');
        const payload = { type: 'welcome', sessionId, token: tokenNew, seed: challengeSeed };
        const env = aesEncrypt(aesKey, payload);
        ws.send(JSON.stringify({ token: tokenNew, iv: env.iv, ct: env.ct, tag: env.tag, ts: now() }));
        authComplete = true;
        sessions.set(sessionId, new ActiveSession(ws, clientId, sessionId, remoteIP, aesKey));
        return;
      }

      // Post-auth: verify token maps to active session
      const decoded = verifyJWT(token);
      if (!decoded || decoded.sid !== sessionId || decoded.sub !== clientId) { ws.close(1008, 'bad token'); return; }

      const sess = sessions.get(sessionId);
      if (!sess) { ws.close(1011, 'no session'); return; }

      // Token renewal window
      const msLeft = decoded.exp * 1000 - now();
      if (msLeft < CONFIG.renewWindowMs) {
        const t2 = makeJWT(clientId, sessionId, CONFIG.tokenTTLms);
        const env2 = aesEncrypt(aesKey, { type: 'token_renew', token: t2, exp: jwt.decode(t2).exp * 1000 });
        ws.send(JSON.stringify({ token: t2, iv: env2.iv, ct: env2.ct, tag: env2.tag, ts: now() }));
        stmt.invalidateSession.run(sessionId);
        stmt.insertSession.run(sessionId, clientId, t2, jwt.decode(t2).iat * 1000, jwt.decode(t2).exp * 1000, remoteIP);
        jwtToken = t2;
      }

      // Handle inner messages
      switch (inner.type) {
        case 'tick': {
          sess.stats.ticksRcvd++;
          sess.lastSeenMono = process.hrtime.bigint();

          // Validate client's answer to prior server challenge (if any)
          if (sess.pendingChallenge) {
            const { q, expect, deadlineMono } = sess.pendingChallenge;
            if (inner.ans && inner.ans === expect && process.hrtime.bigint() < deadlineMono) {
              sess.stats.challengesOk++;
            } else {
              sess.stats.challengesFail++;
              sess.close('challenge-fail');
              return;
            }
            sess.pendingChallenge = null;
          }

          // Occasionally respond (~1/5)
          const respond = (crypto.randomInt(1, 6) === 3);
          // Create a simple server challenge derived from known values (no brute force)
          const serverQNonce = crypto.randomBytes(16);
          const expect = crypto.createHash('sha256')
            .update(serverQNonce).update(Buffer.from(sessionId)).digest('hex').slice(0, 16);

          if (respond) {
            // Include a challenge the client must answer on its next tick
            const env = aesEncrypt(aesKey, {
              type: 'tick_ack',
              ok: true,
              q: serverQNonce.toString('base64'),
              // also include server stats snapshot
              stats: { r: sess.stats.ticksRcvd, s: sess.stats.ticksSent, ok: sess.stats.challengesOk, fail: sess.stats.challengesFail },
            });
            sess.sendEncrypted(jwtToken, { type: 'noop' }); // lightweight extra encrypted payload (optional)
            ws.send(JSON.stringify({ token: jwtToken, iv: env.iv, ct: env.ct, tag: env.tag, ts: now() }));
            // set pending challenge deadline
            sess.pendingChallenge = { q: serverQNonce, expect, deadlineMono: process.hrtime.bigint() + BigInt(CONFIG.tickTimeoutMs * 1_000_000) };
          }
          break;
        }

        case 'stats': {
          // Client can send its view for reconciliation
          logEv('stats', clientId, inner.snapshot || {});
          break;
        }

        default:
          // Ignore unknown types
          break;
      }
    } catch (e) {
      try { ws.close(1011, 'error'); } catch {}
    }
  });

  ws.on('close', () => {
    if (sessionId && sessions.has(sessionId)) {
      const sess = sessions.get(sessionId);
      sessions.delete(sessionId);
      if (sess && !sess.closed) sess.close('ws-close');
    }
  });
});

// DB checkpoint/backup every 2h
setInterval(() => {
  try {
    db.pragma('wal_checkpoint(RESTART)');
    fs.copyFileSync(CONFIG.dbPath, CONFIG.backupPath);
    logEv('db_checkpoint', null, { backup: CONFIG.backupPath });
  } catch (e) {
    console.error('DB checkpoint/backup error:', e.message);
  }
}, 2 * 60 * 60 * 1000);

// CLI
const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: '> ' });
console.log('CLI ready. Commands: add-key <keyId> <rawKey>, list-unused, list-active, ban <clientId> <minutes>, disconnect <sessionId>, exit');
rl.prompt();
rl.on('line', (line) => {
  const [cmd, ...args] = line.trim().split(/\s+/);
  try {
    switch (cmd) {
      case 'add-key': {
        const [keyId, rawKey] = args;
        if (!keyId || !rawKey) { console.log('Usage: add-key <keyId> <rawKey>'); break; }
        const hk = crypto.createHash('sha256').update(rawKey, 'utf8').digest('hex');
        stmt.insertKey.run(keyId, hk, now());
        console.log('Added key', keyId);
        break;
      }
      case 'list-unused': {
        const rows = stmt.listUnusedKeys.all();
        console.table(rows);
        break;
      }
      case 'list-active': {
        const rows = stmt.getActiveSessions.all();
        console.table(rows);
        break;
      }
      case 'ban': {
        const [clientId, minutes] = args;
        const until = now() + (parseInt(minutes || '0', 10) * 60 * 1000);
        stmt.banUpsert.run(clientId, until);
        console.log('Banned', clientId, 'until', new Date(until).toISOString());
        break;
      }
      case 'disconnect': {
        const [sessionId] = args;
        const sess = sessions.get(sessionId);
        if (sess) sess.close('cli-disconnect');
        console.log('Disconnected', sessionId);
        break;
      }
      case 'exit': {
        console.log('Saving and exiting...');
        db.pragma('wal_checkpoint(TRUNCATE)');
        process.exit(0);
      }
      default:
        if (cmd) console.log('Unknown command');
    }
  } catch (e) {
    console.error('CLI error:', e.message);
  }
  rl.prompt();
});

server.listen(CONFIG.port, CONFIG.host, () => {
  console.log(`WS server listening on ws://${CONFIG.host}:${CONFIG.port}`);
});
