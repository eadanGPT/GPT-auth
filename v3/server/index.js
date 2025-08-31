// server/index.js
// WebSocket auth server with JWT, ECDH/AES-GCM, tick Q/A challenges,
// HTTP live page, CLI, SQLite persistence with autosave.

const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const readline = require('readline');

const { aesEncrypt, aesDecrypt, generateECDH, hkdfSha256, sign, verify, pubkeyFingerprint, sha256Buf, monotonicNowNs } = require('../shared/crypto');
const DB = require('./db');
const Sessions = require('./sessions');
const Logger = require('./logger');

// --- Load or initialize config and RSA keys ---

const CONFIG_PATH = path.join(__dirname, 'config.json');
let config = {
  port: 8081,            // WebSocket+HTTP server port
  jwtSecret: null,       // Random secret for JWT signing
  rsaPrivatePath: path.join(__dirname, 'privatekey.pem'),
  rsaPublicPath: path.join(__dirname, 'publickey.pem'),
  allowedHosts: [],      // Optional: list of allowed Host headers
  httpHost: '0.0.0.0'
};
if (fs.existsSync(CONFIG_PATH)) {
  Object.assign(config, JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')));
} else {
  config.jwtSecret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

// Generate/load RSA long-term keypair
function ensureRSA() {
  if (!fs.existsSync(config.rsaPrivatePath) || !fs.existsSync(config.rsaPublicPath)) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
    fs.writeFileSync(config.rsaPrivatePath, privateKey.export({ type: 'pkcs1', format: 'pem' }));
    fs.writeFileSync(config.rsaPublicPath, publicKey.export({ type: 'pkcs1', format: 'pem' }));
  }
}
ensureRSA();

const serverPrivate = fs.readFileSync(config.rsaPrivatePath, 'utf8');
const serverPublic = fs.readFileSync(config.rsaPublicPath, 'utf8');
const serverPubFp = pubkeyFingerprint(serverPublic);

// --- Initialize components ---

const db = new DB(path.join(__dirname, 'data.sqlite'), serverPrivate);
const sessions = new Sessions();
const log = new Logger(path.join(__dirname, 'logs'));

// --- HTTP server for live page and file/integrity services ---

const httpServer = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);

  // Optional host allowlist check
  if (config.allowedHosts.length && !config.allowedHosts.includes(req.headers.host)) {
    res.writeHead(403); return res.end('Forbidden');
  }

  // Live client page: /active/clients/connId
  if (req.method === 'GET' && /^\/active\/clients\/[A-Za-z0-9_-]+$/.test(parsed.pathname)) {
    const connId = parsed.pathname.split('/').pop();
    const s = sessions.get(connId);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    if (!s) return res.end(`<h1>No live session for ${connId}</h1>`);
    const client = db.getClientById(s.clientId);
    const page = `
      <html><head><title>Client ${s.clientId}</title></head>
      <body>
        <h1>Client ${s.clientId}</h1>
        <p><b>Conn:</b> ${connId}</p>
        <p><b>IPs:</b> ${(client?.ips || []).join(', ')}</p>
        <p><b>Ban status:</b> ${client?.banned_until ? 'Banned until ' + new Date(client.banned_until).toISOString() : 'Not banned'}</p>
        <p><b>Live stats:</b> heartbeats=${s.stats.heartbeats}, challengesIssued=${s.stats.challengesIssued}, challengesSolved=${s.stats.challengesSolved}</p>
        <p><b>Last seen:</b> ${new Date(s.lastSeen).toISOString()}</p>
      </body></html>`;
    return res.end(page);
  }

  // File digest map (for integrity checks) - require server-chosen secret header for security
  if (req.method === 'GET' && parsed.pathname === '/integrity/digests') {
    if (req.headers['x-server-key'] !== sha256Buf(Buffer.from(config.jwtSecret))) {
      res.writeHead(401); return res.end('Unauthorized');
    }
    const digests = db.getFileDigests(); // Persisted set computed at startup
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(digests));
  }

  // Raw file service by path (restricted to client/ directory)
  if (req.method === 'GET' && parsed.pathname.startsWith('/integrity/file')) {
    if (req.headers['x-server-key'] !== sha256Buf(Buffer.from(config.jwtSecret))) {
      res.writeHead(401); return res.end('Unauthorized');
    }
    const q = parsed.query;
    if (!q || !q.relpath || q.relpath.includes('..')) {
      res.writeHead(400); return res.end('Bad request');
    }
    const filePath = path.join(__dirname, '..', 'client', q.relpath);
    if (!fs.existsSync(filePath)) {
      res.writeHead(404); return res.end('Not found');
    }
    res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
    return fs.createReadStream(filePath).pipe(res);
  }

  // Default
  res.writeHead(404);
  res.end('Not found');
});

// --- WebSocket server ---

const wss = new WebSocket.Server({ server: httpServer });

// Utility: envelope encrypt
function encryptEnvelope(sessionKey, token, obj) {
  const ts = Date.now(); // server timestamp (validated on client)
  const payload = Buffer.from(JSON.stringify({ ts, ...obj }));
  const aad = Buffer.from(String(ts));
  const { iv, ct, tag } = aesEncrypt(payload, sessionKey, aad);
  return { token, iv: iv.toString('base64'), tag: tag.toString('base64'), data: ct.toString('base64'), ts };
}

// Utility: envelope decrypt
function decryptEnvelope(sessionKey, msg) {
  const { iv, tag, data, ts } = msg;
  const aad = Buffer.from(String(ts));
  const pt = aesDecrypt({
    iv: Buffer.from(iv, 'base64'),
    tag: Buffer.from(tag, 'base64'),
    ct: Buffer.from(data, 'base64')
  }, sessionKey, aad);
  return JSON.parse(pt.toString('utf8'));
}

// Random solvable challenge generator (no brute force)
function makeChallenge() {
  // Simple arithmetic with nonce to avoid replay
  const a = 1000 + Math.floor(Math.random() * 9000);
  const b = 1000 + Math.floor(Math.random() * 9000);
  const op = ['+', '-', '^'][Math.floor(Math.random() * 3)];
  const expr = `${a}${op}${b}`;
  let expected;
  switch (op) {
    case '+': expected = a + b; break;
    case '-': expected = a - b; break;
    case '^': expected = a ^ b; break;
  }
  const nonce = crypto.randomBytes(12).toString('hex');
  return { id: crypto.randomUUID(), expr, expected, nonce };
}

// JWT helpers
function issueToken(clientId, connId, ip) {
  const nowSec = Math.floor(Date.now() / 1000);
  const exp = nowSec + 3 * 24 * 3600; // 3 days
  const token = jwt.sign({ sub: clientId, sid: connId, ip }, config.jwtSecret, { algorithm: 'HS256', expiresIn: exp - nowSec, notBefore: 0 });
  return token;
}

function verifyToken(token) {
  try { return jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] }); }
  catch { return null; }
}

// --- Connection handling ---

wss.on('connection', (ws, req) => {
  const remoteIP = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString();

  // Per-connection volatile state (no explicit auth stage variables)
  const ecdh = generateECDH();
  let sessionKey = null;
  let connId = crypto.randomUUID();
  let clientId = null;
  let jwtToken = null;
  let lastHeartbeatMonotonic = monotonicNowNs();
  let ticks = 0;

  const wsSend = (obj) => ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify(obj));

  // Send server's ECDH pubkey signed by RSA to prove identity
  const serverPub = ecdh.getPublicKey();
  const signed = sign(serverPub, serverPrivate);
  wsSend({ type: 'kex', serverPub: serverPub.toString('base64'), sig: signed.toString('base64'), serverTime: Date.now(), serverPubFp: serverPubFp });

  // Handle incoming messages
  ws.on('message', async (raw) => {
    try {
      const msg = JSON.parse(raw.toString());

      // ECDH key material from client
      if (msg.type === 'kex') {
        const clientPub = Buffer.from(msg.clientPub, 'base64');
        // Session key derivation via HKDF
        const shared = ecdh.computeSecret(clientPub);
        const { key: k } = await hkdfSha256(shared, undefined, Buffer.from('wss-session'));
        sessionKey = k;
        // Optional: reply ack
        return;
      }

      // From here on, require sessionKey and encrypted envelopes
      if (!sessionKey) return ws.close(1008, 'No session');

      // Decrypt envelope
      const inner = decryptEnvelope(sessionKey, msg);
      const type = inner.type;

      // Client presents server pubkey fingerprint to pin identity and avoid MITM
      if (type === 'pin') {
        if (inner.serverPubFp !== serverPubFp) {
          log.error('auth', `Pin mismatch from ${remoteIP}`);
          return ws.close(4003, 'Pin mismatch');
        }
        return;
      }

      // Anti-tamper: validate client timestamp is sane (±120s)
      if (Math.abs(Date.now() - inner.ts) > 120000) {
        log.error('auth', `Timestamp skew from ${remoteIP}`);
        return ws.close(4009, 'Skew');
      }

      // Client authentication by key+IP; HWID logged separately.
      if (type === 'auth') {
        const { hmac, nonce } = inner; // HMAC-SHA256(key, nonce)
        // Find key in DB by checking HMAC across unused/used keys (keys stored encrypted or plain per your policy)
        const rec = db.findClientByKeyHMAC(hmac, nonce);
        if (!rec) {
          log.auth(`Failed auth from ${remoteIP}`);
          wsSend(encryptEnvelope(sessionKey, null, { type: 'auth_result', ok: false }));
          return ws.close(4001, 'Auth failed');
        }

        // IP limit check
        const allowed = db.updateClientIPs(rec.id, remoteIP);
        if (!allowed) {
          log.auth(`IP limit exceeded for ${rec.id} from ${remoteIP}`);
          wsSend(encryptEnvelope(sessionKey, null, { type: 'auth_result', ok: false, reason: '
