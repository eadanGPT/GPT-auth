// server/index.js
// WebSocket auth server with JWT, ECDH/AES-GCM per message, tick Q/A challenges,
// integrity service, HTTP live page, CLI admin, SQLite persistence with autosave and critical saves.
// NOTE: Keep stage-less logic. No explicit "auth stage" flags.

const http = require('http');             // Serve live pages and integrity endpoints
const url = require('url');               // Parse request URLs
const fs = require('fs');                 // File IO for keys and assets
const path = require('path');             // Path joins/safety
const crypto = require('crypto');         // Cryptographic primitives
const jwt = require('jsonwebtoken');      // JWT issuance/verification
const WebSocket = require('ws');          // WebSocket server
const readline = require('readline');     // CLI admin interface

const {
  aesEncrypt, aesDecrypt, generateECDH, hkdfSha256,
  sign, verify, pubkeyFingerprint, sha256Buf, monotonicNowNs
} = require('../shared/crypto');          // Shared crypto helpers
const DB = require('./db');               // SQLite wrapper
const Sessions = require('./sessions');   // Active sessions manager
const Logger = require('./logger');       // Disk-only logger

// --- load or init server config ---
const CONFIG_PATH = path.join(__dirname, 'config.json'); // Server configuration path
let config = {
  port: 8081,                              // Combined HTTP+WS port
  jwtSecret: null,                         // JWT secret; generated once
  rsaPrivatePath: path.join(__dirname, 'privatekey.pem'), // Server long-term private RSA key
  rsaPublicPath: path.join(__dirname, 'publickey.pem'),   // Server long-term public RSA key
  allowedHosts: [],                        // Optional HTTP Host allowlist
  httpHost: '0.0.0.0'                      // Bind host for HTTP/WS
};
if (fs.existsSync(CONFIG_PATH)) {
  Object.assign(config, JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'))); // Load persisted config
} else {
  config.jwtSecret = crypto.randomBytes(32).toString('hex');               // Create new JWT secret on first run
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));          // Persist config
}

// --- ensure RSA keys exist and load them ---
function ensureRSA() {
  // Generate long-term RSA key if missing to support signing (pinning and log encryption)
  if (!fs.existsSync(config.rsaPrivatePath) || !fs.existsSync(config.rsaPublicPath)) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
    fs.writeFileSync(config.rsaPrivatePath, privateKey.export({ type: 'pkcs1', format: 'pem' })); // Save private key
    fs.writeFileSync(config.rsaPublicPath, publicKey.export({ type: 'pkcs1', format: 'pem' }));   // Save public key
  }
}
ensureRSA();

const serverPrivate = fs.readFileSync(config.rsaPrivatePath, 'utf8'); // Load private key PEM
const serverPublic = fs.readFileSync(config.rsaPublicPath, 'utf8');   // Load public key PEM
const serverPubFp = pubkeyFingerprint(serverPublic);                  // Compute server pubkey fingerprint for pinning

// --- init DB, sessions, logging ---
const db = new DB(path.join(__dirname, 'data.sqlite'), serverPrivate); // Initialize SQLite and integrity seeds
const sessions = new Sessions();                                       // Maintain active sessions + stats
const log = new Logger(path.join(__dirname, 'logs'));                  // Disk logger (auth, log, error files)

// --- HTTP server: live page, integrity digests, raw file service ---
const httpServer = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);                                              // Parse URL and query

  if (config.allowedHosts.length && !config.allowedHosts.includes(req.headers.host)) {  // Optional host restrict
    res.writeHead(403); return res.end('Forbidden');                                    // Reject unapproved host
  }

  // Serve a minimal live status page for an active session at /active/clients/connId
  if (req.method === 'GET' && /^\/active\/clients\/[A-Za-z0-9_-]+$/.test(parsed.pathname)) {
    const connId = parsed.pathname.split('/').pop();                                    // Extract connection ID
    const s = sessions.get(connId);                                                     // Find live session in RAM
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    if (!s) return res.end(`<h1>No live session for ${connId}</h1>`);                   // Show not-found if not alive
    const client = db.getClientById(s.clientId);                                        // Load DB client record
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
    return res.end(page);                                                                // Return live HTML page
  }

  // Integrity digest map endpoint, gated by a secret header derived from jwtSecret
  if (req.method === 'GET' && parsed.pathname === '/integrity/digests') {
    if (req.headers['x-server-key'] !== sha256Buf(Buffer.from(config.jwtSecret))) {     // Validate shared secret
      res.writeHead(401); return res.end('Unauthorized');                                // Reject if missing/invalid
    }
    const digests = db.getFileDigests();                                                // Read cached digests from DB
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(digests));                                            // Return integrity reference
  }

  // Raw file serving endpoint for integrity remediation (restricted to /client folder)
  if (req.method === 'GET' && parsed.pathname.startsWith('/integrity/file')) {
    if (req.headers['x-server-key'] !== sha256Buf(Buffer.from(config.jwtSecret))) {     // Validate shared secret
      res.writeHead(401); return res.end('Unauthorized');                                // Reject if invalid
    }
    const q = parsed.query;
    if (!q || !q.relpath || q.relpath.includes('..')) {                                 // Enforce path safety
      res.writeHead(400); return res.end('Bad request');
    }
    const filePath = path.join(__dirname, '..', 'client', q.relpath);                   // Resolve requested file path
    if (!fs.existsSync(filePath)) {                                                     // Ensure file exists
      res.writeHead(404); return res.end('Not found');
    }
    res.writeHead(200, { 'Content-Type': 'application/octet-stream' });                 // Serve as raw bytes
    return fs.createReadStream(filePath).pipe(res);
  }

  res.writeHead(404);                                                                    // Default 404 for other routes
  res.end('Not found');
});

// --- WebSocket server (combined with HTTP server) ---
const wss = new WebSocket.Server({ server: httpServer });                                // Attach WS to HTTP server

// Envelope helper: encrypt response with AES-GCM and include a timestamp
function encryptEnvelope(sessionKey, token, obj) {
  const ts = Date.now();                                                                // Server timestamp for AAD
  const payload = Buffer.from(JSON.stringify({ ts, ...obj }));                          // JSON payload with ts
  const aad = Buffer.from(String(ts));                                                  // AAD bound to timestamp
  const { iv, ct, tag } = aesEncrypt(payload, sessionKey, aad);                         // Encrypt with session key
  return { token, iv: iv.toString('base64'), tag: tag.toString('base64'), data: ct.toString('base64'), ts }; // Encrypted envelope
}

// Envelope helper: decrypt request with AES-GCM using session key
function decryptEnvelope(sessionKey, msg) {
  const { iv, tag, data, ts } = msg;                                                    // Extract envelope fields
  const aad = Buffer.from(String(ts));                                                  // Rebuild AAD from timestamp
  const pt = aesDecrypt({
    iv: Buffer.from(iv, 'base64'),
    tag: Buffer.from(tag, 'base64'),
    ct: Buffer.from(data, 'base64')
  }, sessionKey, aad);
  return JSON.parse(pt.toString('utf8'));                                               // Parse JSON payload
}

// Generate a simple, directly solvable challenge (no brute force)
function makeChallenge() {
  // Arithmetic/bitwise expression with nonce to avoid replay
  const a = 1000 + Math.floor(Math.random() * 9000);                                    // Random operand A
  const b = 1000 + Math.floor(Math.random() * 9000);                                    // Random operand B
  const op = ['+', '-', '^'][Math.floor(Math.random() * 3)];                            // Random operator
  const expr = `${a}${op}${b}`;                                                         // Expression as string
  let expected;
  switch (op) {                                                                          // Compute expected solution
    case '+': expected = a + b; break;
    case '-': expected = a - b; break;
    case '^': expected = a ^ b; break;
  }
  const nonce = crypto.randomBytes(12).toString('hex');                                 // Random nonce for binding
  return { id: crypto.randomUUID(), expr, expected, nonce };                            // Emit complete challenge
}

// JWT issuance: 3-day token lifetime, identify client and connection
function issueToken(clientId, connId, ip) {
  const nowSec = Math.floor(Date.now() / 1000);                                         // Current time in seconds
  const exp = nowSec + 3 * 24 * 3600;                                                   // Expire in 3 days
  return jwt.sign({ sub: clientId, sid: connId, ip }, config.jwtSecret, {
    algorithm: 'HS256',
    expiresIn: exp - nowSec,
    notBefore: 0
  });                                                                                   // Signed JWT
}

// Verify JWT; return claims or null on failure
function verifyToken(token) {
  try { return jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] }); }
  catch { return null; }
}

// --- Handle websocket connections ---
wss.on('connection', (ws, req) => {
  const remoteIP = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString(); // Extract remote IP

  const ecdh = generateECDH();                                                          // Generate ephemeral ECDH key
  let sessionKey = null;                                                                // Symmetric key post-KEX
  let connId = crypto.randomUUID();                                                     // Unique connection ID
  let clientId = null;                                                                  // Will be assigned after auth
  let jwtToken = null;                                                                  // Issued JWT for this session
  let lastHeartbeatMonotonic = monotonicNowNs();                                        // Monotonic last heartbeat moment
  let ticks = 0;                                                                        // Tick counter to track pace
  let lastClientChallenge = null;                                                       // Last challenge received from client
  let lastServerChallenge = null;                                                       // Last challenge server issued to client

  const wsSend = (obj) => ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify(obj)); // Safe send helper

  // Initial identity proof: send server's ECDH public key signed by long-term RSA
  const serverPub = ecdh.getPublicKey();                                                // Server ECDH public
  const signed = sign(serverPub, serverPrivate);                                        // Sign ECDH pub for pinning
  wsSend({ type: 'kex', serverPub: serverPub.toString('base64'), sig: signed.toString('base64'), serverTime: Date.now(), serverPubFp: serverPubFp }); // KEX offer

  // Incoming message handler
  ws.on('message', async (raw) => {
    try {
      const msg = JSON.parse(raw.toString());                                           // Parse inbound JSON

      // ECDH client response: finalize session key
      if (msg.type === 'kex') {
        const clientPub = Buffer.from(msg.clientPub, 'base64');                         // Client ECDH public
        const shared = ecdh.computeSecret(clientPub);                                   // Compute shared secret
        const { key: k } = await hkdfSha256(shared, undefined, Buffer.from('wss-session')); // HKDF derive AES-256 key
        sessionKey = k;                                                                 // Store session key
        return;                                                                          // KEX complete
      }

      if (!sessionKey) return ws.close(1008, 'No session');                              // Require KEX before proceeding

      // Decrypt incoming envelope with AES-GCM
      const inner = decryptEnvelope(sessionKey, msg);                                    // Symmetric decrypt
      const type = inner.type;                                                           // Message semantic type

      // Client pinning: verify the server public key fingerprint
      if (type === 'pin') {
        if (inner.serverPubFp !== serverPubFp) {
          log.error('auth', `Pin mismatch from ${remoteIP}`);                            // Log pin failures
          return ws.close(4003, 'Pin mismatch');                                         // Terminate on mismatch
        }
        return;                                                                          // Pin confirmed
      }

      // Validate timestamp sanity: ±120s skew allowed
      if (Math.abs(Date.now() - inner.ts) > 120000) {
        log.error('auth', `Timestamp skew from ${remoteIP}`);                            // Log skew anomalies
        return ws.close(4009, 'Skew');                                                   // Terminate on skew
      }

      // Client authentication packet (key+IP verify; HWID logged via separate packet)
      if (type === 'auth') {
        const { hmac, nonce } = inner;                                                  // HMAC(key, nonce) sent by client
        const rec = db.findClientByKeyHMAC(hmac, nonce);                                 // Resolve key/client
        if (!rec) {
          log.auth(`Failed auth from ${remoteIP}`);                                      // Log auth failure
          wsSend(encryptEnvelope(sessionKey, null, { type: 'auth_result', ok: false })); // Return failure
          return ws.close(4001, 'Auth failed');                                          // Terminate on failure
        }

        // IP limit enforcement: client may have up to 3 IPs total
        const allowed = db.updateClientIPs(rec.id, remoteIP);                            // Update/validate IPs
        if (!allowed) {
          log.auth(`IP limit exceeded for ${rec.id} from ${remoteIP}`);                  // Log IP limit breach
          wsSend(encryptEnvelope(sessionKey, null, { type: 'auth_result', ok: false, reason: 'ip_limit' })); // Return failure
          return ws.close(4010, 'IP limit');                                             // Terminate for policy
        }

        // Check ban status; if banned, reject
        const banUntil = db.getBanUntil(rec.id);                                         // Lookup ban expiry
        if (banUntil && banUntil > Date.now()) {
          log.auth(`Banned client ${rec.id} attempted from ${remoteIP}`);                // Log banned attempt
          wsSend(encryptEnvelope(sessionKey, null, { type: 'auth_result', ok: false, reason: 'banned' }));  // Return banned
          return ws.close(4011, 'Banned');                                               // Terminate banned
        }

        // Create JWT token and register active session
        clientId = rec.id;                                                               // Bind connection to client
        jwtToken = issueToken(clientId, connId, remoteIP);                               // Issue 3-day JWT
        sessions.add({ connId, clientId, ip: remoteIP });                                // Track live session
        db.recordConnection(clientId, remoteIP);                                         // Append to connection history
        log.auth(`Auth success ${clientId}@${remoteIP}`);                                // Log success

        // Return auth result with token and server fingerprint; include a solvable challenge for immediate health check
        const sChallenge = makeChallenge();                                              // Create server->client challenge
        lastServerChallenge = sChallenge;                                                // Keep last challenge to verify
        db.storeChallengeDigest(clientId, sChallenge.id, sChallenge.expr, sChallenge.nonce); // Persist digest for audit
        wsSend(encryptEnvelope(sessionKey, jwtToken, {
          type: 'auth_result',
          ok: true,
          serverPubFp,
          challenge: { id: sChallenge.id, expr: sChallenge.expr, nonce: sChallenge.nonce }
        }));                                                                             // Send success packet
        return;                                                                          // Done with auth
      }

      // HWID packet: log interfaces per client for analytics/auditing (not used for auth gating)
      if (type === 'hwid') {
        if (!msg.token || !verifyToken(msg.token)) {                                     // Require valid token
          return ws.close(4004, 'No token');                                             // Terminate if token missing/invalid
        }
        const { interfaces } = inner;                                                    // Received interfaces list
        if (clientId) db.updateClientHWID(clientId, interfaces);                         // Persist HWID info
        return;                                                                          // Acknowledge silently
      }

      // Token refresh request: allow within 6 hours of expiration
      if (type === 'token_refresh') {
        const claims = verifyToken(msg.token);                                           // Validate presented token
        if (!claims || claims.sub !== clientId) return ws.close(4005, 'Bad token');      // Reject invalid tokens
        const nowSec = Math.floor(Date.now() / 1000);                                    // Current seconds
        const timeLeft = (claims.exp || 0) - nowSec;                                     // Remaining time
        if (timeLeft <= 6 * 3600) {                                                      // Within 6 hours of expiry
          jwtToken = issueToken(clientId, connId, remoteIP);                             // Issue new token
          wsSend(encryptEnvelope(sessionKey, jwtToken, { type: 'token_ok' }));           // Confirm refresh
        } else {
          wsSend(encryptEnvelope(sessionKey, msg.token, { type: 'token_nok' }));         // Deny early refresh
        }
        return;                                                                          // Done
      }

      // Heartbeat tick: tick-based Q/A; bidirectional challenge solving
      if (type === 'tick') {
        const claims = verifyToken(msg.token);                                           // Verify per-packet token
        if (!claims || claims.sub !== clientId) return ws.close(4006, 'Token mismatch'); // Reject mismatched token
        lastHeartbeatMonotonic = monotonicNowNs();                                       // Update liveness marker
        ticks++;                                                                         // Increment tick count
        sessions.onHeartbeat(connId);                                                    // Update session stats

        // Client answer to previously issued server challenge
        if (inner.answer && lastServerChallenge && inner.answer.id === lastServerChallenge.id) {
          const ok = Number(inner.answer.solution) === Number(lastServerChallenge.expected); // Validate solution
          if (ok) {
            sessions.onChallengeSolved(connId);                                          // Update stats
          } else {
            log.error('auth', `Challenge failed by ${clientId}`);                        // Log failed challenge
            wsSend(encryptEnvelope(sessionKey, jwtToken, { type: 'terminate', reason: 'challenge_failed' })); // Notify client
            return ws.close(4012, 'Challenge fail');                                     // Terminate on failure
          }
          lastServerChallenge = null;                                                    // Clear outstanding challenge
        }

        // Verify and solve client's challenge to server, if present
        if (inner.challenge && inner.challenge.id && inner.challenge.expr) {
          // Recompute expected to verify client's future scoring
          const ch = inner.challenge;                                                    // Challenge object
          db.storeChallengeDigest(clientId, ch.id, ch.expr, ch.nonce);                   // Save digest for audit
          // Compute solution deterministically (same operator set)
          const m = ch.expr.match(/^(\d+)([+\-^])(\d+)$/);                               // Parse expression
          let sol = null;
          if (m) {
            const A = parseInt(m[1], 10), OP = m[2], B = parseInt(m[3], 10);            // Extract operands
            sol = (OP === '+') ? (A + B) : (OP === '-') ? (A - B) : (A ^ B);            // Compute result
          }
          if (sol === null) {
            log.error('error', `Bad client challenge format from ${clientId}`);          // Log malformed challenge
            wsSend(encryptEnvelope(sessionKey, jwtToken, { type: 'terminate', reason: 'bad_challenge' })); // Notify client
            return ws.close(4013, 'Bad challenge');                                      // Terminate on error
          }
          // Optionally respond to only ~1/5 ticks for heartbeat response cadence
          if (Math.random() < 0.2) {                                                     // Random ~20% acknowledge cadence
            wsSend(encryptEnvelope(sessionKey, jwtToken, { type: 'tick_ack', solution: { id: ch.id, solution: sol } })); // Reply with solution
          }
        }

        // Randomly issue a new server challenge to client (~1/5 ticks)
        if (Math.random() < 0.2) {
          const sChallenge = makeChallenge();                                            // Generate challenge
          lastServerChallenge = sChallenge;                                              // Hold expected answer
          sessions.onChallengeIssued(connId);                                            // Update stats
          db.storeChallengeDigest(clientId, sChallenge.id, sChallenge.expr, sChallenge.nonce); // Record digest
          wsSend(encryptEnvelope(sessionKey, jwtToken, { type: 'challenge', challenge: { id: sChallenge.id, expr: sChallenge.expr, nonce: sChallenge.nonce } })); // Send challenge
        }

        return;                                                                          // Done with tick
      }

      // Any other message types: ignore or close
      ws.close(4002, 'Unknown');                                                         // Close on unknown types
    } catch (e) {
      log.error('error', `WS error: ${e.message}`);                                      // Log parse/processing errors
      ws.close(1011, 'Server error');                                                    // Close with server error code
    }
  });

  // Enforce heartbeat timeout: terminate sessions without tick within 60 seconds
  const heartbeatInterval = setInterval(() => {
    const now = monotonicNowNs();                                                        // Monotonic now
    const elapsedSec = Number(now - lastHeartbeatMonotonic) / 1e9;                      // Convert nanoseconds to seconds
    if (elapsedSec > 60) {                                                               // If no heartbeat within 60 seconds
      log.error('error', `Heartbeat timeout ${connId}`);                                 // Log timeout
      try { ws.close(4008, 'Timeout'); } catch {}                                        // Close connection
      clearInterval(heartbeatInterval);                                                  // Clear monitoring interval
    }
  }, 5000);                                                                              // Check every 5 seconds

  // Clean up after socket closes
  ws.on('close', () => {
    clearInterval(heartbeatInterval);                                                    // Stop heartbeat watcher
    if (clientId) sessions.remove(connId);                                               // Remove from active sessions RAM
    db.flushCritical();                                                                  // Flush critical data to disk
  });

  // On error, log and terminate
  ws.on('error', (e) => {
    log.error('error', `WS fatal ${connId}: ${e.message}`);                              // Log WS error
    try { ws.close(); } catch {}                                                         // Attempt to close
  });
});

// --- CLI admin interface for keys, bans, sessions, and graceful shutdown ---
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });   // Setup CLI
const help = () => {
  console.log(`
Commands:
  help                          - Show this help
  genkeys N                     - Generate N new unused keys
  addkey KEY                    - Add a specific key string
  unused                        - List unused keys
  clients                       - List all clients
  active                        - List active sessions (DB)
  live                          - List live connections (RAM)
  ban CLIENT_ID MINUTES         - Temporarily ban a client for minutes
  disconnect CONN_ID            - Disconnect a live connection
  stats CLIENT_ID               - Show last 10 connections and stats
  exit                          - Save and exit
`); // CLI help banner
};

rl.on('line', (line) => {
  const [cmd, ...args] = line.trim().split(/\s+/);                                      // Tokenize command
  try {
    switch (cmd) {
      case 'help': help(); break;                                                        // Print help
      case 'genkeys': {
        const n = parseInt(args[0] || '1', 10);                                          // Number of keys to generate
        const list = db.generateKeys(n);                                                 // Create new unused keys
        console.log('Generated keys:', list.join(', '));                                 // Show keys
        db.flushCritical();                                                              // Save critical changes
        break;
      }
      case 'addkey': {
        const k = args[0]; if (!k) { console.log('Usage: addkey KEY'); break; }          // Validate input
        db.addKey(k);                                                                    // Add provided key
        db.flushCritical();                                                              // Save critical changes
        console.log('Added key.');                                                       // Acknowledge
        break;
      }
      case 'unused': {
        const keys = db.listUnusedKeys();                                                // List unused keys
        console.log('Unused keys:', keys.join(', '));                                    // Print list
        break;
      }
      case 'clients': {
        const clients = db.listClients(); // List all clients in DB
        clients.forEach(c => {
          console.log(`ID: ${c.id}, Key: ${c.keyMasked}, IPs: ${c.ips.join(', ')}, Banned: ${c.banned_until ? new Date(c.banned_until).toISOString() : 'No'}`);
        });
        break;
      }
      case 'active': {
        const active = db.listActiveSessions(); // DB view of active sessions
        console.table(active);
        break;
      }
      case 'live': {
        const live = sessions.list(); // RAM view of live connections
        console.table(live.map(s => ({
          connId: s.connId,
          clientId: s.clientId,
          ip: s.ip,
          heartbeats: s.stats.heartbeats
        })));
        break;
      }
      case 'ban': {
        const cid = args[0];
        const minutes = parseInt(args[1] || '0', 10);
        if (!cid || !minutes) { console.log('Usage: ban CLIENT_ID MINUTES'); break; }
        db.banClient(cid, minutes);
        db.flushCritical();
        console.log(`Banned ${cid} for ${minutes} minutes`);
        break;
      }
      case 'disconnect': {
        const connId = args[0];
        if (!connId) { console.log('Usage: disconnect CONN_ID'); break; }
        const wsConn = sessions.getWS(connId);
        if (wsConn) {
          wsConn.close(4000, 'Admin disconnect');
          console.log(`Disconnected ${connId}`);
        } else {
          console.log('No such live connection');
        }
        break;
      }
      case 'stats': {
        const cid = args[0];
        if (!cid) { console.log('Usage: stats CLIENT_ID'); break; }
        const stats = db.getClientStats(cid);
        console.log(`Last 10 connections for ${cid}:`);
        stats.lastConnections.forEach(c => console.log(`  ${c.ip} @ ${new Date(c.time).toISOString()}`));
        console.log('User statistics:', stats.userStats);
        break;
      }
      case 'exit': {
        console.log('Saving DB and shutting down...');
        db.flushCritical();
        process.exit(0);
        break;
      }
      default:
        console.log('Unknown command. Type "help" for list.');
    }
  } catch (err) {
    console.error('CLI error:', err);
  }
});

// Start HTTP+WS server
httpServer.listen(config.port, config.httpHost, () => {
  console.log(`Server listening on ${config.httpHost}:${config.port}`);
  help(); // Show CLI help on startup
});
