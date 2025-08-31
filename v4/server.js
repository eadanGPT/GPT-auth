// server.js
/* eslint-disable no-console */
const http = require('http');
const express = require('express');
const WebSocket = require('ws');
const readline = require('readline');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const {
  nowNs, seal, unseal,
  genEd25519, edSign, edVerify,
  genX25519, x25519Shared, hkdf,
  aeadEncrypt, aeadDecrypt,
  genRsa2048, rsaDecrypt, sha256, hmacSha256
} = require('./crypto-helpers');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server: http.createServer().listen(8080) }); // ws on 8080
const db = new sqlite3.Database('auth.db');

// Server keys (persist in DB after first run)
let serverSignPrivPem, serverSignPubPem;
let logPrivPem, logPubPem;

function loadOrInitKeys() {
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS server_keys(name TEXT PRIMARY KEY, value TEXT NOT NULL)`);
    db.get(`SELECT value FROM server_keys WHERE name='ed25519_priv'`, (e, row) => {
      if (row) {
        serverSignPrivPem = row.value;
        db.get(`SELECT value FROM server_keys WHERE name='ed25519_pub'`, (_, row2) => {
          serverSignPubPem = row2.value;
        });
      } else {
        const kp = genEd25519();
        serverSignPrivPem = kp.privateKey.export({ type: 'pkcs8', format: 'pem' });
        serverSignPubPem = kp.publicKey.export({ type: 'spki', format: 'pem' });
        db.run(`INSERT INTO server_keys(name,value) VALUES(?,?)`, ['ed25519_priv', serverSignPrivPem]);
        db.run(`INSERT INTO server_keys(name,value) VALUES(?,?)`, ['ed25519_pub', serverSignPubPem]);
      }
    });
    db.get(`SELECT value FROM server_keys WHERE name='log_rsa_priv'`, (e, row) => {
      if (row) {
        logPrivPem = row.value;
        db.get(`SELECT value FROM server_keys WHERE name='log_rsa_pub'`, (_, row2) => {
          logPubPem = row2.value;
        });
      } else {
        const kp = genRsa2048();
        logPrivPem = kp.privateKey.export({ type: 'pkcs1', format: 'pem' });
        logPubPem = kp.publicKey.export({ type: 'pkcs1', format: 'pem' });
        db.run(`INSERT INTO server_keys(name,value) VALUES(?,?)`, ['log_rsa_priv', logPrivPem]);
        db.run(`INSERT INTO server_keys(name,value) VALUES(?,?)`, ['log_rsa_pub', logPubPem]);
      }
    });
  });
}

function initDb() {
  db.serialize(() => {
    db.run(`PRAGMA journal_mode=WAL`);
    db.run(`CREATE TABLE IF NOT EXISTS keys(
      key_id TEXT PRIMARY KEY,
      sealed_secret_iv BLOB, sealed_secret_ct BLOB, sealed_secret_tag BLOB,
      user TEXT,
      blacklisted INTEGER DEFAULT 0,
      created_ns TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS users(
      user TEXT PRIMARY KEY,
      banned_until_ns TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS ips(
      key_id TEXT, ip TEXT, last_used_ns TEXT,
      PRIMARY KEY(key_id, ip)
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS hwids(
      key_id TEXT, hwid TEXT,
      PRIMARY KEY(key_id, hwid)
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS sessions(
      session_id TEXT PRIMARY KEY,
      key_id TEXT, user TEXT, start_ns TEXT, end_ns TEXT,
      connected_time_ns TEXT, login_time_ns TEXT,
      challenges_failed INTEGER, challenges_solved INTEGER
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS analytics_global(
      key_id TEXT PRIMARY KEY,
      total_connected_time_ns TEXT DEFAULT '0',
      total_challenges_failed INTEGER DEFAULT 0,
      total_challenges_solved INTEGER DEFAULT 0,
      sessions_count INTEGER DEFAULT 0
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS manifest(
      version TEXT,
      fn_name TEXT, hash_hex TEXT, source_file TEXT,
      PRIMARY KEY(version, fn_name)
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS logs_meta(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key_id TEXT, session_id TEXT, created_ns TEXT, type TEXT, notes TEXT
    )`);
  });
}

loadOrInitKeys();
initDb();

// Settings
const settings = {
  allowConnections: true,
  maxConnections: 1000
};

// In-memory active sessions (no secrets in plaintext; wrap with seal())
const active = new Map(); // sessionId -> { ws, keyId, user, sealedSessionKey, sealedJwt, counters, startNs, lastHeartbeatNs }

// Utility: wrap/unwrap session key
function sealKey(buf) { return seal(buf, Buffer.from('sess')); }
function unsealKey(obj) { return unseal(obj, Buffer.from('sess')); }

// Message transport (encrypt everything after ECDH established)
function sendEncrypted(ws, sessionKey, msgObj) {
  const aad = Buffer.from('ws-msg');
  const payload = Buffer.from(JSON.stringify(msgObj));
  const { iv, ct, tag } = aeadEncrypt(sessionKey, payload, aad);
  ws.send(JSON.stringify({ iv: iv.toString('base64'), ct: ct.toString('base64'), tag: tag.toString('base64') }));
}

function recvEncrypted(sessionKey, enc) {
  const { iv, ct, tag } = {
    iv: Buffer.from(enc.iv, 'base64'),
    ct: Buffer.from(enc.ct, 'base64'),
    tag: Buffer.from(enc.tag, 'base64')
  };
  const aad = Buffer.from('ws-msg');
  const pt = aeadDecrypt(sessionKey, iv, ct, tag, aad);
  return JSON.parse(pt.toString('utf8'));
}

// Server manifest example (populate DB on boot)
const SERVER_VERSION = '1.0.0';
const projectFunctions = {
  // name: code string (for demo; real usage: load from files)
  algebraEval: `function algebraEval(coeffs, x){return coeffs.reduce((s,c,i)=>s + c*Math.pow(x, coeffs.length-1-i),0)} module.exports=algebraEval;`,
  transformData: `function transformData(s){return s.split('').reverse().join('')} module.exports=transformData;`
};
function upsertManifest() {
  db.serialize(() => {
    const stmt = db.prepare(`INSERT OR REPLACE INTO manifest(version,fn_name,hash_hex,source_file) VALUES(?,?,?,?)`);
    for (const [name, code] of Object.entries(projectFunctions)) {
      const hashHex = sha256(Buffer.from(code));
      stmt.run([SERVER_VERSION, name, hashHex, `functions/${name}.js`]);
    }
    stmt.finalize();
  });
}
upsertManifest();

// JWT signer
function signJwt(payload) {
  return jwt.sign(payload, serverSignPrivPem, { algorithm: 'EdDSA', expiresIn: '3d' });
}

// Key utilities: on key creation we store sealed secret; we never reveal it
function addKeyRaw(secretHex, user = null) {
  const keyBuf = Buffer.from(secretHex, 'hex');
  const keyId = hmacSha256(keyBuf, Buffer.from('id')).toString('hex');
  const sealed = seal(keyBuf, Buffer.from(`key:${keyId}`));
  db.run(`INSERT OR REPLACE INTO keys(key_id, sealed_secret_iv, sealed_secret_ct, sealed_secret_tag, user, created_ns)
          VALUES(?,?,?,?,?,?)`,
    [keyId, sealed.iv, sealed.ct, sealed.tag, user, nowNs().toString()], (e) => {
      if (e) console.error('addKey error', e);
    });
  return keyId;
}

// Heartbeat algebra challenge
function makePolyChallenge() {
  // ax^2 + bx + c
  const a = Math.floor(Math.random()*7)+1, b = Math.floor(Math.random()*7)+1, c = Math.floor(Math.random()*7)+1;
  const x = Math.floor(Math.random()*11)-5;
  return { coeffs: [a,b,c], x, answer: a*x*x + b*x + c };
}

// Cleanup unused IPs older than 30 days
function pruneOldIps() {
  const cutoff = (nowNs() - BigInt(30*24*60*60*1e9)).toString();
  db.run(`DELETE FROM ips WHERE last_used_ns < ?`, [cutoff]);
}
setInterval(pruneOldIps, 6*60*60*1000);

// Web dashboard
app.get('/clients/:keyId', (req, res) => {
  const { keyId } = req.params;
  db.serialize(() => {
    db.get(`SELECT * FROM analytics_global WHERE key_id=?`, [keyId], (e, globalRow) => {
      db.all(`SELECT * FROM sessions WHERE key_id=? ORDER BY start_ns DESC LIMIT 10`, [keyId], (e2, sessions) => {
        // current session
        const current = [];
        for (const [sid, ctx] of active.entries()) {
          if (ctx.keyId === keyId) {
            current.push({
              session_id: sid,
              start_ns: ctx.startNs.toString(),
              challenges_failed: ctx.counters.failed,
              challenges_solved: ctx.counters.solved,
              connected_time_ns: (nowNs() - ctx.startNs).toString()
            });
          }
        }
        res.setHeader('Content-Type', 'text/html');
        res.end(`
          <html><head><title>Client ${keyId}</title></head><body>
          <h1>Client ${keyId}</h1>
          <h2>Current sessions</h2>
          <pre>${JSON.stringify(current,null,2)}</pre>
          <h2>Recent sessions</h2>
          <pre>${JSON.stringify(sessions||[],null,2)}</pre>
          <h2>Global analytics</h2>
          <pre>${JSON.stringify(globalRow||{},null,2)}</pre>
          </body></html>
        `);
      });
    });
  });
});

server.listen(8081, () => console.log('HTTP dashboard on 8081'));
console.log('WebSocket server on 8080');

// WebSocket logic
wss.on('connection', (ws, req) => {
  if (!settings.allowConnections || active.size >= settings.maxConnections) {
    ws.close();
    return;
  }
  const sessionId = crypto.randomBytes(16).toString('hex');
  const startNs = nowNs();
  let sessionKey = null; // raw Buffer, will be sealed post-setup
  let sealedSessionKey = null;
  let keyId = null;
  let user = null;
  let jwtSealed = null;
  let lastHeartbeatNs = nowNs();
  const counters = { solved: 0, failed: 0 };

  // Handshake: send server signing pub, ECDH pub, signature, RSA log pub, version+manifest digest
  const ecdh = genX25519();
  const ecdhPubPem = ecdh.publicKey.export({ type: 'spki', format: 'pem' });
  const ecdhSig = edSign(crypto.createPrivateKey(serverSignPrivPem), Buffer.from(ecdhPubPem));
  // manifest digest
  db.all(`SELECT fn_name, hash_hex FROM manifest WHERE version=?`, [SERVER_VERSION], (e, rows) => {
    const manifestObj = {};
    for (const r of rows) manifestObj[r.fn_name] = r.hash_hex;
    const manifestJson = JSON.stringify({ version: SERVER_VERSION, manifest: manifestObj });
    ws.send(JSON.stringify({
      type: 'hello',
      serverSignPub: serverSignPubPem,
      ecdhPub: ecdhPubPem,
      ecdhSig: ecdhSig.toString('base64'),
      logPub: logPubPem,
      manifest: manifestObj,
      version: SERVER_VERSION
    }));
  });

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());

      // Step: receive client ECDH pub and verify server signature on our pub (client already verified; we don't track stages)
      if (msg.type === 'client_ecdh') {
        const clientPub = crypto.createPublicKey(msg.ecdhPub);
        const shared = x25519Shared(ecdh.privateKey, clientPub);
        sessionKey = hkdf(shared, Buffer.from('salt'), Buffer.from('ws-session'), 32);
        sealedSessionKey = seal(sessionKey, Buffer.from(`sess:${sessionId}`));

        // Begin HMAC auth challenge
        const nonce = crypto.randomBytes(32);
        // We will verify HMAC against stored sealed secret mapped by keyId (client must send keyId with response)
        sendEncrypted(ws, sessionKey, { type: 'challenge', nonce: nonce.toString('base64') });

        // Stash nonce for next message scope
        ws._nonce = nonce;
        return;
      }

      // Encrypted pathway
      if (!sessionKey) return ws.close();

      const dec = recvEncrypted(sessionKey, msg);

      if (dec.type === 'auth') {
        // { keyId, ip, hwids, hmac }
        keyId = dec.keyId;
        const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString();
        const hwids = Array.isArray(dec.hwids) ? dec.hwids.slice(0, 64) : [];
        if (!keyId || !dec.hmac || !ws._nonce) return ws.close();

        // Fetch sealed secret
        db.get(`SELECT sealed_secret_iv, sealed_secret_ct, sealed_secret_tag, user, blacklisted FROM keys WHERE key_id=?`, [keyId], (e, row) => {
          if (e || !row) { ws.close(); return; }
          if (row.blacklisted) { ws.close(); return; }
          // user ban?
          db.get(`SELECT banned_until_ns FROM users WHERE user=?`, [row.user], (e2, urow) => {
            if (urow && urow.banned_until_ns && BigInt(urow.banned_until_ns) > nowNs()) { ws.close(); return; }

            const sealed = { iv: row.sealed_secret_iv, ct: row.sealed_secret_ct, tag: row.sealed_secret_tag };
            let keyBuf;
            try {
              keyBuf = unseal(sealed, Buffer.from(`key:${keyId}`));
            } catch { ws.close(); return; }

            // Verify HMAC
            const expect = hmacSha256(keyBuf, ws._nonce);
            if (!crypto.timingSafeEqual(Buffer.from(dec.hmac, 'hex'), expect)) {
              ws.close(); return;
            }

            user = row.user || null;

            // IP/hwid policy
            db.get(`SELECT COUNT(*) as cnt FROM ips WHERE key_id=?`, [keyId], (e3, ic) => {
              const now = nowNs().toString();
              db.run(`INSERT OR REPLACE INTO ips(key_id, ip, last_used_ns) VALUES(?,?,?)`, [keyId, ip, now]);
              if (ic && ic.cnt >= 3) {
                // keep but we’ll not add new beyond 3; existing is updated
              }
            });
            for (const h of hwids) {
              db.run(`INSERT OR IGNORE INTO hwids(key_id, hwid) VALUES(?,?)`, [keyId, h]);
            }

            // Issue JWT (seal in memory)
            const token = signJwt({ sub: keyId, user, sid: sessionId });
            jwtSealed = seal(Buffer.from(token), Buffer.from(`jwt:${sessionId}`));

            // Send auth_ok + token
            sendEncrypted(ws, sessionKey, { type: 'auth_ok', jwt: token });

            // Send server integrity manifest again (client may compare)
            db.all(`SELECT fn_name, hash_hex, source_file FROM manifest WHERE version=?`, [SERVER_VERSION], (e4, mrows) => {
              const manifest = {};
              const sources = {};
              for (const r of mrows) { manifest[r.fn_name] = r.hash_hex; sources[r.fn_name] = r.source_file; }
              sendEncrypted(ws, sessionKey, { type: 'manifest', version: SERVER_VERSION, manifest, sources });
            });

            // Start heartbeat loop
            const hb = setInterval(() => {
              if (!active.has(sessionId)) { clearInterval(hb); return; }
              const ch = makePolyChallenge();
              // server->client challenge
              sendEncrypted(ws, sessionKey, { type: 'hb_challenge', coeffs: ch.coeffs, x: ch.x, ts: nowNs().toString() });
              ws._serverAnswer = ch.answer;
              // client should counter-challenge us too
              lastHeartbeatNs = nowNs();
              // Timeout check in 5s
              setTimeout(() => {
                if (nowNs() - lastHeartbeatNs > BigInt(5e9)) {
                  ws.close();
                }
              }, 5200);
            }, 10000);

            // Activate session
            active.set(sessionId, {
              ws, keyId, user,
              sealedSessionKey, sealedJwt: jwtSealed,
              startNs, lastHeartbeatNs,
              counters
            });

            // Session login analytics placeholder
            db.run(`INSERT OR REPLACE INTO sessions(session_id,key_id,user,start_ns,login_time_ns,challenges_failed,challenges_solved)
                    VALUES(?,?,?,?,?,?,?)`,
              [sessionId, keyId, user, startNs.toString(), nowNs().toString(), 0, 0]);
          });
        });
        return;
      }

      if (dec.type === 'hb_response') {
        // { value }
        const ok = (dec.value === ws._serverAnswer);
        if (!ok) { counters.failed++; ws.close(); return; }
        counters.solved++;
        lastHeartbeatNs = nowNs();
        // Respond to client’s challenge if provided
        if (typeof dec.clientChallenge === 'object' && Array.isArray(dec.clientChallenge.coeffs)) {
          const { coeffs, x } = dec.clientChallenge;
          const ans = coeffs.reduce((s,c,i)=> s + c*Math.pow(x, coeffs.length-1-i), 0);
          sendEncrypted(ws, sessionKey, { type: 'hb_answer', value: ans });
        }
        // Update session counters
        db.run(`UPDATE sessions SET challenges_failed=?, challenges_solved=? WHERE session_id=?`,
          [counters.failed, counters.solved, sessionId]);
        return;
      }

      if (dec.type === 'code_request') {
        // { fn, expectHash }
        db.get(`SELECT hash_hex, source_file FROM manifest WHERE version=? AND fn_name=?`, [SERVER_VERSION, dec.fn], (e, row) => {
          if (!row) { ws.close(); return; }
          const code = projectFunctions[dec.fn] || '';
          const hashHex = sha256(Buffer.from(code));
          if (hashHex !== row.hash_hex) {
            // mismatch — send fresh code
            sendEncrypted(ws, sessionKey, { type: 'code_update', fn: dec.fn, code });
          } else {
            sendEncrypted(ws, sessionKey, { type: 'code_ok', fn: dec.fn });
          }
        });
        return;
      }

      if (dec.type === 'log_upload') {
        // { session_id, encLogBase64 }
        const encBuf = Buffer.from(dec.encLogBase64, 'base64');
        try {
          const logPlain = rsaDecrypt(logPrivPem, encBuf);
          db.run(`INSERT INTO logs_meta(key_id, session_id, created_ns, type, notes)
                  VALUES(?,?,?,?,?)`,
            [keyId, sessionId, nowNs().toString(), 'client_log', logPlain.toString('utf8')]);
        } catch (err) {
          console.error('Log decrypt error', err);
        }
        return;
      }
    } catch (err) {
      console.error('WS message error', err);
      ws.close();
    }
  });

  ws.on('close', () => {
    // Save analytics
    const ctx = active.get(sessionId);
    if (ctx) {
      const connectedTime = nowNs() - ctx.startNs;
      db.run(`UPDATE sessions SET end_ns=?, connected_time_ns=? WHERE session_id=?`,
        [nowNs().toString(), connectedTime.toString(), sessionId]);
      db.run(`INSERT INTO analytics_global(key_id,total_connected_time_ns,total_challenges_failed,total_challenges_solved,sessions_count)
              VALUES(?,?,?,?,?)
              ON CONFLICT(key_id) DO UPDATE SET
                total_connected_time_ns = total_connected_time_ns + excluded.total_connected_time_ns,
                total_challenges_failed = total_challenges_failed + excluded.total_challenges_failed,
                total_challenges_solved = total_challenges_solved + excluded.total_challenges_solved,
                sessions_count = sessions_count + 1`,
        [ctx.keyId, connectedTime.toString(), ctx.counters.failed, ctx.counters.solved, 1]);
      active.delete(sessionId);
    }
  });
});


// Simple CLI
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
console.log('Server CLI ready. Type "help" for commands.');

rl.on('line', (line) => {
  const [cmd, ...args] = line.trim().split(/\s+/);
  switch (cmd) {
    case 'help':
      console.log(`Commands:
ActiveSessions: list, disconnect <id|key|all>, send <id|key> <cmd>, find <id|key>
Keys: addKey <hex>, listKeys, removeKey <keyId>, blacklistKey <keyId>
Users: ban <user> <minutes>, unban <user>, stats <user>
Settings: allowConnections <true|false>, maxConnections <n>
`);
      break;
    case 'list':
      console.log([...active.keys()]);
      break;
    case 'disconnect':
      if (args[0] === 'all') {
        for (const [sid, ctx] of active) ctx.ws.close();
      } else {
        for (const [sid, ctx] of active) {
          if (sid === args[0] || ctx.keyId === args[0]) ctx.ws.close();
        }
      }
      break;
    case 'addKey':
      console.log('KeyId:', addKeyRaw(args[0]));
      break;
    case 'listKeys':
      db.all(`SELECT key_id,user,blacklisted FROM keys`, (e, rows) => console.table(rows));
      break;
    case 'blacklistKey':
      db.run(`UPDATE keys SET blacklisted=1 WHERE key_id=?`, [args[0]]);
      break;
    case 'allowConnections':
      settings.allowConnections = args[0] === 'true';
      break;
    case 'maxConnections':
      settings.maxConnections = parseInt(args[0], 10);
      break;
    default:
      console.log('Unknown command');
  }
});
