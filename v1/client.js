// client.js
// Node >= 18
// This client pairs with the previously provided server.js.
// It performs: pinned Ed25519 verification, ECDH+HKDF channel key, per-payload AES-256-GCM,
// key-based auth (HMAC of SHA-256(key) over server nonce), JWT handling, tick Q/A heartbeat,
// monotonic timing, token persistence, and exit-on-failure semantics.

const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const WebSocket = require('ws');

const CONFIG = {
  // Server
  url: 'ws://127.0.0.1:8081',

  // Client key credentials
  keyId: 'example-key-id',
  rawKey: 'super-secret-client-key',

  // Pinned server public key (from server startup stdout). Do NOT trust any key sent over the wire.
  pinnedServerEd25519PubPem: `-----BEGIN PUBLIC KEY-----
...paste the server Ed25519 public key here...
-----END PUBLIC KEY-----`,

  // Timings (client uses monotonic clock for control)
  tickIntervalMs: 30_000,
  tickTimeoutMs: 60_000,
  maxNoAckMs: 10 * 60_000, // if no server ack for this long, exit

  // Token persistence
  tokenStore: path.join(__dirname, 'client-token.json'),
};

function monotonicNowMs() {
  return Number(process.hrtime.bigint() / 1_000_000n);
}

// Crypto helpers
function hkdf(key, salt, info, length = 32) {
  return crypto.hkdfSync('sha256', key, salt, info, length);
}
function aesEncrypt(key, obj) {
  const iv = crypto.randomBytes(12);
  const aad = Buffer.from('v1');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: undefined });
  const pt = Buffer.from(JSON.stringify(obj));
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
function pinnedServerKey() {
  return crypto.createPublicKey(CONFIG.pinnedServerEd25519PubPem);
}
function verifyServerHandshakeSignature(serverPubBuf, serverNonceBuf, sigBuf) {
  // Signature is over: "HSK1" || serverEphemeralPub || handshakeNonce
  const data = Buffer.concat([Buffer.from('HSK1'), serverPubBuf, serverNonceBuf]);
  return crypto.verify(null, data, pinnedServerKey(), sigBuf);
}
function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}
function hmacSha256Hex(keyBuf, msgBuf) {
  return crypto.createHmac('sha256', keyBuf).update(msgBuf).digest('hex');
}
function getHWIDHashes() {
  const ifs = os.networkInterfaces();
  const hashes = [];
  for (const [name, arr] of Object.entries(ifs)) {
    for (const i of arr || []) {
      const mac = i.mac || '';
      if (mac && mac !== '00:00:00:00:00:00') {
        const h = sha256Hex(Buffer.from(`${name}:${mac}`));
        hashes.push(h);
      }
    }
  }
  // whitelist: each interface individually (just report them individually)
  return [...new Set(hashes)].slice(0, 64);
}
function readTokenFile() {
  try { return JSON.parse(fs.readFileSync(CONFIG.tokenStore, 'utf8')); } catch { return null; }
}
function writeTokenFile(obj) {
  try { fs.writeFileSync(CONFIG.tokenStore, JSON.stringify(obj, null, 2)); } catch {}
}
function decodeJwtUnsafe(token) {
  try {
    const [, payloadB64] = token.split('.');
    const json = Buffer.from(payloadB64, 'base64url').toString('utf8');
    return JSON.parse(json);
  } catch { return null; }
}

class AuthClient {
  constructor() {
    this.ws = null;

    // Handshake/channel state
    this.ecdh = null;
    this.sessionAesKey = null;

    // Identity/session
    this.sessionId = null;
    this.token = null;
    this.tokenExpMs = null;

    // Heartbeat/challenge state
    this.pendingServerQ = null;  // Buffer (random from server)
    this.pendingServerDeadlineMono = null; // bigint
    this.lastAckMono = null;
    this.tickTimer = null;

    // Stats
    this.stats = { ticksSent: 0, ticksRcvd: 0, challengesOk: 0, challengesFail: 0, acks: 0 };
  }

  exit(code = 1) {
    try { if (this.ws) this.ws.close(); } catch {}
    process.exit(code);
  }

  sendEncrypted(obj) {
    if (!this.sessionAesKey) return;
    const env = aesEncrypt(this.sessionAesKey, obj);
    const envelope = {
      token: this.token || null,
      iv: env.iv,
      ct: env.ct,
      tag: env.tag,
      ts: Date.now(), // server validates skew; this is not used for control logic
    };
    this.ws.send(JSON.stringify(envelope));
  }

  computeExpectedAnswerHex(qBuf) {
    // Must match server: hex(sha256(q || sessionId)).slice(0, 16)
    const h = crypto.createHash('sha256');
    h.update(qBuf);
    h.update(Buffer.from(this.sessionId));
    return h.digest('hex').slice(0, 16);
  }

  startTicks() {
    if (this.tickTimer) clearInterval(this.tickTimer);
    this.lastAckMono = monotonicNowMs();

    this.tickTimer = setInterval(() => {
      // Check max no-ack window
      const sinceAck = monotonicNowMs() - this.lastAckMono;
      if (sinceAck > CONFIG.maxNoAckMs) {
        console.error('No server acknowledgments for too long; exiting.');
        this.exit(1);
      }

      // If token is known to be expired and we didn't get a renew, try one last tick then exit soon.
      if (this.tokenExpMs && Date.now() > this.tokenExpMs) {
        console.error('Token expired and no renewal received; exiting.');
        this.exit(1);
      }

      const payload = { type: 'tick' };

      // If we have a pending server challenge, answer it now
      if (this.pendingServerQ) {
        const expect = this.computeExpectedAnswerHex(this.pendingServerQ);
        payload.ans = expect;
        // client will clear pending after it sees next ack (server validates on its side)
      }

      // Optionally send a lightweight client->server challenge (server currently ignores; benign)
      const cliQ = crypto.randomBytes(8);
      payload.cliQ = cliQ.toString('base64');

      this.sendEncrypted(payload);
      this.stats.ticksSent++;

      // Occasionally send stats snapshot for reconciliation
      if (this.stats.ticksSent % 10 === 0) {
        this.sendEncrypted({
          type: 'stats',
          snapshot: {
            sent: this.stats.ticksSent,
            rcvd: this.stats.ticksRcvd,
            ok: this.stats.challengesOk,
            fail: this.stats.challengesFail,
            acks: this.stats.acks,
          },
        });
      }
    }, CONFIG.tickIntervalMs);
  }

  connect() {
    this.ws = new WebSocket(CONFIG.url);

    this.ws.on('open', () => {
      // Wait for server hello
    });

    this.ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString());

        // First leg: server hello (unencrypted)
        if (msg.hello && msg.nonce && msg.sig) {
          const srvPub = Buffer.from(msg.hello, 'base64');
          const srvNonce = Buffer.from(msg.nonce, 'base64');
          const sig = Buffer.from(msg.sig, 'base64');

          // Verify signature with PINNED server public key (ignore any pk provided by server)
          const ok = verifyServerHandshakeSignature(srvPub, srvNonce, sig);
          if (!ok) {
            console.error('Pinned server key verification failed.');
            this.exit(1);
          }

          // Build ECDH and send our share
          this.ecdh = crypto.createECDH('prime256v1');
          this.ecdh.generateKeys();
          const shared = this.ecdh.computeSecret(srvPub);

          // Derive AES-256-GCM key via HKDF
          const salt = Buffer.from('SALT1');
          this.sessionAesKey = hkdf(shared, salt, Buffer.concat([Buffer.from('WS-AES'), srvNonce, Buffer.from([1])]), 32);

          // Respond with our ephemeral pub and a client nonce (server doesn't use the nonce; harmless)
          const clientNonce = crypto.randomBytes(16).toString('base64');
          this.ws.send(JSON.stringify({ clientPub: this.ecdh.getPublicKey().toString('base64'), nonce: clientNonce }));
          return;
        }

        // After ECDH, everything is encrypted envelope {token, iv, ct, tag, ts}
        if (!this.sessionAesKey) {
          console.error('Encrypted message before channel key ready.');
          this.exit(1);
        }

        // Optional sanity check on server timestamp skew (±5 minutes). Not used for client control.
        if (typeof msg.ts === 'number') {
          if (Math.abs(Date.now() - msg.ts) > 5 * 60_000) {
            console.error('Server timestamp skew too large.');
            this.exit(1);
          }
        }

        const inner = aesDecrypt(this.sessionAesKey, msg.iv, msg.ct, msg.tag);
        this.stats.ticksRcvd++;

        // Handle handshake auth nonce
        if (inner.type === 'auth_nonce') {
          const nBuf = Buffer.from(inner.n, 'base64');
          const hk = Buffer.from(sha256Hex(Buffer.from(CONFIG.rawKey, 'utf8')), 'hex');
          const h = hmacSha256Hex(hk, nBuf);

          // Send auth with keyId, H, and HWID list
          const hwids = getHWIDHashes();
          this.sendEncrypted({ type: 'auth', keyId: CONFIG.keyId, h, hwids });
          return;
        }

        // Handle welcome (session start + token)
        if (inner.type === 'welcome') {
          this.sessionId = inner.sessionId;
          this.token = inner.token;

          // Persist token (for bookkeeping; server will renew proactively as needed)
          const decoded = decodeJwtUnsafe(this.token);
          this.tokenExpMs = decoded ? decoded.exp * 1000 : null;
          writeTokenFile({ token: this.token, sessionId: this.sessionId, expMs: this.tokenExpMs });

          // Start heartbeat
          this.startTicks();
          return;
        }

        // Token renewal
        if (inner.type === 'token_renew' && inner.token) {
          this.token = inner.token;
          this.tokenExpMs = inner.exp || (decodeJwtUnsafe(this.token)?.exp * 1000) || null;
          writeTokenFile({ token: this.token, sessionId: this.sessionId, expMs: this.tokenExpMs });
          return;
        }

        // Tick acknowledgment + new challenge from server
        if (inner.type === 'tick_ack') {
          this.stats.acks++;
          this.lastAckMono = monotonicNowMs();

          // Server sets a new challenge 'q' to be answered on next tick
          if (inner.q) {
            this.pendingServerQ = Buffer.from(inner.q, 'base64');
            // Deadline is enforced by server; client uses max tick timeout buffer to sanity check
            this.pendingServerDeadlineMono = process.hrtime.bigint() + BigInt(CONFIG.tickTimeoutMs * 1_000_000);
          } else {
            // If server didn’t set a challenge this time, clear any stale one
            this.pendingServerQ = null;
            this.pendingServerDeadlineMono = null;
          }

          // Optional: quick client-side stats reconciliation (informational)
          if (inner.stats && typeof inner.stats === 'object') {
            // You could compare expectations here; we just keep our own tallies.
          }

          return;
        }

        // Unknown message types can be ignored safely
      } catch (e) {
        console.error('Client error:', e.message);
        this.exit(1);
      }
    });

    this.ws.on('close', (code, reason) => {
      console.error('WebSocket closed:', code, reason && reason.toString());
      this.exit(1);
    });

    this.ws.on('error', (err) => {
      console.error('WebSocket error:', err?.message || String(err));
      this.exit(1);
    });
  }
}

// Boot
(function main() {
  // Load previously stored token (not used for pre-auth; kept for visibility)
  const t = readTokenFile();
  if (t && t.token) {
    console.log('Found stored token, exp at:', t.expMs ? new Date(t.expMs).toISOString() : '(unknown)');
  }
  const client = new AuthClient();
  client.connect();
})();
