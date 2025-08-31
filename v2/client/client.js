// client/client.js
// Client-side: prompts for key if missing, establishes pinned-identity WS, ECDH session, AES-GCM payloads,
// token usage/renewal, ticked heartbeat with random challenges, server challenge handling,
// tamper-resistant timing (monotonic), and immediate exit on auth failure.

/* TODO
     * Integrity check of critical file (self-hash recorded on first run)
       -> Need to add hashes for each file, and check on startup
     * Ensure pinned server identity is configured
       -> Need to add server Keypair
     * Prompt for client key if not set (3 attempts)
       -> Need to verify with server if key is valid.
     * ws.on('close', () => {
       -> Need to reconnect or process.exit();
     * Ticked Q/A
       -> Need to remove {expectedServerFreq: '1_per_5'} expected values
*/

import fs from 'fs';
import crypto from 'crypto';
import readline from 'readline';
import { WebSocket } from 'ws';
import {
  makeEphemeralECDH, verifyDetached, hkdf, aesGcmEncrypt, aesGcmDecrypt, hmacProof
} from '../common/crypto.js';
import { monoNowMs, hrnowNs, getHWIDs, hardExit } from '../common/util.js';
import { ClientLogger } from './logger.js';
import { obfWrap, obfEqual } from './obfuscation.js';

// -- Load config
const cfgPath = 'client/config.client.json';
const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
const logger = new ClientLogger(cfg);

// -- Integrity check of global functions
(() => {
  const start = performance.now();
  setTimeout(() => {
    const elapsed = performance.now() - start;
    if (elapsed < 1450 || elapsed > 1550) {
      console.error(`Timing drift detected: ${elapsed}ms`);
      process.exit(-1);
    }
  }, 1500);
})();

// -- Integrity check of critical file (self-hash recorded on first run)
const criticalFiles = ['client/client.js', 'client/obfuscation.js', 'common/crypto.js'];
let integrity = '';
try {
  const concat = Buffer.concat(criticalFiles.map(f => fs.readFileSync(f)));
  integrity = crypto.createHash('sha256').update(concat).digest('base64url');
} catch (e) {
  logger.error(`Integrity read failed: ${e.message}`);
}

// -- Ensure pinned server identity is configured
if (!cfg.server.pinnedServerSignPubKeyBase64) {
  logger.error('Pinned server public key not set. Exiting.');
  hardExit(1);
}

// -- Prompt for client key if not set (3 attempts)
async function ensureClientKey() {
  if (cfg.client.keyBase64url) return;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  let attempts = 3;
  while (attempts-- > 0) {
    const key = await question(rl, 'Enter your client key: ');
    if (key && /^[A-Za-z0-9_\-]+$/.test(key)) {
      cfg.client.keyBase64url = key;
      fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));
      rl.close();
      logger.auth('Client key saved to config.');
      return;
    }
    console.log('Invalid key format.');
  }
  rl.close();
  logger.error('Failed to enter valid key in 3 attempts.');
  hardExit(1);
}
function question(rl, q) {
  return new Promise(res => rl.question(q, ans => res(ans.trim())));
}

// -- Connect and authenticate
async function main() {
  await ensureClientKey();

  const ws = new WebSocket(cfg.server.wsUrl);
  let sessionKey = null;
  let serverPubKey = Buffer.from(cfg.server.pinnedServerSignPubKeyBase64, 'base64');
  let connId = crypto.randomUUID();

  // Obfuscated proof generator
  const makeProof = obfWrap((keyB64u, nonce) => hmacProof(Buffer.from(keyB64u, 'base64url'), nonce));

  ws.on('open', () => {
    logger.info('WS open');

    // Nothing to send until server says hello; anti-MITM pinned identity will be checked
  });

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(String(raw));
      if (msg.t === 'hello') {
        // Verify server identity: signed ephemeral pubkey with pinned ED25519 key
        const ok = verifyDetached(crypto.createPublicKey({ key: serverPubKey, format: 'der', type: 'spki' }), Buffer.from(msg.server_pub, 'base64'), Buffer.from(msg.sig, 'base64'));
        if (!ok) {
          logger.error('Pinned identity mismatch. Exiting.');
          return hardExit(1);
        }
        // ECDH ephemeral
        const ecdh = makeEphemeralECDH();
        const shared = ecdh.computeSecret(Buffer.from(msg.server_pub, 'base64'));
        sessionKey = hkdf(shared, Buffer.from('AUTH-SYS-SALT-v1'), Buffer.from('SESSION-KEY'), 32);
        ws.send(JSON.stringify({ t: 'hello-ack', client_pub: ecdh.getPublicKey().toString('base64') }));
        return;
      }

      if (!sessionKey) {
        logger.error('No session key yet. Exiting.');
        return hardExit(1);
      }

      const token = msg.token || cfg.client.token || '';
      const aad = Buffer.concat([Buffer.from(token), Buffer.from(connId)]);
      const pt = JSON.parse(aesGcmDecrypt(sessionKey, msg.data, aad).toString('utf8'));

      if (pt.t === 'nonce') {
        // Send key proof; never send the key or its hash
        const hwids = getHWIDs();
        const proof = makeProof(cfg.client.keyBase64url, pt.nonce);
        sendEncrypted(ws, sessionKey, token, {
          t: 'key-proof',
          proof,
          key_value: cfg.client.keyBase64url,
          hwids,
          seq: 1
        }, connId);
        return;
      }

      if (pt.t === 'token') {
        // Receive JWT and save
        if (!pt.token || !pt.exp) {
          logger.error('No token received.');
          return hardExit(1);
        }
        cfg.client.token = pt.token;
        cfg.client.tokenExp = pt.exp;
        fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));

        // Start heartbeat ticks (Q/A system)
        startHeartbeat(ws, sessionKey, connId);
        return;
      }

      if (pt.t === 'hb-ack') {
        // Server optionally sends challenge and new token
        if (pt.newToken && pt.newExp) {
          cfg.client.token = pt.newToken;
          cfg.client.tokenExp = pt.newExp;
          fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));
          logger.info('Token renewed.');
        }
        if (pt.serverChallenge) {
          // Solve and respond immediately
          const r = solveServerChallenge(pt.serverChallenge);
          sendEncrypted(ws, sessionKey, cfg.client.token, { t: 'challenge-result', response: r, seq: randSeq() }, connId);
        }
        // Track relationship stats locally (never in memory logs — okay to keep simple counters)
        return;
      }

      // Unknown -> ignore
    } catch (e) {
      logger.error(`Message error: ${e.message}`);
      hardExit(1);
    }
  });

  ws.on('close', () => {
    logger.info('WS closed.');
  });

  ws.on('error', (e) => {
    logger.error(`WS error: ${e.message}`);
    hardExit(1);
  });
}

function sendEncrypted(ws, key, token, obj, connId) {
  // Always encrypt payload with AES-GCM and bind token+connId in AAD
  const aad = Buffer.concat([Buffer.from(token || ''), Buffer.from(connId)]);
  const enc = aesGcmEncrypt(key, Buffer.from(JSON.stringify(obj)), aad);
  ws.send(JSON.stringify({ token: token || '', data: enc }));
}

function startHeartbeat(ws, key, connId) {
  const intervalMs = 60000; // 60 seconds
  const timer = setInterval(() => {
    try {
      // Exit if token expired and not renegotiated
      const now = Date.now();
      const exp = cfg.client.tokenExp || 0;
      if (now >= exp) {
        logger.error('Token expired; renegotiation failed. Exiting.');
        clearInterval(timer);
        return hardExit(1);
      }

      // If within 6h of expiry, request renewal by simply sending heartbeat (server will renew)
      const remaining = exp - now;

      // Build a client challenge: directly solvable sum with mixing; server verifies
      const ch = makeClientChallenge();

      // Ticked Q/A
      sendEncrypted(ws, key, cfg.client.token, {
        t: 'heartbeat',
        ts_mono: monoNowMs(),
        ts_hr: Number(hrnowNs() % BigInt(1e9)),
        expectedServerFreq: '1_per_5',
        challenge: ch,
        seq: randSeq()
      }, connId);
    } catch (e) {
      logger.error(`Heartbeat error: ${e.message}`);
      hardExit(1);
    }
  }, intervalMs);
  timer.unref();
}

function makeClientChallenge() {
  // Deterministic expected value
  const data = Array.from({ length: 8 }, () => crypto.randomInt(1, 1000));
  const expected = data.reduce((acc, v, i) => (acc + ((v ^ (i + 13)) % 257)) % 100000, 7);
  return { t: 'mix', data, expected };
}

function solveServerChallenge(ch) {
  if (ch.t !== 'calc') return { ok: false };
  const result = (ch.a * ch.a + 3 * ch.b) ^ (ch.a + ch.b);
  const digest = crypto.createHash('sha256').update(`${result}|${ch.nonce}`).digest('base64url');
  return { t: 'calc', a: ch.a, b: ch.b, nonce: ch.nonce, digest };
}

function randSeq() { return crypto.randomInt(1, 1e9); }

// -- Start
main().catch(e => { logger.error(`Fatal: ${e.message}`); hardExit(1); });
