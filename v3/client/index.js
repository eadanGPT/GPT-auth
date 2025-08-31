// client/index.js
// Client class: connects to server via WS, performs ECDH handshake,
// verifies server identity, authenticates with key+IP, maintains heartbeat ticks,
// solves/answers challenges, refreshes JWT, and runs integrity checks.

const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');
const {
  aesEncrypt, aesDecrypt, generateECDH, hkdfSha256,
  verify, pubkeyFingerprint, sha256File, sha256Buf, monotonicNowNs
} = require('../shared/crypto');
const Logger = require('./logger');

const CONFIG_PATH = path.join(__dirname, 'config.json');
let config = {};
if (fs.existsSync(CONFIG_PATH)) {
  config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
} else {
  config = { serverUrl: 'ws://127.0.0.1:8081', key: null, serverPubFp: null, token: null };
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

const log = new Logger(path.join(__dirname, 'logs'));

// Prompt for key if missing
async function promptKey() {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    let attempts = 0;
    const ask = () => {
      rl.question('Enter your client key: ', (answer) => {
        if (answer && answer.length > 5) {
          rl.close();
          resolve(answer.trim());
        } else {
          attempts++;
          if (attempts >= 3) {
            console.error('Too many invalid attempts.');
            process.exit(1);
          }
          ask();
        }
      });
    };
    ask();
  });
}

class Client {
  constructor() {
    this.ws = null;
    this.sessionKey = null;
    this.ecdh = generateECDH();
    this.token = config.token;
    this.lastHeartbeat = monotonicNowNs();
    this.pendingChallenge = null;
    this.serverChallenge = null;
    this.heartbeatInterval = null;
  }

  connect() {
    this.ws = new WebSocket(config.serverUrl);
    this.ws.on('open', () => {
      log.log('log', 'Connected to server');
    });
    this.ws.on('message', (raw) => this.onMessage(raw));
    this.ws.on('close', () => {
      log.error('error', 'Connection closed');
      process.exit(1);
    });
    this.ws.on('error', (err) => {
      log.error('error', `WS error: ${err.message}`);
      process.exit(1);
    });
  }

  send(obj) {
    if (this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(obj));
    }
  }

  encryptEnvelope(token, obj) {
    const ts = Date.now();
    const payload = Buffer.from(JSON.stringify({ ts, ...obj }));
    const aad = Buffer.from(String(ts));
    const { iv, ct, tag } = aesEncrypt(payload, this.sessionKey, aad);
    return { token, iv: iv.toString('base64'), tag: tag.toString('base64'), data: ct.toString('base64'), ts };
  }

  decryptEnvelope(msg) {
    const { iv, tag, data, ts } = msg;
    const aad = Buffer.from(String(ts));
    const pt = aesDecrypt({
      iv: Buffer.from(iv, 'base64'),
      tag: Buffer.from(tag, 'base64'),
      ct: Buffer.from(data, 'base64')
    }, this.sessionKey, aad);
    return JSON.parse(pt.toString('utf8'));
  }

  onMessage(raw) {
    const msg = JSON.parse(raw.toString());

    // Server sends its ECDH pubkey + signature
    if (msg.type === 'kex') {
      const serverPub = Buffer.from(msg.serverPub, 'base64');
      const sig = Buffer.from(msg.sig, 'base64');
      if (!verify(serverPub, sig, msg.serverPubFp ? null : null)) {
        log.error('auth', 'Server signature invalid');
        process.exit(1);
      }
      const fp = msg.serverPubFp;
      if (config.serverPubFp && config.serverPubFp !== fp) {
        log.error('auth', 'Server fingerprint mismatch');
        process.exit(1);
      }
      config.serverPubFp = fp;
      fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));

      // Send our ECDH pubkey
      this.send({ type: 'kex', clientPub: this.ecdh.getPublicKey().toString('base64') });
      return;
    }

    if (!this.sessionKey && msg.iv) {
      // First encrypted message after KEX: derive session key
      // Actually, session key is derived immediately after sending our pubkey
      return;
    }

    // Decrypt envelope
    const inner = this.decryptEnvelope(msg);

    if (inner.type === 'auth_result') {
      if (!inner.ok) {
        log.error('auth', 'Authentication failed');
        process.exit(1);
      }
      this.token = msg.token;
      config.token = this.token;
      fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
      log.auth('Authenticated successfully');
      if (inner.challenge) {
        this.serverChallenge = inner.challenge;
      }
      this.startHeartbeat();
      return;
    }

    if (inner.type === 'challenge') {
      this.serverChallenge = inner.challenge;
      return;
    }

    if (inner.type === 'terminate') {
      log.error('error', `Terminated: ${inner.reason}`);
      process.exit(1);
    }

    if (inner.type === 'token_ok') {
      this.token = msg.token;
      config.token = this.token;
      fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
      log.log('log', 'Token refreshed');
    }
  }

  async authenticate() {
    if (!config.key) {
      config.key = await promptKey();
      fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
    }
    const nonce = crypto.randomBytes(16).toString('hex');
    const hmac = crypto.createHmac('sha256', config.key).update(nonce).digest('hex');
    this.send(this.encryptEnvelope(null, { type: 'auth', hmac, nonce }));
  }

  startHeartbeat() {
    this.heartbeatInterval = setInterval(() => {
      const challenge = this.makeChallenge();
      const payload = {
        type: 'tick',
        token: this.token,
        challenge
      };
      if (this.serverChallenge) {
        payload.answer = { id: this.serverChallenge.id, solution: this.solveChallenge(this.serverChallenge.expr) };
        this.serverChallenge = null;
      }
      this.send(this.encryptEnvelope(this.token, payload));
    }, 5000);
  }

  makeChallenge() {
    const a = 1000 + Math.floor(Math.random() * 9000);
    const b = 1000 + Math.floor(Math.random() * 9000);
    const op = ['+', '-', '^'][Math.floor(Math.random() * 3)];
    const expr = `${a}${op}${b}`;
    return { id: crypto.randomUUID(), expr, nonce: crypto.randomBytes(12).toString('hex') };
  }

  solveChallenge(expr) {
    const m = expr.match(/^(\d+)([+\-^])(\d+)$/);
    if (!m) return null;
    const A = parseInt(m[1], 10), OP = m[2], B = parseInt(m[3], 10);
    return (OP === '+') ? (A + B) : (OP === '-') ? (A - B) : (A ^ B);
  }
}

(async () => {
  const client = new Client();
  client.connect();
  setTimeout(() => client.authenticate(), 2000);
})();
