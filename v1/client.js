// client.js
// Node >=18
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const WebSocket = require('ws');

const CONFIG = {
  url: 'ws://127.0.0.1:8081',
  keyId: 'example-key-id',
  rawKey: 'super-secret-client-key', // DO NOT commit in real projects
  pinnedServerEd25519PubPem: `-----BEGIN PUBLIC KEY-----
...paste from server startup...
-----END PUBLIC KEY-----`,
  tickIntervalMs: 30_000,
  tickTimeoutMs: 60_000,
  tokenStore: path.join(__dirname, 'client-token.json'),
};

function monotonicMs() {
  return Number(process.hrtime.bigint() / 1_000_000n);
}

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
function getHWIDHashes() {
  const ifs = os.networkInterfaces();
  const hashes = [];
  for (const [name, arr] of Object.entries(ifs)) {
    for (const i of arr || []) {
      // Use MAC if present; hash each individually
      const mac = i.mac || '';
      if (mac && mac !== '00:00:00:00:00:00') {
        const h = crypto.createHash('sha256').update(name + ':' + mac).digest('hex');
        hashes.push(h);
      }
    }
  }
  return [...new Set(hashes)].slice(0, 64);
}
function readToken() {
  try { return JSON.parse(fs.readFileSync(CONFIG.tokenStore, 'utf8')); } catch { return null; }
}
function writeToken(obj) {
  fs.writeFileSync(CONFIG.tokenStore, JSON.stringify(obj, null, 2));
}

function exit(code = 1) {
  process.exit(code);
}

class Client {
  constructor() {
    this.ws = null;
    this.aesKey = null;
    this.sessionId = null;
    this.token = null;
    this.pendingServerQ = null;
    this.stats = { ticksSent: 0, ticksRcvd: 0, ok: 0, fail: 0 };
    this.tickTimer = null;
    this.monoStart = process.hr
