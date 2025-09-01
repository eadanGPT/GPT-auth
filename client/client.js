
// client/client.js (preview only piece will be shown in chat; full file included in zip)
import fs from 'fs';
import os from 'os';
import crypto from 'crypto';
import { WebSocket } from 'ws';
import express from 'express';

const cfgPath = new URL('./config.json', import.meta.url).pathname;
let config = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
const PROCESS_ENTROPY = crypto.randomBytes(32);

function processEntropy() { return crypto.createHash('sha256').update(PROCESS_ENTROPY).digest(); }
function scryptKey(password, salt, size=32) { return crypto.scryptSync(password, salt, size, { N: 1<<15, r: 8, p: 1 }); }
function aesGcmEncrypt(key, plaintext, aad=Buffer.alloc(0)) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad?.length) cipher.setAAD(aad);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}
function aesGcmDecrypt(key, b64, aad=Buffer.alloc(0)) {
  const buf = Buffer.from(b64, 'base64');
  const iv = buf.subarray(0,12);
  const tag = buf.subarray(12,28);
  const enc = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  if (aad?.length) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec;
}

// === Runtime obfuscation & string protection ===
function createEncryptedExpression(str) {
  function obfuscateText(txt) {
    function obNum(n) {
      const p = Math.max(1, Math.floor(Math.log2(Math.max(2, n))));
      const variants = [
        `(${n>>1}<<1|${n&1})`,
        `(~${~n})`,
        `((1<<${Math.floor(Math.log2(n))})+${n-(1<<Math.log2(n))})`,
        `(${n}^0)`,
        `(((${n>>1}<<1)|(${n&1})) + (~${~n}))`,
        `((~${~n}) ^ (${n}^0))`,
        `(((1<<${p}) + ${n - (1 << p)}) + ((1<<${p}) + ${n - (1 << p)})) >> 1)`,
        `(((${n}^0) + (${n>>1}<<1|${n&1})) - ${n}) + ${n}`
      ];
      return variants[Math.floor(Math.random() * variants.length)];
    }
    const codes = Array.from(txt).map((ch) => obNum(ch.charCodeAt(0)));
    const body = `return ((str.at(0).charCodeAt(0) ** 2 + 1) % 2) === 1 ? (0>>1) : String.fromCharCode.apply(null,[${codes.join(',')}]);`;
    return new Function('str', body).bind(null, str);
  }
  return obfuscateText(str);
}

let clientKey = config.licenseKey || '';
let clientKeyHash = clientKey ? crypto.createHash('sha256').update(clientKey).digest('hex') :
  crypto.createHash('sha256').update(crypto.randomBytes(16)).digest('hex');

const _obKey = crypto.createHash('sha256').update(clientKeyHash + crypto.randomBytes(32)).digest();
function protectString(s){ const b = Buffer.from(String(s),'utf8'); const o = Buffer.alloc(b.length); for(let i=0;i<b.length;i++) o[i]=b[i]^_obKey[i%_obKey.length]; return o; }
function revealString(b){ const o = Buffer.alloc(b.length); for(let i=0;i<b.length;i++) o[i]=b[i]^_obKey[i%_obKey.length]; const s=o.toString('utf8'); o.fill(0); return s; }

function permanentHWID() {
  const cpu = os.cpus().map(c=>c.model).join('|');
  const mem = os.totalmem().toString();
  const host = os.hostname();
  const platform = os.platform() + '-' + os.release();
  const nets = Object.values(os.networkInterfaces()).flat().filter(Boolean).map(n=>n.mac).join(',');
  return crypto.createHash('sha256').update([cpu,mem,host,platform,nets].join('|')).digest('hex');
}
function temporaryHWID() {
  const ips = Object.values(os.networkInterfaces()).flat().filter(Boolean).map(n=>n.address).join(',');
  const boot = Math.floor((Date.now() - os.uptime()*1000) / (24*60*60*1000));
  return crypto.createHash('sha256').update([ips, boot].join('|')).digest('hex');
}

let runtimeKey = scryptKey(clientKeyHash, processEntropy(), 32);
function wrapToken(token) { const enc = aesGcmEncrypt(runtimeKey, Buffer.from(token,'utf8')); return createEncryptedExpression(enc); }

let ws; let sessionKey=null; let jwtToken=null; let reconAttempts=0;

function startLocalFrontend(){/* ...full UI in archive... */}
function attemptAuthOnce(){/* ...implemented in archive... */}
function connect(){/* ...implemented in archive... */}
connect();
