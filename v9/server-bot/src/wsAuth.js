
import WebSocket from 'ws';
import crypto from 'node:crypto';
import { aesGcmDecrypt, aesGcmEncrypt, deriveClientKeyHash } from './crypto.js';
import { getPermanentHWID, getTemporaryHWID } from './hwid.js';
import { config } from './config.js';

export async function connectAndAuth() {
  const licenseKey = config.licenseKey;
  const clientKeyHash = deriveClientKeyHash(licenseKey);

  let ws;
  let serverPubKey = null;
  let sessionKey = crypto.randomBytes(32);
  let sessionIv = crypto.randomBytes(12);
  let jwtToken = null;
  let lastChallenge = null;

  await new Promise((resolve,reject)=>{
    ws = new WebSocket(config.serverURL);
    ws.on('message', (raw)=>{
      const msg = JSON.parse(raw.toString());
      if (msg.type === 'hello') {
        serverPubKey = msg.pubkey;
        const info = { key_hash: clientKeyHash, hwid_perm: getPermanentHWID(), temp_hwid: getTemporaryHWID() };
        const buf = Buffer.concat([sessionKey, sessionIv]);
        const ek = crypto.publicEncrypt({ key: serverPubKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, buf).toString('base64');
        ws.send(JSON.stringify({ type:'handshake', ek, info }));
      } else if (msg.type === 'handshake_ok') {
        const data = Buffer.from(msg.data, 'base64');
        const dec = JSON.parse(aesGcmDecrypt(sessionKey, sessionIv, data).toString('utf8'));
        if (!dec.ok) { ws.close(); return reject(new Error('auth_failed')); }
        jwtToken = dec.token;
        resolve();
      } else if (msg.type === 'hb') {
        const dec = JSON.parse(aesGcmDecrypt(sessionKey, sessionIv, Buffer.from(msg.data,'base64')).toString('utf8'));
        lastChallenge = dec.ch;
      } else if (msg.type === 'packet_ok') {
        const dec = JSON.parse(aesGcmDecrypt(sessionKey, sessionIv, Buffer.from(msg.data,'base64')).toString('utf8'));
        lastChallenge = dec.next;
      }
    });
    ws.on('error', reject);
  });

  function solveChallenge(ch) {
    function factor(n){ const res=[]; for(let i=2;i*i<=n;i++){ while(n%i===0){res.push(i); n=n/i;} } if(n>1) res.push(n); return res; }
    // eslint-disable-next-line no-new-func
    const fn = new Function('factor', `return (${ch.expr});`);
    const v = fn(factor);
    return Array.isArray(v) ? v.reduce((a,b)=>a+b,0) : (typeof v==='boolean' ? (v?1:0) : Math.floor(v));
  }

  setInterval(()=>{
    if (!lastChallenge) return;
    const answer = solveChallenge(lastChallenge);
    const payload = Buffer.from(JSON.stringify({ token: jwtToken, kind:'heartbeat', answer }));
    const out = aesGcmEncrypt(sessionKey, sessionIv, payload);
    try { ws.send(JSON.stringify({ type:'packet', data: out.toString('base64') })); } catch {}
  }, 2*60*1000);

  return { ws };
}
