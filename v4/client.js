// client.js
const WebSocket = require('ws');
const os = require('os');
const crypto = require('crypto');
const {
  nowNs, genX25519, x25519Shared, hkdf,
  aeadEncrypt, aeadDecrypt, hmacSha256,
  rsaEncrypt, sha256
} = require('./crypto-helpers');
const fs = require('fs');

class LiveAuthClient {
  constructor(config) {
    this.config = config; // { keyHex, serverUrl }
    this.keyBuf = Buffer.from(config.keyHex, 'hex');
    this.keyId = hmacSha256(this.keyBuf, Buffer.from('id')).toString('hex');
    this.hwids = Object.values(os.networkInterfaces())
      .flat().filter(Boolean).map(i => i.mac);
    this.sessionKey = null;
    this.ws = null;
    this.logs = [];
  }

  connect() {
    this.ws = new WebSocket(this.config.serverUrl);
    this.ws.on('message', (data) => this.onMessage(data));
  }

  sendEncrypted(obj) {
    const aad = Buffer.from('ws-msg');
    const payload = Buffer.from(JSON.stringify(obj));
    const { iv, ct, tag } = aeadEncrypt(this.sessionKey, payload, aad);
    this.ws.send(JSON.stringify({ iv: iv.toString('base64'), ct: ct.toString('base64'), tag: tag.toString('base64') }));
  }

  onMessage(data) {
    const msg = JSON.parse(data.toString());
    if (msg.type === 'hello') {
      // Verify server signature on ECDH pub
      const serverPubKey = crypto.createPublicKey(msg.serverSignPub);
      const sigOk = crypto.verify(null, Buffer.from(msg.ecdhPub), serverPubKey, Buffer.from(msg.ecdhSig, 'base64'));
      if (!sigOk) { console.error('Bad server signature'); process.exit(1); }
      // ECDH
      const ecdh = genX25519();
      const shared = x25519Shared(ecdh.privateKey, crypto.createPublicKey(msg.ecdhPub));
      this.sessionKey = hkdf(shared, Buffer.from('salt'), Buffer.from('ws-session'), 32);
      this.ws.send(JSON.stringify({ type: 'client_ecdh', ecdhPub: ecdh.publicKey.export({ type: 'spki', format: 'pem' }) }));
      this.serverLogPub = msg.logPub;
      return;
    }
    if (!this.sessionKey) return;
    const dec = (() => {
      const { iv, ct, tag } = { iv: Buffer.from(msg.iv, 'base64'), ct: Buffer.from(msg.ct, 'base64'), tag: Buffer.from(msg.tag, 'base64') };
      return JSON.parse(aeadDecrypt(this.sessionKey, iv, ct, tag, Buffer.from('ws-msg')).toString('utf8'));
    })();

    if (dec.type === 'challenge') {
      const hmac = hmacSha256(this.keyBuf, Buffer.from(dec.nonce, 'base64')).toString('hex');
      this.sendEncrypted({ type: 'auth', keyId: this.keyId, hwids: this.hwids, hmac });
      return;
    }
    if (dec.type === 'auth_ok') {
      console.log('Authenticated, JWT:', dec.jwt);
      return;
    }
    if (dec.type === 'hb_challenge') {
      const ans = dec.coeffs.reduce((s,c,i)=> s + c*Math.pow(dec.x, dec.coeffs.length-1-i), 0);
      // Also send our own challenge
      const myCh = { coeffs: [1,2,3], x: 5 };
      this.sendEncrypted({ type: 'hb_response', value: ans, clientChallenge: myCh });
      return;
    }
    if (dec.type === 'hb_answer') {
      // ignore for now
      return;
    }
    if (dec.type === 'code_update') {
      console.log('Updating function', dec.fn);
      eval(dec.code);
      return;
    }
  }

  sendLog(str) {
    const enc = rsaEncrypt(this.serverLogPub, Buffer.from(str));
    this.sendEncrypted({ type: 'log_upload', encLogBase64: enc.toString('base64') });
  }
}

const client = new LiveAuthClient({
  keyHex: fs.readFileSync('./client.key', 'utf8').trim(),
  serverUrl: 'ws://localhost:8080'
});
client.connect();
