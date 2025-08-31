// crypto-helpers.js
const crypto = require('crypto');

function nowNs() {
  return process.hrtime.bigint();
}

// AES-256-GCM (returns Buffer objects)
function aeadEncrypt(key, plaintext, aad = Buffer.alloc(0)) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  if (aad.length) cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ct, tag };
}

function aeadDecrypt(key, iv, ct, tag, aad = Buffer.alloc(0)) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  if (aad.length) decipher.setAAD(aad, { plaintextLength: ct.length });
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt;
}

// Seal in-memory secrets with a process master key
const MASTER_KEY = crypto.randomBytes(32); // runtime-only

function seal(plaintextBuf, context = Buffer.alloc(0)) {
  return aeadEncrypt(MASTER_KEY, plaintextBuf, context);
}
function unseal(sealed, context = Buffer.alloc(0)) {
  return aeadDecrypt(MASTER_KEY, sealed.iv, sealed.ct, sealed.tag, context);
}

// Ed25519 signing
function genEd25519() {
  return crypto.generateKeyPairSync('ed25519');
}
function edSign(privateKey, data) {
  return crypto.sign(null, data, privateKey);
}
function edVerify(publicKey, data, sig) {
  return crypto.verify(null, data, publicKey, sig);
}

// X25519 ECDH
function genX25519() {
  return crypto.generateKeyPairSync('x25519');
}
function x25519Shared(privateKey, publicKey) {
  return crypto.diffieHellman({ privateKey, publicKey });
}

// HKDF
function hkdf(ikm, salt = Buffer.alloc(0), info = Buffer.alloc(0), len = 32) {
  if (crypto.hkdfSync) return crypto.hkdfSync('sha256', ikm, salt, info, len);
  // fallback
  const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
  let t = Buffer.alloc(0), okm = Buffer.alloc(0), i = 0;
  while (okm.length < len) {
    i++;
    t = crypto.createHmac('sha256', prk).update(Buffer.concat([t, info, Buffer.from([i])])).digest();
    okm = Buffer.concat([okm, t]);
  }
  return okm.slice(0, len);
}

// HMAC-SHA256
function hmacSha256(keyBuf, dataBuf) {
  return crypto.createHmac('sha256', keyBuf).update(dataBuf).digest();
}

// RSA-OAEP (for log encryption)
function genRsa2048() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
}
function rsaEncrypt(pubPem, data) {
  return crypto.publicEncrypt({ key: pubPem, oaepHash: 'sha256' }, data);
}
function rsaDecrypt(privPem, data) {
  return crypto.privateDecrypt({ key: privPem, oaepHash: 'sha256' }, data);
}

// Hash helper
function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

module.exports = {
  nowNs,
  aeadEncrypt, aeadDecrypt,
  seal, unseal,
  genEd25519, edSign, edVerify,
  genX25519, x25519Shared, hkdf,
  hmacSha256, genRsa2048, rsaEncrypt, rsaDecrypt, sha256
};
