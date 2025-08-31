'use strict';
const crypto = require('crypto');

const AES_ALGO = 'aes-256-gcm';

function genRandom(bytes = 32) {
  return crypto.randomBytes(bytes);
}

function aesGcmEncrypt(key, plaintext, aad = Buffer.alloc(0)) {
  const iv = genRandom(12);
  const cipher = crypto.createCipheriv(AES_ALGO, key, iv, { authTagLength: 16 });
  if (aad.length) cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, enc, tag };
}

function aesGcmDecrypt(key, iv, enc, tag, aad = Buffer.alloc(0)) {
  const decipher = crypto.createDecipheriv(AES_ALGO, key, iv, { authTagLength: 16 });
  if (aad.length) decipher.setAAD(aad, { plaintextLength: enc.length });
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec;
}

function hash256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

function nowTicks() {
  return process.hrtime.bigint(); // ns
}

// Ed25519
function signEd25519(privateKeyPem, msg) {
  const key = crypto.createPrivateKey(privateKeyPem);
  return crypto.sign(null, msg, key);
}
function verifyEd25519(publicKeyPem, msg, sig) {
  const key = crypto.createPublicKey(publicKeyPem);
  return crypto.verify(null, msg, key, sig);
}

// X25519 ECDH
function ecdhX25519(privateKeyPem, peerPublicKeyPem) {
  const priv = crypto.createPrivateKey(privateKeyPem);
  const pub = crypto.createPublicKey(peerPublicKeyPem);
  const shared = crypto.diffieHellman({ privateKey: priv, publicKey: pub });
  return hash256(shared); // KDF
}

// In‑memory wrapping using a runtime master key
const runtimeMaster = (() => {
  // Stir with hrtime and process fields
  const seed = Buffer.concat([
    crypto.randomBytes(32),
    Buffer.from(String(process.pid)),
    Buffer.from(String(process.hrtime.bigint()))
  ]);
  return hash256(seed);
})();

function wrapSecret(plainBuf) {
  const { iv, enc, tag } = aesGcmEncrypt(runtimeMaster, plainBuf);
  plainBuf.fill(0);
  return Buffer.concat([iv, tag, enc]);
}
function unwrapSecret(wrapped) {
  const iv = wrapped.subarray(0, 12);
  const tag = wrapped.subarray(12, 28);
  const enc = wrapped.subarray(28);
  return aesGcmDecrypt(runtimeMaster, iv, enc, tag);
}

function serialize(obj) {
  return Buffer.from(JSON.stringify(obj));
}
function deserialize(buf) {
  return JSON.parse(buf.toString('utf8'));
}

module.exports = {
  genRandom,
  aesGcmEncrypt,
  aesGcmDecrypt,
  hash256,
  nowTicks,
  signEd25519,
  verifyEd25519,
  ecdhX25519,
  wrapSecret,
  unwrapSecret,
  serialize,
  deserialize
};
