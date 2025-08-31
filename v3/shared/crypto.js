// shared/crypto.js
// All cryptographic primitives centralized to avoid misuse.
// Node.js >= 18 recommended.

const crypto = require('crypto');

// --- AES-GCM per-payload encryption ---

function aesEncrypt(plaintextBuf, key32, aadBuf = Buffer.alloc(0)) {
  // Generate a fresh IV per message (12 bytes recommended for AES-GCM)
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key32, iv, { authTagLength: 16 });
  if (aadBuf.length) cipher.setAAD(aadBuf, { plaintextLength: plaintextBuf.length });
  const ct = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ct, tag };
}

function aesDecrypt({ iv, ct, tag }, key32, aadBuf = Buffer.alloc(0)) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key32, iv, { authTagLength: 16 });
  if (aadBuf.length) decipher.setAAD(aadBuf, { plaintextLength: ct.length });
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt;
}

// --- ECDH session key (X25519) ---

function generateECDH() {
  const ecdh = crypto.createECDH('x25519');
  ecdh.generateKeys();
  return ecdh; // expose getPublicKey(), computeSecret(peerPub)
}

// HKDF for deriving AES key from ECDH shared secret
function hkdfSha256(ikm, salt = crypto.randomBytes(16), info = Buffer.from('session')) {
  return new Promise((resolve, reject) => {
    crypto.hkdf('sha256', salt, ikm, info, 32, (err, key) => {
      if (err) reject(err);
      else resolve({ key, salt });
    });
  });
}

// --- RSA (server long-term) ---

function sign(dataBuf, privatePem) {
  const s = crypto.createSign('sha256');
  s.update(dataBuf);
  s.end();
  return s.sign(privatePem);
}

function verify(dataBuf, signatureBuf, publicPem) {
  const v = crypto.createVerify('sha256');
  v.update(dataBuf);
  v.end();
  return v.verify(publicPem, signatureBuf);
}

// Fingerprint helper for pinning (SHA-256 of public key DER)
function pubkeyFingerprint(publicPem) {
  const der = crypto.createPublicKey(publicPem).export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

// --- Integrity helpers ---

function sha256File(fs, path) {
  const h = crypto.createHash('sha256');
  const s = fs.createReadStream(path);
  return new Promise((resolve, reject) => {
    s.on('data', chunk => h.update(chunk));
    s.on('end', () => resolve(h.digest('hex')));
    s.on('error', reject);
  });
}

function sha256Buf(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// --- Anti-tamper time guards ---

function monotonicNowNs() {
  return process.hrtime.bigint(); // monotonic clock immune to Date tampering
}

module.exports = {
  aesEncrypt,
  aesDecrypt,
  generateECDH,
  hkdfSha256,
  sign,
  verify,
  pubkeyFingerprint,
  sha256File,
  sha256Buf,
  monotonicNowNs
};
