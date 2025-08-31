// common/crypto.js
// Cryptography helpers: ECDH (X25519), ED25519 signing, HKDF, AES-GCM, HMAC proofs, and integrity utilities.

import crypto from 'crypto';

// -- Constants
export const CURVE = 'x25519'; // ECDH curve for key agreement
export const SIGN_ALGO = 'ed25519'; // For server identity and pinning
export const AES_ALGO = 'aes-256-gcm'; // Symmetric payload encryption
export const HKDF_HASH = 'sha256'; // HKDF hash for key derivation
export const AAD_LABEL = Buffer.from('AUTH-SYS-AAD-v1'); // AAD label for AEAD
export const TOKEN_AAD = Buffer.from('JWT-BINDING-v1'); // Bind token into AEAD

// -- Key derivation (HKDF)
export function hkdf(ikm, salt, info, length = 32) {
  // HKDF-SHA256 to derive session keys
  return crypto.hkdfSync(HKDF_HASH, ikm, salt, info, length);
}

// -- ECDH ephemeral keypair
export function makeEphemeralECDH() {
  // Create ephemeral ECDH keypair for a session
  const ecdh = crypto.createECDH(CURVE);
  ecdh.generateKeys();
  return ecdh;
}

// -- ED25519 key generation (server persistent identity)
export function makeSigningKeyPair() {
  // Create server signing key pair to pin identity
  return crypto.generateKeyPairSync(SIGN_ALGO);
}

// -- ED25519 sign/verify for server identity and pinned key
export function signDetached(privateKey, message) {
  // Sign message using ED25519
  return crypto.sign(null, message, privateKey);
}
export function verifyDetached(publicKey, message, sig) {
  // Verify signature using ED25519
  return crypto.verify(null, message, publicKey, sig);
}

// -- AES-GCM encrypt/decrypt
export function aesGcmEncrypt(key, plaintext, aad) {
  // Symmetric AEAD encryption with random IV and AAD bound metadata
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(AES_ALGO, key, iv, { authTagLength: 16 });
  if (aad) cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('base64'), ct: ct.toString('base64'), tag: tag.toString('base64') };
}
export function aesGcmDecrypt(key, { iv, ct, tag }, aad) {
  // AEAD decryption with tag verification; throws on failure
  const ivBuf = Buffer.from(iv, 'base64');
  const ctBuf = Buffer.from(ct, 'base64');
  const tagBuf = Buffer.from(tag, 'base64');
  const decipher = crypto.createDecipheriv(AES_ALGO, key, ivBuf, { authTagLength: 16 });
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(tagBuf);
  const pt = Buffer.concat([decipher.update(ctBuf), decipher.final()]);
  return pt;
}

// -- HMAC challenge/response without sending the key
export function hmacProof(keyBytes, nonce, context = 'KEY-PROOF-v1') {
  // Computes an HMAC to prove knowledge of the key using a server nonce
  return crypto.createHmac('sha256', keyBytes).update(context).update(nonce).digest('base64url');
}

// -- Integrity check for critical code (self-hash)
export function digestCode(sourceBuf) {
  // SHA-256 hash of code to detect tampering (basic integrity)
  return crypto.createHash('sha256').update(sourceBuf).digest('base64url');
}

// -- Authenticated time token (server -> client)
export function signServerTime(privateKey, nowMs) {
  // Server signs time so client can cross-verify its monotonic clock drift
  const msg = Buffer.from(`TIME:${nowMs}`);
  const sig = signDetached(privateKey, msg);
  return { nowMs, sig: sig.toString('base64') };
}
export function verifyServerTime(publicKey, payload) {
  // Client verifies server-signed time and computes drift
  const msg = Buffer.from(`TIME:${payload.nowMs}`);
  const ok = verifyDetached(publicKey, msg, Buffer.from(payload.sig, 'base64'));
  return ok;
}

// -- Utility: secure random int in range
export function randomInt(maxExclusive) {
  // Uniform random integer in [0, maxExclusive)
  return crypto.randomInt(0, maxExclusive);
}
