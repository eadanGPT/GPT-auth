
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { env, keypair } from './config.js';

export function rsaDecryptOAEP(base64) {
  const buf = Buffer.from(base64, 'base64');
  const dec = crypto.privateDecrypt({ key: keypair.privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, buf);
  return dec;
}

export function rsaPublicKeyPem() { return keypair.publicKey; }

export function aesGcmEncrypt(key, iv, plaintext, aad = Buffer.alloc(0)) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad.length) cipher.setAAD(aad);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([enc, tag]);
}
export function aesGcmDecrypt(key, iv, ciphertextPlusTag, aad = Buffer.alloc(0)) {
  const tag = ciphertextPlusTag.slice(-16);
  const ciphertext = ciphertextPlusTag.slice(0, -16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  if (aad.length) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return dec;
}
export function deriveKeyScrypt(password, salt, len = 32) {
  return crypto.scryptSync(password, salt, len);
}

export function signJWT(payload, ttlDays = env.JWT_TTL_DAYS) {
  return jwt.sign(payload, keypair.privateKey, { algorithm: 'RS256', expiresIn: `${ttlDays}d` });
}
export function verifyJWT(token) {
  return jwt.verify(token, keypair.publicKey, { algorithms: ['RS256'] });
}
export function tokenFingerprint(token) {
  const [header, payload, signature] = token.split('.');
  const sigHash = crypto.createHash('sha256').update(signature).digest('hex');
  const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  const sub = data.sub || '';
  const exp = data.exp || 0;
  return crypto.createHash('sha256').update(`${sigHash}:${sub}:${exp}`).digest('hex');
}
