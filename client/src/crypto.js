
import crypto from 'node:crypto';

export function deriveClientKeyHash(licenseKey) {
  if (!licenseKey) return crypto.createHash('sha256').update('temp-'+Date.now()).digest('hex');
  return crypto.createHash('sha256').update(licenseKey).digest('hex');
}
export function scryptWrap(password, salt, len=32){
  return crypto.scryptSync(password, salt, len);
}
export function aesGcmEncrypt(key, iv, plaintext, aad=Buffer.alloc(0)){
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad.length) cipher.setAAD(aad);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([enc, tag]);
}
export function aesGcmDecrypt(key, iv, ciphertextPlusTag, aad=Buffer.alloc(0)){
  const tag = ciphertextPlusTag.slice(-16);
  const ciphertext = ciphertextPlusTag.slice(0, -16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  if (aad.length) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return dec;
}
