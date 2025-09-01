 
// server/auth.js
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { db, logEvent } from './db.js';

let serverKeyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
let logKeyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

export function getServerKeys(){
  return { priv: serverKeyPair.privateKey.export({ type:'pkcs1', format:'pem' }),
           pub: serverKeyPair.publicKey.export({ type:'pkcs1', format:'pem' }),
           logsPub: logKeyPair.publicKey.export({ type:'pkcs1', format:'pem' }) };
}
export function rsaDecryptOAEP(privPem, b64){
  const buf = Buffer.from(b64, 'base64');
  return crypto.privateDecrypt({ key: privPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash:'sha256' }, buf);
}
export function hkdf(ikm, salt, info, len){
  return crypto.hkdfSync('sha256', ikm, salt, info, len);
}
export function aesGcmEncrypt(key, plaintext, aad=Buffer.alloc(0)){
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad?.length) cipher.setAAD(aad);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}
export function aesGcmDecrypt(key, b64, aad=Buffer.alloc(0)){
  const buf = Buffer.from(b64,'base64');
  const iv = buf.subarray(0,12);
  const tag = buf.subarray(12,28);
  const enc = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  if (aad?.length) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec;
}

export function issueJwt({ owner, client_keyhash, permanent_hwid }){
  const now = Math.floor(Date.now()/1000);
  const exp = now + 3*24*60*60;
  const payload = { sub: owner, iat: now, exp, enc: crypto.publicEncrypt(getServerKeys().pub, Buffer.from(`${client_keyhash}:${permanent_hwid}`)).toString('base64') };
  const tok = jwt.sign(payload, crypto.randomBytes(32).toString('hex'));
  return tok;
}
export function deterministicTokenId(token){
  const parts = token.split('.');
  const sig = parts[2] || '';
  const subject = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')).sub || '';
  const exp = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')).exp || 0;
  const h = crypto.createHash('sha256').update(sig+subject+String(exp)).digest('hex');
  return h;
}
export function validateLicense(license){
  const row = db.prepare('SELECT owner, blacklisted FROM keys WHERE license_key=?').get(license);
  if (!row) return { ok:false, reason:'no_such_license' };
  if (row.blacklisted) return { ok:false, reason:'blacklisted' };
  return { ok:true, owner: row.owner };
}
export function enforceSingleSession(owner){
  db.prepare('UPDATE sessions SET active=0 WHERE owner=?').run(owner);
}
export function saveToken({ token, owner, client_keyhash }){
  db.prepare('INSERT INTO logs(kind,level,owner,message,created_at) VALUES (?,?,?,?,?)').run('token','info',owner,'issued',Date.now());
}
