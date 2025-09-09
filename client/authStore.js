
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const AUTH_FILE = path.join(process.cwd(), '.auth.json.enc');

function deriveKey(password, salt){
  return crypto.scryptSync(password, salt, 32);
}
export function encryptCreds(creds, masterPassword){
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(masterPassword, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(creds),'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from('v1'), salt, iv, tag, ct]).toString('base64');
}
export function decryptCreds(b64, masterPassword){
  const buf = Buffer.from(b64, 'base64');
  const ver = buf.subarray(0,2).toString();
  if (ver!=='v1') throw new Error('bad_version');
  const salt = buf.subarray(2,18);
  const iv = buf.subarray(18,30);
  const tag = buf.subarray(30,46);
  const ct = buf.subarray(46);
  const key = deriveKey(masterPassword, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return JSON.parse(pt.toString('utf8'));
}
export function saveAuth(creds, masterPassword){
  const enc = encryptCreds(creds, masterPassword);
  fs.writeFileSync(AUTH_FILE, enc);
}
export function loadAuth(masterPassword){
  if (!fs.existsSync(AUTH_FILE)) return null;
  const b64 = fs.readFileSync(AUTH_FILE,'utf8');
  return decryptCreds(b64, masterPassword);
}
export default { saveAuth, loadAuth };
