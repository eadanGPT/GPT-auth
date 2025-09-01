
const crypto = require('crypto');

function hkdf(keyMaterial, salt, info, len=32){
  return crypto.hkdfSync('sha256', keyMaterial, salt, Buffer.from(info), len);
}

function aesgcmEncrypt(key, plaintext, aad=null){
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if(aad) cipher.setAAD(Buffer.from(aad));
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}

function aesgcmDecrypt(key, b64, aad=null){
  const buf = Buffer.from(b64, 'base64');
  const iv = buf.slice(0,12);
  const tag = buf.slice(12,28);
  const enc = buf.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  if(aad) decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec;
}

// Runtime obfuscation: XOR with a process-ephemeral key derived from random seed
const _obKey = crypto.createHash('sha256').update(crypto.randomBytes(32)).digest();
function obfuscate(buf){
  const out = Buffer.alloc(buf.length);
  for(let i=0;i<buf.length;i++) out[i]=buf[i]^_obKey[i%_obKey.length];
  return out;
}
function deobfuscate(buf){ return obfuscate(buf); }

function sha256(data){
  return crypto.createHash('sha256').update(data).digest('hex');
}

function sha256b(data){
  return crypto.createHash('sha256').update(data).digest();
}

module.exports = { hkdf, aesgcmEncrypt, aesgcmDecrypt, obfuscate, deobfuscate, sha256, sha256b };
