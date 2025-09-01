'use strict';
const crypto = require('crypto');
function hkdf(keyMaterial, salt, info, len=32){ return crypto.hkdfSync('sha256', keyMaterial, salt, Buffer.from(info), len); }
function aesgcmEncrypt(key, plaintext, aad=null){ const iv=crypto.randomBytes(12); const cipher=crypto.createCipheriv('aes-256-gcm', key, iv); if(aad) cipher.setAAD(Buffer.from(aad)); const enc=Buffer.concat([cipher.update(plaintext),cipher.final()]); const tag=cipher.getAuthTag(); return Buffer.concat([iv,tag,enc]).toString('base64'); }
function aesgcmDecrypt(key, b64, aad=null){ const buf=Buffer.from(b64,'base64'); const iv=buf.slice(0,12), tag=buf.slice(12,28), enc=buf.slice(28); const decipher=crypto.createDecipheriv('aes-256-gcm', key, iv); if(aad) decipher.setAAD(Buffer.from(aad)); decipher.setAuthTag(tag); const dec=Buffer.concat([decipher.update(enc),decipher.final()]); return dec; }
function sha256(buf){ return crypto.createHash('sha256').update(buf).digest('hex'); }
module.exports={ hkdf, aesgcmEncrypt, aesgcmDecrypt, sha256 };
