
const crypto = require('crypto');
const { hkdf, aesgcmEncrypt, aesgcmDecrypt, sha256, sha256b } = require('../shared/crypto');

// Server long-term signing key (Ed25519)
let SIGN_KP = crypto.generateKeyPairSync('ed25519');
// Server ECDH for session key agreement (x25519)
function makeECDH(){
  try { return crypto.generateKeyPairSync('x25519'); }
  catch(e){ 
    // Fallback P-256
    const ecdh = crypto.createECDH('prime256v1'); ecdh.generateKeys();
    return { privateKey: ecdh, publicKey: ecdh.getPublicKey() };
  }
}

function sign(data){
  return crypto.sign(null, Buffer.from(data), SIGN_KP.privateKey).toString('base64');
}
function verify(data, b64sig){
  return crypto.verify(null, Buffer.from(data), SIGN_KP.publicKey, Buffer.from(b64sig,'base64'));
}
function exportPublicKey(){
  return SIGN_KP.publicKey.export({type:'spki', format:'pem'});
}

function deriveSessionKey(serverPriv, clientPubRaw){
  if(serverPriv.type === 'private'){ // node x25519 pair
    const shared = crypto.diffieHellman({ privateKey: serverPriv, publicKey: crypto.createPublicKey({key:clientPubRaw, format:'der', type:'spki'}) });
    return hkdf(shared, Buffer.alloc(0), 'ws-session', 32);
  }else{
    // ECDH fallback
    const shared = serverPriv.computeSecret(clientPubRaw);
    return hkdf(shared, Buffer.alloc(0), 'ws-session', 32);
  }
}

module.exports = { makeECDH, sign, verify, exportPublicKey, deriveSessionKey, aesgcmEncrypt, aesgcmDecrypt, sha256, sha256b };
