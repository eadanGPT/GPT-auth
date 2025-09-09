import crypto from 'node:crypto';
import { LocalKms } from './kms/local.js';

export const KeyManager = {
  async init() {
    const kms = await LocalKms.init(); // swap with cloud KMS SDK
    let active = await kms.rotateEd25519(); // returns {kid, alias, pubSpkiPem}
    const previous = new Map();

    const allowedPurposes = new Set(['jwt','module_envelope','rpc_envelope']);
    const metrics = { kms_sign_count:0, kms_rotate_count:0 };

    async function rotateIfNeeded() {
      const before = active;
      const rotated = await kms.rotateEd25519();
      if (!before || rotated.kid !== before.kid) {
        metrics.kms_rotate_count++;
        if (before) previous.set(before.kid, { pubSpkiPem: before.pubSpkiPem, expiresAt: Date.now()+prevTtlSec*1000 });
        active = rotated;
      } else {
        active = rotated; // re-affirm
      }
    }
 // kid -> { pubSpkiPem, expiresAt }

    const prevTtlSec = Number(process.env.KEY_PREV_TTL || 86400);

    async function rotateEd25519() {
      const old = active;
      active = await kms.rotateEd25519();
      if (old) previous.set(old.kid, { pubSpkiPem: old.pubSpkiPem, expiresAt: Date.now()+prevTtlSec*1000 });
    }

    async function sign(bytes, purpose='generic') {
      return kms.signEd25519(active.alias, bytes);
    }

    async function verify(kid, sig, bytes) {
      let pem;
      if (kid === active.kid) pem = active.pubSpkiPem;
      else if (previous.has(kid)) {
        const p = previous.get(kid);
        if (p.expiresAt < Date.now()) { previous.delete(kid); throw new Error('KID expired'); }
        pem = p.pubSpkiPem;
      } else {
        throw new Error('Unknown KID');
      }
      const pub = crypto.createPublicKey(pem);
      return crypto.verify(null, Buffer.from(bytes), pub, sig);
    }

    async function getActive() { return { kid: active.kid }; }
    async function getActivePublicSPKIb64() { return Buffer.from(active.pubSpkiPem).toString('base64'); }

    return { rotateEd25519, sign, verify, getActive, getActivePublicSPKIb64, rotateIfNeeded, metrics, previous };
  }
};
