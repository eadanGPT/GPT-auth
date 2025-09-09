
import { v4 as uuidv4 } from 'uuid';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';

function encPrivPem(masterKey, pemStr) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(masterKey, salt, 32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(pemStr,'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  // zero out key buffer
  key.fill(0);
  return Buffer.concat([salt, iv, ct, tag]).toString('base64');
}

function decPrivPem(masterKey, b64) {
  const buf = Buffer.from(b64,'base64');
  const salt = buf.slice(0,16);
  const iv = buf.slice(16,28);
  const tag = buf.slice(buf.length-16);
  const ct = buf.slice(28, buf.length-16);
  const key = crypto.scryptSync(masterKey, salt, 32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  key.fill(0);
  return pt.toString('utf8');
}

export const LocalKms = {
  async init() {
    const master = process.env.KMS_MASTER_KEY || 'dev-master-key';
    const dbPath = process.env.SQLITE_DB || 'server/data/licenses.db';
    const db = new Database(dbPath);
    db.exec(`
CREATE TABLE IF NOT EXISTS kms_signing_keys (
  kid TEXT PRIMARY KEY,
  algo TEXT NOT NULL,
  pubSpkiPem TEXT NOT NULL,
  encPrivB64 TEXT NOT NULL,
  createdAt INTEGER NOT NULL,
  lastUsedAt INTEGER,
  usageCount INTEGER NOT NULL DEFAULT 0,
  rotateAfterMs INTEGER NOT NULL DEFAULT 43200000, -- 12h
  rotateAfterUse INTEGER NOT NULL DEFAULT 5000
);`);

    function getActiveRow() {
      return db.prepare('SELECT * FROM kms_signing_keys ORDER BY createdAt DESC LIMIT 1').get();
    }

    function needRotate(row) {
      if (!row) return true;
      const age = Date.now() - row.createdAt;
      return age > row.rotateAfterMs || row.usageCount >= row.rotateAfterUse;
    }

    async function newEd25519() {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const pubSpkiPem = publicKey.export({ type:'spki', format:'pem' });
      const pkcs8Pem = privateKey.export({ type:'pkcs8', format:'pem' });
      const encPrivB64 = encPrivPem(master, pkcs8Pem);
      const kid = 'ed25519-' + uuidv4();
      db.prepare('INSERT INTO kms_signing_keys(kid,algo,pubSpkiPem,encPrivB64,createdAt) VALUES(?,?,?,?,?)')
        .run(kid,'Ed25519', pubSpkiPem, encPrivB64, Date.now());
      // zero out pem strings
      return { kid, alias: kid, pubSpkiPem };
    }

    async function rotateEd25519() {
      const row = getActiveRow();
      if (needRotate(row)) {
        return await newEd25519();
      }
      return { kid: row.kid, alias: row.kid, pubSpkiPem: row.pubSpkiPem };
    }

    function loadPrivateKey(alias) {
      const row = db.prepare('SELECT * FROM kms_signing_keys WHERE kid=?').get(alias);
      if (!row) throw new Error('Alias not found');
      const pem = decPrivPem(master, row.encPrivB64);
      const keyObj = crypto.createPrivateKey({ key: pem, format:'pem', type:'pkcs8' });
      // wipe pem string
      return { keyObj, row };
    }

    async function signEd25519(alias, bytes, purpose='generic') {
      const { keyObj, row } = loadPrivateKey(alias);
      try {
        const sig = crypto.sign(null, Buffer.from(bytes), keyObj);
        db.prepare('UPDATE kms_signing_keys SET usageCount=usageCount+1,lastUsedAt=? WHERE kid=?')
          .run(Date.now(), alias);
        return sig;
      } finally {
        try { keyObj.export({ format:'pem', type:'pkcs8' }).fill(0); } catch {}
      }
    }

    return { rotateEd25519, signEd25519 };
  }
};
