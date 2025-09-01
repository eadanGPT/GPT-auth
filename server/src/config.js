
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const CFG_DIR = path.join(process.cwd(), 'server', 'config');
const KEYS_DIR = path.join(CFG_DIR, 'keys');
fs.mkdirSync(KEYS_DIR, { recursive: true });

function ensureKeypair(name = 'auth') {
  const pubPath = path.join(KEYS_DIR, `${name}.pub.pem`);
  const privPath = path.join(KEYS_DIR, `${name}.priv.pem`);
  if (!fs.existsSync(pubPath) || !fs.existsSync(privPath)) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    });
    fs.writeFileSync(pubPath, publicKey);
    fs.writeFileSync(privPath, privateKey);
  }
  return {
    publicKey: fs.readFileSync(pubPath, 'utf8'),
    privateKey: fs.readFileSync(privPath, 'utf8'),
  };
}

export const env = {
  PORT: parseInt(process.env.PORT || '8080', 10),
  ADMIN_PORT: parseInt(process.env.ADMIN_PORT || '8080', 10),
  WS_PATH: process.env.WS_PATH || '/ws',
  JWT_TTL_DAYS: parseInt(process.env.JWT_TTL_DAYS || '3', 10),
  ALLOW_CONNECTIONS: (process.env.ALLOW_CONNECTIONS || 'true') === 'true',
  MAX_CONNECTIONS: parseInt(process.env.MAX_CONNECTIONS || '100', 10),
  ADMIN_TOKEN_TTL_MIN: parseInt(process.env.ADMIN_TOKEN_TTL_MIN || '60', 10),
  ADMIN_PASSWORD_ROTATE_MIN: parseInt(process.env.ADMIN_PASSWORD_ROTATE_MIN || '60', 10),
};

export const keypair = ensureKeypair('auth');
