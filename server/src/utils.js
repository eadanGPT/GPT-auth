
import crypto from 'node:crypto';
export function safeParseJSON(s, fallback = null) { try { return JSON.parse(s); } catch { return fallback; } }
export function bufToB64(buf) { return Buffer.from(buf).toString('base64'); }
export function b64ToBuf(b64) { return Buffer.from(b64, 'base64'); }
export function randBytesB64(n=32){ return crypto.randomBytes(n).toString('base64'); }
export function now() { return Date.now(); }
