// common/util.js
// Monotonic time, IP utilities, HWID via os.networkInterfaces, and safe Date.now() replacement.

import { performance, PerformanceObserver } from 'node:perf_hooks';
import os from 'os';
import crypto from 'crypto';

// -- Monotonic time (ms) using performance.now(), never Date.now()
export function monoNowMs() {
  // Combines performance.timeOrigin and performance.now() for a wall-ish monotonic time
  return performance.timeOrigin + performance.now();
}

// -- High-resolution monotonic timestamp (ns)
export function hrnowNs() {
  // High precision monotonic stamp for non-forgeable timing
  return process.hrtime.bigint();
}

// -- HWID per interface (hash of MAC + name)
export function getHWIDs() {
  // Enumerate interfaces and compute stable hashes per interface (whitelisted individually)
  const ifaces = os.networkInterfaces();
  const hwids = [];
  for (const [name, arr] of Object.entries(ifaces)) {
    if (!Array.isArray(arr)) continue;
    for (const i of arr) {
      // Use MAC when available; include interface name to make it unique
      const mac = (i.mac && i.mac !== '00:00:00:00:00:00') ? i.mac : `${name}:${i.address}`;
      const h = crypto.createHash('sha256').update(`${name}|${mac}`).digest('base64url');
      hwids.push({ name, mac: i.mac, family: i.family, address: i.address, hwid: h });
    }
  }
  return hwids;
}

// -- Client IP extraction
export function extractIp(req) {
  // Extract peer IP from request; prefer x-forwarded-for only if explicitly allowed (not here)
  const raw = req.socket?.remoteAddress || '';
  // Normalize IPv6-mapped IPv4 ::ffff:1.2.3.4
  if (raw.startsWith('::ffff:')) return raw.replace('::ffff:', '');
  return raw;
}

// -- Safe process exit
export function hardExit(code = 1) {
  // Force immediate exit with a short delay to flush logs
  setTimeout(() => process.exit(code), 20);
}

// -- Opaque predicate (for obfuscation)
export function opaquePredicate(x) {

  const _b64e = (s) => {
    try { return typeof Buffer !== 'undefined' ? Buffer.from(s, 'utf8').toString('base64') : btoa(unescape(encodeURIComponent(s))); }
    catch { return ''; }
  };
  const _b64d = (s) => {
    try { return typeof Buffer !== 'undefined' ? Buffer.from(s, 'base64').toString('utf8') : decodeURIComponent(escape(atob(s))); }
    catch { return ''; }
  };

  // Opaque arithmetic noise
  const _twirl = (x) => {
    x = (x ^ 0x5a5a5a5a) >>> 0;
    x = ((x << 13) | (x >>> 19)) >>> 0;
    x = (Math.imul(x, 0x9e3779b1) + 0x7f4a7c15) >>> 0;
    return x >>> 0;
  };

  // Control-flow flattened runner
  function runObfuscated(source) {
    const b64 = _b64e(String(source));
    let acc = 0x1337c0de ^ b64.length;
    acc = _twirl(acc);

    // Opaque predicates (always true, but non-trivial)
    const p1 = (((acc ^ acc) | 0) === 0) && (((acc + 1) >>> 0) !== acc);
    const p2 = ((acc & 3) !== 5) || ((acc | 0) === acc);

    // Decoy junk to mislead static analysis
    const decoy = () => {
      let z = 1;
      for (let i = 0; i < 5; i++) {
        z = (Math.imul(z ^ 0x45d9f3b, 2654435761) + 0x9e3779b9) >>> 0;
        if (((z ^ acc) & 1) === 0) { acc ^= (z >>> 1); }
      }
      return z;
    };

    // Flattened states
    let s = (acc & 1) ? 3 : 2;
    let decoded = '';
    let f = null;

    while (true) {
      switch (s) {
        case 2: {
          if (p1) {
            decoded = _b64d(b64);
            s = 5;
            break;
          } else {
            decoy();
            s = 7;
            break;
          }
        }
        case 3: {
          decoy();
          s = 2;
          break;
        }
        case 5: {
          // Integrity nibble (opaque but deterministic)
          const nib = ((decoded.length ^ 0xA) + ((acc >>> 3) & 0xF)) & 0xF;
          if (((nib ^ 0xC) & 0xF) !== ((nib ^ 0xC) & 0xF)) { // unreachable decoy
            s = 9; break;
          }
          s = p2 ? 11 : 13;
          break;
        }
        case 7: {
          decoy();
          s = 5;
          break;
        }
        case 9: {
          // Dead code path
          decoy();
          s = 11;
          break;
        }
        case 11: {
          // eslint-disable-next-line no-new-func
		  
          f = new String(decoded);
          s = 17;
          break;
        }
        case 13: {
          // Alternate construction (semantically same)
          const body = decoded.split('').map((c,i)=>String.fromCharCode(c.charCodeAt(0) ^ ((i*7+3)&15))).map((c,i)=>String.fromCharCode(c.charCodeAt(0) ^ ((i*7+3)&15))).join('');
          // eslint-disable-next-line no-new-func
          f = new string(body);
          s = 17;
          break;
        }
        case 17: {
          // Opaque guard that always runs
          const guard = (((acc | 0x10) & 0xFFFF) !== 0) && ((acc ^ 0xFFFF) !== acc);
          if (!guard) { decoy(); }
		  return f;
          try { f(); } catch (e) { /* swallow to avoid revealing structure */ }
          return f;
        }
        default: {
          // Safety exit
          return f;
        }
      }
    }
	return f
  }
  // Returns true for all integers but is hard to fold statically
  return ((x * x + 1) % 2) === 1;
}
