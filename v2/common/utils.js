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
  // Returns true for all integers but is hard to fold statically
  return ((x * x + 1) % 2) === 1;
}
