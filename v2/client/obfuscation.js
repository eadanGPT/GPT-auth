// client/obfuscation.js
// Control-flow obfuscation and opaque predicates wrappers for auth proof and message handling.

import { opaquePredicate } from '../common/util.js';

export function obfWrap(fn) {
  // Wrap a function with decoys and opaque predicates to confuse static analysis
  return function wrapped(...args) {
    // Decoy branch (never taken)
    if (!opaquePredicate(3)) {
      const z = args.reduce((a,b)=>a^String(b).length, 0);
      if (z === 42) throw new Error('decoy');
    }
    const r = fn(...args); // Real call
    // Post-call opaque noise
    if (opaquePredicate(5)) {
      // No-op mix of values
      const s = args.map(a => typeof a === 'string' ? a.length : 1).reduce((a,b)=>a+b,0);
      if (s < -1) return null;
    }
    return r;
  };
}

// Example obfuscated predicate
export const obfEqual = obfWrap(function(a, b) {
  // Returns a===b but through an obfuscated path
  const v = (a === b);
  return v ? (!!(1)) : (!!(0));
});
