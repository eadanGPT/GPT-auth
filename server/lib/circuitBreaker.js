export const CircuitBreaker = {
  create() {
    const failures = new Map();
    const openUntil = new Map();

    const windowMs = 60_000;
    const threshold = 5;
    const baseBackoffMs = 5_000;
    const maxBackoffMs = 5 * 60_000;

    function fail(key) {
      const now = Date.now();
      const arr = (failures.get(key) || []).filter(x => now - x < windowMs);
      arr.push(now);
      failures.set(key, arr);
      if (arr.length >= threshold) {
        const n = arr.length - threshold + 1;
        const backoff = Math.min(maxBackoffMs, baseBackoffMs * Math.pow(2, n-1));
        openUntil.set(key, now + backoff);
      }
    }

    function blocked(key) {
      const until = openUntil.get(key) || 0;
      if (Date.now() < until) return true;
      if (until) openUntil.delete(key);
      return false;
    }

    return { fail, blocked };
  }
};
