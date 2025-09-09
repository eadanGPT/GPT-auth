import Redis from 'ioredis';

export const RateLimiter = {
  async init() {
    const redis = new Redis(process.env.REDIS_URL || 'redis://127.0.0.1:6379');
    const script = `
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local leakRate = tonumber(ARGV[2])   -- tokens per second
local now = tonumber(ARGV[3])
local weight = tonumber(ARGV[4])
local state = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(state[1]) or capacity
local ts = tonumber(state[2]) or now
local delta = math.max(0, now - ts)
tokens = math.min(capacity, tokens + delta * leakRate)
if tokens < weight then
  return 0
else
  tokens = tokens - weight
  redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
  redis.call('EXPIRE', key, math.ceil(capacity / leakRate))
  return 1
end
`;
    const sha = await redis.script('LOAD', script);

    async function allow(actor, weight=1, capacity=20, leakRate=10) {
      const key = `ratelimit:${actor}`;
      const now = Math.floor(Date.now()/1000);
      const ok = await redis.evalsha(sha, 1, key, capacity, leakRate, now, weight);
      if (ok !== 1) throw new Error('Rate limit exceeded');
    }

    return { allow, redis };
  }
};
