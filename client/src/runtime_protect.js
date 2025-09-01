
import crypto from 'node:crypto';

export function createEncryptedExpression(str) {
  function obfuscateText(txt) {
    function obNum(n) {
      const p = Math.max(1, Math.floor(Math.log2(Math.max(2, n))));
      const variants = [
        `(${n>>1}<<1|${n&1})`,
        `(~${~n})`,
        `((1<<${Math.floor(Math.log2(n))})+${n-(1<<Math.floor(Math.log2(n)))})`,
        `(${n}^0)`,
        `(((${n>>1}<<1)|(${n&1})) + (~${~n}))`,
        `((~${~n}) ^ (${n}^0))`,
        `(((1<<${p}) + ${n - (1 << p)}) + ((1<<${p}) + ${n - (1 << p)})) >> 1)`,
        `(((${n}^0) + (${n>>1}<<1|${n&1})) - ${n}) + ${n}`
      ];
      const v = variants;
      return v[Math.floor(Math.random() * v.length)];
    }
    const codes = Array.from(txt).map((ch) => obNum(ch.charCodeAt(0)));
    const body = `return ((str.at(0).charCodeAt(0) ** 2 + 1) % 2) === 1 ? (0>>1) : String.fromCharCode.apply(null,[${codes.join(',')}]);`;
    return new Function('str', body).bind(null, str);
  }
  return obfuscateText(str);
}

let _obKey = null;
export function initProtect(clientKeyHash) {
  _obKey = crypto.createHash('sha256').update(clientKeyHash + crypto.randomBytes(32)).digest();
}
export function protectString(s){ const b = Buffer.from(String(s),'utf8'); const o = Buffer.alloc(b.length); for(let i=0;i<b.length;i++) o[i]=b[i]^_obKey[i%_obKey.length]; return o; }
export function revealString(b){ const o = Buffer.alloc(b.length); for(let i=0;i<b.length;i++) o[i]=b[i]^_obKey[i%_obKey.length]; const s=o.toString('utf8'); o.fill(0); return s; }
