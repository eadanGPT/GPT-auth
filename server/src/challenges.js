
import crypto from 'node:crypto';

function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

function genExpr() {
  const ops = ['alg2', 'alg1', 'add', 'sub', 'mul', 'div', 'pow', 'mod', 'semiPrime'];
  const count = randInt(4, 10);
  const parts = [];
  const vars = { a: randInt(2, 30), b: randInt(2, 30), c: randInt(2, 30), x: randInt(1, 10), y: randInt(1, 10), z: randInt(1, 5), base: randInt(2, 8), exp: randInt(2, 6), add: randInt(1, 20), mod: randInt(5, 50) };
  for (let i = 0; i < count; i++) {
    const choice = ops[randInt(0, ops.length - 1)];
    switch (choice) {
      case 'alg2': parts.push(`${vars.a}*${vars.x}+${vars.b}*${vars.y}==${vars.c}`); break;
      case 'alg1': parts.push(`${vars.a}*${vars.x}+${vars.b}==${vars.c}`); break;
      case 'add': parts.push(`${vars.a}+${vars.b}+${vars.x}`); break;
      case 'sub': parts.push(`${vars.c}-${vars.b}-${vars.x}`); break;
      case 'mul': parts.push(`${vars.a}*${vars.b}`); break;
      case 'div': parts.push(`${vars.c}/${Math.max(1, vars.x)}`); break;
      case 'pow': parts.push(`${vars.base}**${vars.exp}`); break;
      case 'mod': parts.push(`((${vars.base}**${vars.exp})+${vars.add})%${vars.mod}`); break;
      case 'semiPrime': {
        let p = 0, q = 0; while (p*q < 50) { p = randInt(11, 97); q = randInt(11, 97); }
        parts.push(`factor(${p*q})`); break;
      }
    }
  }
  return parts.join(' + ');
}

function evalExpr(expr) {
  function factor(n) {
    const res = [];
    for (let i = 2; i * i <= n; i++) { while (n % i === 0) { res.push(i); n = n / i; } }
    if (n > 1) res.push(n);
    return res;
  }
  // eslint-disable-next-line no-new-func
  const fn = new Function('factor', `return (${expr});`);
  const v = fn(factor);
  const flat = Array.isArray(v) ? v.reduce((a,b)=>a+b,0) : (typeof v === 'boolean' ? (v?1:0) : v);
  return Number.isFinite(flat) ? Math.floor(flat) : 0;
}

export function newChallenge() {
  const expr = genExpr();
  const answer = evalExpr(expr);
  const id = crypto.randomUUID();
  return { id, expr, answer };
}
