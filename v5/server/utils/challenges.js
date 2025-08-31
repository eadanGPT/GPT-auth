'use strict';
const { nowTicks } = require('./crypto');

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function pickChallenge() {
  const t = ['algebra', 'arith', 'factor'][randInt(0, 2)];
  if (t === 'algebra') {
    // ax + b = c
    const a = randInt(2, 19);
    const x = randInt(-20, 20);
    const b = randInt(-50, 50);
    const c = a * x + b;
    return { type: 'algebra', data: { a, b, c } };
  }
  if (t === 'arith') {
    const a = randInt(-1000, 1000);
    const b = randInt(-1000, 1000);
    const op = Math.random() < 0.5 ? '+' : '-';
    return { type: 'arith', data: { a, b, op } };
  }
  // factor
  const p = [2,3,5,7,11,13,17,19,23][randInt(0,8)];
  const q = [29,31,37,41,43,47,53,59][randInt(0,7)];
  const n = p * q;
  return { type: 'factor', data: { n } };
}

function solve(ch) {
  if (ch.type === 'algebra') {
    const { a, b, c } = ch.data;
    if (a === 0) return null;
    const x = (c - b) / a;
    return Number.isInteger(x) ? x : null;
  }
  if (ch.type === 'arith') {
    const { a, b, op } = ch.data;
    return op === '+' ? (a + b) : (a - b);
  }
  if (ch.type === 'factor') {
    const { n } = ch.data;
    for (let i = 2; i * i <= n; i++) {
      if (n % i === 0) return [i, n / i];
    }
    return null;
  }
  return null;
}

function deadline(ms) {
  const start = nowTicks();
  const ns = BigInt(ms) * 1000000n;
  return { start, limit: start + ns };
}

function timedOut(deadlineObj) {
  return nowTicks() > deadlineObj.limit;
}

module.exports = { pickChallenge, solve, deadline, timedOut };
