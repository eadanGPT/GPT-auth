
// server/challenge.js
import crypto from 'crypto';

const challenges = new Map();

export function buildChallenge(){
  const vars = Math.floor(Math.random()*7)+4; // 4-10
  const parts = [];
  for (let i=0;i<vars;i++){
    const t = Math.floor(Math.random()*6);
    const a = Math.floor(Math.random()*20)+2;
    const b = Math.floor(Math.random()*20)+2;
    const c = Math.floor(Math.random()*20)+2;
    if (t===0) parts.push(`${a}+${b}`);
    else if(t===1) parts.push(`${a}-${b}`);
    else if(t===2) parts.push(`${a}*${b}`);
    else if(t===3) parts.push(`${a}^${Math.floor(Math.random()*5)+2}`);
    else if(t===4) parts.push(`((${a}^${Math.floor(Math.random()*5)+2})+${b})%${Math.floor(Math.random()*19)+2}`);
    else if(t===5) parts.push(`factor(${a*b})`);
  }
  const expression = parts.join(' + ');
  const id = crypto.randomUUID();
  challenges.set(id, { expression, created_at: Date.now() });
  return { id, expression };
}

export function verifyChallenge(id, answers){
  const ch = challenges.get(id);
  if (!ch) return false;
  // Basic check: just verify count matches
  const count = ch.expression.split('+').length;
  return Array.isArray(answers) && answers.length === count;
}
