'use strict';
const crypto = require('crypto');
class ChallengeKit {
  constructor(){ this._manifest=new Map(); this._maxUnique=100; }
  _randInt(min,max){ return Math.floor(Math.random()*(max-min+1))+min; }
  _pickChallenge(){
    const types=['algebra','arith','factor','muldiv','power','modexp','gcd'];
    const t=types[Math.floor(Math.random()*types.length)];
    if(t==='algebra'){
      const sub=this._randInt(0,1);
      if(sub===0){ const a=this._randInt(2,19); const x=this._randInt(-20,20); const b=this._randInt(-50,50); const c=a*x+b; return {type:'algebra',variant:'ax+b=c',data:{a,b,c}}; }
      else { const a=this._randInt(2,10), b=this._randInt(2,10), x=this._randInt(-5,5), y=this._randInt(-5,5), c=a*x+b*y; return {type:'algebra',variant:'ax+by=c',data:{a,b,c,y}}; }
    }
    if(t==='arith'){
      const sub=this._randInt(0,2);
      if(sub===0){ const a=this._randInt(-100,100), b=this._randInt(-100,100); return {type:'arith',variant:'a+b',data:{a,b,ops:['+']}}; }
      if(sub===1){ const a=this._randInt(-100,100), b=this._randInt(-100,100), c=this._randInt(-100,100); return {type:'arith',variant:'a+b+c',data:{a,b,c,ops:['+','+']}}; }
      if(sub===2){ const a=this._randInt(-100,100), b=this._randInt(-100,100), c=this._randInt(-100,100); return {type:'arith',variant:'a-b+c',data:{a,b,c,ops:['-','+']}}; }
    }
    if(t==='factor'){
      const sub=this._randInt(0,1);
      if(sub===0){ const P=[2,3,5,7,11,13,17,19,23][this._randInt(0,8)]; const Q=[29,31,37,41,43,47,53,59][this._randInt(0,7)]; return {type:'factor',variant:'semiprime',data:{n:P*Q}}; }
      else { const n=this._randInt(30,200); return {type:'factor',variant:'generic',data:{n}}; }
    }
    if(t==='muldiv'){
      const sub=this._randInt(0,2);
      if(sub===0){ const a=this._randInt(2,50), b=this._randInt(2,50); return {type:'muldiv',variant:'a*b',data:{a,b,op:'*'}}; }
      if(sub===1){ const a=this._randInt(2,20), b=this._randInt(2,20); return {type:'muldiv',variant:'a*b*c',data:{a,b,c:this._randInt(2,20)}}; }
      if(sub===2){ const a=this._randInt(2,20), b=this._randInt(2,20); return {type:'muldiv',variant:'a/b',data:{a:a*b,b,op:'/'}}; }
    }
    if(t==='power'){
      const sub=this._randInt(0,1);
      if(sub===0){ const base=this._randInt(2,9), exp=this._randInt(2,5); return {type:'power',variant:'base^exp',data:{base,exp}}; }
      else { const base=this._randInt(2,9), exp=this._randInt(2,3), mul=this._randInt(2,10); return {type:'power',variant:'base^exp*mul',data:{base,exp,mul}}; }
    }
    if(t==='modexp'){
      const sub=this._randInt(0,1);
      const base=this._randInt(2,12), exp=this._randInt(2,6), mod=this._randInt(13,50);
      if(sub===0){ return {type:'modexp',variant:'(base^exp)%mod',data:{base,exp,mod}}; }
      else { const add=this._randInt(1,mod-1); return {type:'modexp',variant:'((base^exp)+add)%mod',data:{base,exp,mod,add}}; }
    }
    if(t==='gcd'){
      const sub=this._randInt(0,1);
      if(sub===0){ const a=this._randInt(20,200), b=this._randInt(20,200); return {type:'gcd',variant:'gcd(a,b)',data:{a,b}}; }
      else { const a=this._randInt(20,200), b=this._randInt(20,200), c=this._randInt(20,200); return {type:'gcd',variant:'gcd(a,b,c)',data:{a,b,c}}; }
    }
    return null;
  }
  _solve(ch){
    if(ch.type==='algebra'){ if(ch.variant==='ax+b=c'){ const {a,b,c}=ch.data; return (c-b)/a; } if(ch.variant==='ax+by=c'){ const {a,b,c,y}=ch.data; return (c-b*y)/a; } }
    if(ch.type==='arith'){ const {a,b,c,ops}=ch.data; if(ops.length===1){ return ops[0]==='+'?a+b:a-b; } if(ops.length===2){ if(ops[0]==='+'&&ops[1]==='+') return a+b+c; if(ops[0]==='-'&&ops[1]==='+') return a-b+c; } }
    if(ch.type==='factor'){ const {n}=ch.data; for(let i=2;i*i<=n;i++){ if(n%i===0) return [i,n/i]; } return null; }
    if(ch.type==='muldiv'){ if(ch.variant==='a*b') return ch.data.a*ch.data.b; if(ch.variant==='a*b*c') return ch.data.a*ch.data.b*ch.data.c; if(ch.variant==='a/b') return ch.data.a/ch.data.b; }
    if(ch.type==='power'){ if(ch.variant==='base^exp') return Math.pow(ch.data.base,ch.data.exp); if(ch.variant==='base^exp*mul') return Math.pow(ch.data.base,ch.data.exp)*ch.data.mul; }
    if(ch.type==='modexp'){ const {base,exp,mod,add}=ch.data; let r=1, b=base%mod, e=exp; while(e>0){ if(e&1) r=(r*b)%mod; b=(b*b)%mod; e>>=1; } return (add!==undefined)?(r+add)%mod:r; }
    if(ch.type==='gcd'){ if(ch.variant==='gcd(a,b)'){ let {a,b}=ch.data; while(b!==0){ [a,b]=[b,a%b]; } return a; } if(ch.variant==='gcd(a,b,c)'){ let {a,b,c}=ch.data; const gcd=(x,y)=>y?gcd(y,x%y):x; return gcd(gcd(a,b),c); } }
    return null;
  }
  next(){ if(this._manifest.size<this._maxUnique){ const ch=this._pickChallenge(); const id=crypto.randomBytes(16).toString('hex'); this._manifest.set(id,ch); return {id,ch}; } else { const keys=Array.from(this._manifest.keys()); const id=keys[this._randInt(0,keys.length-1)]; return {id,ch:this._manifest.get(id)}; } }
  solve(payload){ return this._solve(payload); }
}
module.exports={ ChallengeKit };
