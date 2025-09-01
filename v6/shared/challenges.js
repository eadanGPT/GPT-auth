
// Shared challenge helpers (exact code provided by user)
class ChallengeKit {
  _randInt(min, max){
    return Math.floor(Math.random()*(max-min+1))+min;
  }

  _pickChallenge(){
    const t = ['algebra','arith','factor'][Math.floor(Math.random()*3)];
    if(t==='algebra'){
      const a = this._randInt(2,19);
      const x = this._randInt(-20,20);
      const b = this._randInt(-50,50);
      const c = a*x + b;
      return { type:'algebra', data:{a,b,c} };
    }
    if(t==='arith'){
      const a = this._randInt(-1000,1000);
      const b = this._randInt(-1000,1000);
      const op = Math.random()<0.5?'+':'-';
      return { type:'arith', data:{a,b,op} };
    }
    const P=[2,3,5,7,11,13,17,19,23][this._randInt(0,8)];
    const Q=[29,31,37,41,43,47,53,59][this._randInt(0,7)];
    return { type:'factor', data:{ n:P*Q } };
  }

  _solve(ch){
    if(ch.type==='algebra'){
      const {a,b,c} = ch.data; if(a===0) return null; const x=(c-b)/a; return Number.isInteger(x)? x : null;
    }
    if(ch.type==='arith'){
      const {a,b,op} = ch.data; return op==='+'? (a+b):(a-b);
    }
    if(ch.type==='factor'){
      const {n} = ch.data; for(let i=2;i*i<=n;i++){ if(n%i===0) return [i, n/i]; } return null;
    }
    return null;
  }
}

module.exports = { ChallengeKit };
