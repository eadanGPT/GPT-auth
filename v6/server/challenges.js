
const { ChallengeKit } = require('../shared/challenges');
const ck = new ChallengeKit();

function pickChallenge(){ return ck._pickChallenge(); }
function solveChallenge(ch){ return ck._solve(ch); }

module.exports = { pickChallenge, solveChallenge };
