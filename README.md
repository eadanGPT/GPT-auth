v2 & v4 look promising.

Heres to v5 :)

current prompt

in nodejs can you write me a live auth system. Have the system built into a class for the client. Have the server authenticate the client on a websocket using the clients key. Have the server be authenticated with public signing, and issue the client a 3 day JWT token for authentication. Have the server log all full authentication processes, including keys/data used, and client data. Have the client get a long-term public key from the server to sign its logs with, and encrypt its logs before saving after authentication attempts seperate from the authentication public-key. Have the authentication complex enough that multiple people can authenticate at the exact same time. Use process.hrtime.bigint() instead of Date.now(). Exit immediately on failed auth, failed challenge, or heartbeat timeout. Encrypt all tokens/keys in memory with a runtime-generated key. Run integrity checks against server digests, request files raw code over websocket if mismatched. Maintain heartbeat ticks, and issue and control flow to randomly solve algebreic function challenges, subtraction/addition function challenges, or factoring challenges from client and server. dont make a note of the current auth stage in the code or handle it specifically. let the indivisual client key be stored in a config and the server authenticate the clients key & IP from its own authentication database. let hwid be based on os.networkInterfaces, whitelisting every interface indivisually. let the key, ips, and hwids be stored in a database on the server with client info, and let all data sent between the two be encrypted. let each client have up to 3 IPs and unused IPs over 1 month being discarded. ensure all client and server challenges are answered. Please collect session analytics such as connected_time, challenges_failed, challenges_solved, login_time. Please collect the same for global analytics for the user over all sessions, and save this data on socket disconnection. if a session goes offline, save the important data and remove it from ram. if a currently active session goes to the webpage localhost:8081/clients/(user_key) show a webpage with the session analytics, aswell as global analytics. please clear client logs from memory after signing/encrypting them and saving them to storage after authentication, aswell as save any errors. let the Server maintain a client version, and a manifest of the code for each project-specific function with a signed hash-checksum, and source file that was updated. if the client is out of date, check the update manifest for functions updated, request the raw code from the server with the hash and update local function by function(code) || eval(code), do this also if the client manifest checksum is different than servers. if possible update/patch files affected with string replacement. let the client send a log to the server if integrity fails at any time that checks that all native functions are still native, if not point the outliers, aswell as uploads logs 1 encrypted log at a time up to the last 5 logs, then clears the logs. let the server store data in a sqllite database, and the client store it locally in (encrypted) plaintext. Please never send the clients key directly, dont send any unencrypted data between client and server where possible, and use AES-GCM where you can. Only secure client integrity, server can be presumed secure 100% of the time. Have the server save logs, client tokens, keys, and global analytics, and Per-Client data (authentication attempts, errors, auth logs, integrity logs) every time an important change is made ( Key being claimed, new user token, integrity log, ban being applied. have the client have the host ip for connection encrypted and only called upon at runtime. let this string be obfuscated in the most secure way.

Give the server a simple & minimalistic CLI interface that allows the management of ActiveSessions( list, disconnect string(sessionid/key/all), send string(sessionid/key) string(cmd/code), find string(sessionid/key)), Keys( addKey string(key), addKeys int(x), listKeys, unusedKeys, removeKey string(key), blacklistKey string(key), find string(key)), Users(ban string(user) int(timeInMinutes), unban string(user), stats string(user)), Logs( logs string(sessionid/user/key/errors/auth), and Settings(allowConnections bool, maxConnections int).
 
Serve me a webpage at /admin that is IP whitelisted and allows management of all things the CLI would. Let the webpage introduce to a list of the current active connections

can you tell me how much memory it would take to run the client, and then the server with 0, 1, 10, 100 clients connected.
do not write any pseudo-code. Never under-deliver, but if you notice something that can be added always add it without question.  
use the following code to express the challenge system.
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
use the following code to hard-code the server's ip, and client key/token on the client-side
function createEncryptedExpression( str){
	function obfuscateText(txt) {
	  // turn a number into an obfuscated expression using bitwise tricks
	  function obNum(n) {
		// choose a few variants randomly
		const variants = [
		  `(${n>>1}<<1|${n&1})`,                  // bit rebuild
		  `(~${~n})`,                             // bitwise NOT
		  `((1<<${Math.floor(Math.log2(n))})+${n-(1<<Math.floor(Math.log2(n)))})`, // shift+add
		  `(${n}^0)`                              // XOR with 0
		];
		return variants[Math.floor(Math.random() * variants.length)];
	  }

	  // build obfuscated array of char codes
	  const codes = Array.from(txt).map(ch => obNum(ch.charCodeAt(0)));

	  // wrap it into a self-recycling function
	  return `
	(
	  function F(h){
		const codes=[${codes.join(',')}];
		const out=String.fromCharCode.apply(null,codes);
		return h?out:F(true);
	  }
	)()
	  `.trim();
	}

	// Example usage:
	return obfuscateText( str);
}
Only give me a peek on the client.js file, upload the rest for download. Take your time and think out each function from a security standpoint. Make a small note on functions that can be encrypted. Any entangled runtime/post-runtime encryption/authentication please add. Add function integrity checks on runtime. Integrity checks and code-obfuscation should only be ran on the client

