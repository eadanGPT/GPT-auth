
const state = { auth: '' };
const $ = (sel)=>document.querySelector(sel);
const app = $('#panel');
$('#setAuth').onclick = ()=>{
  state.auth = 'Basic '+($('#auth').value || '').trim();
  fetch('/admin/api/health',{headers:{Authorization:state.auth}}).then(r=>r.json()).then(()=>{
    $('.login').style.display='none'; app.style.display='block'; render('sessions');
  }).catch(()=>alert('Auth failed'));
};
document.querySelectorAll('nav a[data-tab]').forEach(a=>a.onclick=(e)=>{e.preventDefault(); render(a.dataset.tab)});

async function api(path, opts={}){
  const r = await fetch(path, Object.assign({ headers: { Authorization: state.auth } }, opts));
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

async function render(tab){
  if (tab==='sessions'){
    const d = await api('/admin/api/sessions');
    app.innerHTML = `<h2>Sessions</h2><table><thead><tr><th>Session</th><th>User</th><th>Key</th><th>IP</th><th>HB</th><th>OK/Fail</th><th>Last Seen</th><th></th></tr></thead><tbody>${
      d.sessions.map(s=>`<tr><td>${s.session_id}</td><td>${s.user_id}</td><td>${s.key_hash}</td><td>${s.ip}</td><td>${s.heartbeats}</td><td>${s.challenges_ok}/${s.challenges_fail}</td><td>${new Date(s.last_seen).toLocaleString()}</td><td><button data-disconnect="${s.session_id}">Disconnect</button></td></tr>`).join('')
    }</tbody></table>`;
    app.querySelectorAll('[data-disconnect]').forEach(b=>b.onclick=async()=>{ await api('/admin/api/sessions/'+b.dataset.disconnect+'/disconnect',{method:'POST'}); render('sessions'); });
  }
  if (tab==='keys'){
    const d = await api('/admin/api/keys');
    app.innerHTML = `<h2>Keys</h2>
    <form id="addKey"><input name="hash" placeholder="key hash"/><input name="owner" placeholder="owner user id"/><button>Add</button></form>
    <table><thead><tr><th>Key Hash</th><th>Owner</th><th>Blacklisted</th><th></th></tr></thead><tbody>${
      d.keys.map(k=>`<tr><td>${k.key_hash}</td><td>${k.owner_user_id||''}</td><td>${k.blacklisted}</td><td>
      <button data-bl="${k.key_hash}">Blacklist</button> <button data-del="${k.key_hash}">Remove</button></td></tr>`).join('')
    }</tbody></table>`;
    app.querySelector('#addKey').onsubmit=async(e)=>{ e.preventDefault(); const f=new FormData(e.target); await api('/admin/api/keys',{method:'POST',body:JSON.stringify({key_hash:f.get('hash'),owner_user_id:f.get('owner')}),headers:{'Content-Type':'application/json',Authorization:state.auth}}); render('keys'); };
    app.querySelectorAll('[data-bl]').forEach(b=>b.onclick=async()=>{ await api('/admin/api/keys/'+b.dataset.bl+'/blacklist',{method:'POST'}); render('keys'); });
    app.querySelectorAll('[data-del]').forEach(b=>b.onclick=async()=>{ await api('/admin/api/keys/'+b.dataset.del,{method:'DELETE'}); render('keys'); });
  }
  if (tab==='users'){
    const d = await api('/admin/api/users');
    app.innerHTML = `<h2>Users</h2><table><thead><tr><th>ID</th><th>Key</th><th>HWID</th><th>Banned</th><th></th></tr></thead><tbody>${
      d.users.map(u=>`<tr><td>${u.id}</td><td>${u.key_hash}</td><td>${u.hwid_perm}</td><td>${u.banned}</td>
      <td><button data-ban="${u.id}">Ban</button> <button data-unban="${u.id}">Unban</button> <button data-stats="${u.id}">Stats</button></td></tr>`).join('')
    }</tbody></table><div id="stats"></div>`;
    app.querySelectorAll('[data-ban]').forEach(b=>b.onclick=async()=>{ await api('/admin/api/users/'+b.dataset.ban+'/ban',{method:'POST'}); render('users'); });
    app.querySelectorAll('[data-unban]').forEach(b=>b.onclick=async()=>{ await api('/admin/api/users/'+b.dataset.unban+'/unban',{method:'POST'}); render('users'); });
    app.querySelectorAll('[data-stats]').forEach(b=>b.onclick=async()=>{ const s=await api('/admin/api/users/'+b.dataset.stats+'/stats'); document.getElementById('stats').textContent = JSON.stringify(s,null,2); });
  }
  if (tab==='logs'){
    const d = await api('/admin/api/logs?limit=300');
    app.innerHTML = `<h2>Logs</h2><pre style="white-space:pre-wrap">${d.logs.map(l=>`[${new Date(l.ts).toISOString()}] ${l.level} ${l.user_id||''} ${l.key_hash||''} ${l.hwid_perm||''} :: ${l.msg}`).join('\n')}</pre>`;
  }
  if (tab==='settings'){
    const st = await api('/admin/api/settings');
    app.innerHTML = `<h2>Settings</h2><form id="set"><label>Allow Connections <input type="checkbox" name="ac" ${st.allowConnections?'checked':''}></label>
    <label>Max Connections <input name="mc" type="number" value="${st.maxConnections}"></label><button>Save</button></form>`;
    app.querySelector('#set').onsubmit=async(e)=>{ e.preventDefault(); await api('/admin/api/settings',{method:'POST',headers:{'Content-Type':'application/json',Authorization:state.auth},body:JSON.stringify({allowConnections: e.target.ac.checked, maxConnections: Number(e.target.mc.value)})}); render('settings'); };
  }
}
