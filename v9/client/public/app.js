
(async function(){
  const licenseDiv = document.getElementById('license');
  const key = localStorage.getItem('client_key') || '';
  if (!key) {
    const form = document.createElement('form');
    form.innerHTML = `<input id="k" placeholder="License Key"/><button>Claim</button>`;
    form.onsubmit = (e)=>{
      e.preventDefault();
      const v = document.getElementById('k').value.trim();
      if (!v) return;
      localStorage.setItem('client_key', v);
      location.reload();
    };
    licenseDiv.appendChild(form);
  } else {
    licenseDiv.textContent = 'Client key present';
  }

  // live view
  const live = document.getElementById('live');
  const ws = new WebSocket(`ws://${location.host}/live`);
  ws.onmessage = (e)=> live.textContent = e.data;

  document.getElementById('refresh').onclick = async ()=>{
    const res = await fetch('/api/inventory').then(r=>r.json());
    const ul = document.getElementById('inv'); ul.innerHTML='';
    res.items.forEach(it=>{
      const li = document.createElement('li'); li.textContent = `${it.count}x ${it.name} (#${it.slot})`; ul.appendChild(li);
    });
  };
})();
