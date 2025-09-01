
import { Server } from 'ws';

export function attachLiveView(server, bot){
  const wss = new Server({ server, path: '/live' });
  function snapshot(){
    return JSON.stringify({
      pos: bot.entity?.position,
      health: bot.health, food: bot.food,
      time: Date.now()
    });
  }
  setInterval(()=>{
    const frame = snapshot();
    for (const ws of wss.clients) { try { ws.send(frame); } catch {} }
  }, 1000);
}
