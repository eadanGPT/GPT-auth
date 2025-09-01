
import mineflayer from 'mineflayer';
import { config } from '../config.js';

export function createBot({ host = process.env.MC_HOST || config.mcHost || 'localhost', port = parseInt(process.env.MC_PORT || '25565',10), version = process.env.MC_VERSION || '1.20.4', username='Bot' } = {}){
  const bot = mineflayer.createBot({ host, port, version, username });
  bot.once('spawn', ()=> console.log('[bot] spawned'));
  bot.on('health', ()=> console.log('[bot] health', bot.health, bot.food));
  bot.on('kicked', (r)=> console.log('[bot] kicked', r));
  bot.on('error', (e)=> console.log('[bot] error', e.message));
  return bot;
}
