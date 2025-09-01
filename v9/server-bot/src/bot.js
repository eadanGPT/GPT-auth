
import mineflayer from 'mineflayer';
import { config } from './config.js';

export function createServerSideBot(){
  const bot = mineflayer.createBot({
    host: config.mcHost,
    port: config.mcPort,
    version: config.mcVersion,
    username: config.botName
  });
  bot.once('spawn', ()=> console.log('[server-bot] spawned'));
  bot.on('health', ()=> console.log('[server-bot] health', bot.health, bot.food));
  bot.on('kicked', (r)=> console.log('[server-bot] kicked', r));
  bot.on('error', (e)=> console.log('[server-bot] error', e.message));
  return bot;
}
