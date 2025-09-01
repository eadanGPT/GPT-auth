
// server/cli.js
import readline from 'readline';
import boxen from 'boxen';
import chalk from 'chalk';
import { adminState } from './admin_state.js';
import { db } from './db.js';

const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: chalk.cyan('> ') });

let running = true;
function fmtTime(ms){
  const s = Math.max(0, Math.floor(ms/1000));
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
  return `${h}h ${m}m ${sec}s`;
}
const bootAt = Date.now();

function drawHeader(){
  const meta = adminState.getMeta();
  const left = `${chalk.bold('Secure WS Admin CLI')}\n` +
               `Uptime: ${fmtTime(Date.now()-bootAt)}\n` +
               `DB Rows: logs(${db.prepare('SELECT COUNT(*) AS n FROM logs').get().n}) sessions(${db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n})`;
  const right = `${chalk.yellow('Admin Web Password')}\n${chalk.bold(meta.password)}\n` +
                `Rotates in: ${fmtTime(meta.nextRotationAt - Date.now())}`;
  const content = left + '\n' + right;
  const bx = boxen(content, { padding: 1, title: 'Control', borderColor: 'magenta', borderStyle: 'round' });
  process.stdout.write('\x1Bc'); // clear
  console.log(bx);
  console.log(chalk.gray('Commands: sessions list | sessions disconnect <id> | keys add <license> <owner> | settings rotate-admin-pass | help | quit'));
  rl.prompt(true);
}

setInterval(drawHeader, 1000).unref();
adminState.on('rotated', drawHeader);
drawHeader();

function handle(cmd){
  const [a,b,c,d] = cmd.trim().split(/\s+/);
  if (!a) return;
  if (a==='quit' || a==='exit') { running=false; rl.close(); process.exit(0); }
  if (a==='help') {
    console.log('sessions list | sessions disconnect <id> | keys add <license> <owner> | settings rotate-admin-pass');
    return;
  }
  if (a==='settings' && b==='rotate-admin-pass') {
    adminState.rotate(true); return;
  }
  if (a==='sessions' && b==='list') {
    const rows = db.prepare('SELECT * FROM sessions WHERE active=1').all();
    console.table(rows);
    return;
  }
  if (a==='sessions' && b==='disconnect' && c) {
    db.prepare('UPDATE sessions SET active=0 WHERE id=?').run(c);
    console.log('OK'); return;
  }
  if (a==='keys' && b==='add' && c && d) {
    db.prepare('INSERT OR REPLACE INTO keys(license_key, owner, created_at) VALUES (?,?,?)').run(c,d,Date.now());
    console.log('OK'); return;
  }
  console.log('Unknown command');
}

rl.on('line', (line)=> { handle(line); drawHeader(); });
