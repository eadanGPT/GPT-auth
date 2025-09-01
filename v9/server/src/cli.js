
import chalk from 'chalk';
import readline from 'node:readline';
import { getAdminState, rotateAdminPassword } from './admin.js';
import { setInterval } from 'node:timers';

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
rl.setPrompt('> ');

function header() {
  const { adminPassword, adminPasswordExpiresAt } = getAdminState();
  const left = Math.max(0, Math.floor((adminPasswordExpiresAt - Date.now())/1000));
  console.clear();
  console.log(chalk.bold.cyan('Secure WS Server CLI'));
  console.log(chalk.gray(`Admin password: ${adminPassword} | rotates in: ${left}s`));
  console.log(chalk.gray('Commands: rotate, help, exit'));
  rl.prompt();
}

setInterval(header, 1000);
header();

rl.on('line', (line)=>{
  const cmd = line.trim();
  if (cmd === 'rotate') rotateAdminPassword();
  else if (cmd === 'help') console.log('rotate, help, exit');
  else if (cmd === 'exit') process.exit(0);
  rl.prompt();
});
