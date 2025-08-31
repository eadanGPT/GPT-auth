// server/cli.js
// Interactive CLI: add keys, view unused keys, view active, ban/unban, disconnect, exit & save.

import readline from 'readline';

export function startCLI(db, sessions, logger) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, prompt: '> ' });
  logger.info('CLI ready: commands = addkey, listunused, active, ban <clientId>, unban <clientId>, disconnect <sessionId>, listclients, exit');

  rl.prompt();
  rl.on('line', (line) => {
    try {
      const [cmd, ...args] = line.trim().split(/\s+/);
      if (!cmd) return rl.prompt();

      if (cmd === 'addkey') {
        const newKey = cryptoRandomKey();
        db.stmts.addKey.run(newKey, Date.now());
        db.criticalSaveBackup('addkey');
        logger.info(`New key added: ${newKey}`);
        console.log(newKey);
      } else if (cmd === 'listunused') {
        const rows = db.stmts.listUnused.all();
        console.table(rows);
      } else if (cmd === 'active') {
        console.table(sessions.listActive());
      } else if (cmd === 'ban') {
        const id = args[0];
        db.stmts.banClient.run(id);
        logger.info(`Client banned: ${id}`);
      } else if (cmd === 'unban') {
        const id = args[0];
        db.stmts.unbanClient.run(id);
        logger.info(`Client unbanned: ${id}`);
      } else if (cmd === 'disconnect') {
        const sid = args[0];
        sessions.deactivate(sid);
        logger.info(`Disconnected session ${sid}`);
      } else if (cmd === 'listclients') {
        console.table(db.stmts.listClients.all());
      } else if (cmd === 'exit') {
        logger.info('Exit & save requested.');
        process.exit(0);
      } else {
        console.log('Unknown command');
      }
    } catch (e) {
      logger.error(`CLI error: ${e.message}`);
    } finally {
      rl.prompt();
    }
  });
}

function cryptoRandomKey() {
  // Generate a 32-byte base64url key
  return Buffer.from(require('crypto').randomBytes(32)).toString('base64url');
}
