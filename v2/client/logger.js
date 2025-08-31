// client/logger.js
// Client logger writing directly to files, no in-memory buffering.

import fs from 'fs';
import path from 'path';

export class ClientLogger {
  constructor(cfg) {
    this.dir = cfg.logging.logDir;
    fs.mkdirSync(this.dir, { recursive: true });
  }
  write(file, line) {
    fs.appendFileSync(file, line + '\n', { encoding: 'utf8' });
  }
  log(level, msg) {
    const f = path.join(this.dir, 'client.log');
    const ts = new Date().toISOString();
    this.write(f, `${ts} ${level.toUpperCase()} ${msg}`);
  }
  auth(msg) { this.log('auth', msg); }
  info(msg) { this.log('info', msg); }
  error(msg) { this.log('error', msg); }
}
