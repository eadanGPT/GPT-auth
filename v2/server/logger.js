// server/logger.js
// File-based logger: never store logs in memory; rotate per-user dirs.

import fs from 'fs';
import path from 'path';

export class ServerLogger {
  constructor(cfg) {
    this.serverLog = cfg.logging.serverLog;
    this.authDir = cfg.logging.authLogDir;
    this.userDir = cfg.logging.userLogDir;
    fs.mkdirSync(path.dirname(this.serverLog), { recursive: true });
    fs.mkdirSync(this.authDir, { recursive: true });
    fs.mkdirSync(this.userDir, { recursive: true });
  }

  writeLine(file, line) {
    // Append a line to file synchronously to avoid buffering
    fs.appendFileSync(file, line + '\n', { encoding: 'utf8' });
  }

  server(level, msg) {
    // Server-level log with ISO timestamp
    const ts = new Date().toISOString();
    this.writeLine(this.serverLog, `${ts} ${level.toUpperCase()} ${msg}`);
  }

  auth(clientId, msg) {
    // Auth-level log to dedicated file
    const ts = new Date().toISOString();
    const f = `${this.authDir}/auth.log`;
    this.writeLine(f, `${ts} [${clientId || 'unknown'}] ${msg}`);
  }

  user(clientId, level, msg) {
    // Per-user log file
    const ts = new Date().toISOString();
    const f = `${this.userDir}/${clientId || 'unknown'}.log`;
    this.writeLine(f, `${ts} ${level.toUpperCase()} ${msg}`);
  }

  error(msg) {
    // Shortcut for error-level logs
    this.server('error', msg);
  }

  info(msg) {
    this.server('info', msg);
  }
}
