// logger.js
// Disk-only logger with levels: auth, log, error.

const fs = require('fs');
const path = require('path');

class Logger {
  constructor(baseDir) {
    this.baseDir = baseDir;
    if (!fs.existsSync(baseDir)) fs.mkdirSync(baseDir, { recursive: true });
  }

  write(level, msg) {
    const file = path.join(this.baseDir, `${level}.log`);
    const line = `[${new Date().toISOString()}] ${msg}\n`;
    fs.appendFile(file, line, () => {});
  }

  auth(msg) { this.write('auth', msg); }
  log(level, msg) { this.write(level, msg); }
  error(level, msg) { this.write(level, msg); }
}

module.exports = Logger;
