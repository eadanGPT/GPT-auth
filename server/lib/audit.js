import fs from 'node:fs';
import path from 'node:path';
import chalk from 'chalk';

const AUDIT_FILE = path.join(process.cwd(), 'server', 'audit.log');

function writeEntry(entry) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n";
  fs.appendFileSync(AUDIT_FILE, line);
}

/**
 * Generic log entry
 * @param {string} type - event type (e.g. "admin.rotateLogs")
 * @param {object} data - arbitrary payload (merged into log entry)
 */
 
function typeParser(type) {
  if (/debug/i.test(type)) return chalk.blue;
  if (/log/i.test(type)) return chalk.white;
  if (/error/i.test(type)) return chalk.magenta;
  if (/warning/i.test(type)) return chalk.yellow;
  return chalk.white;
}
export function log(type, data = {}) {
  writeEntry({ type, ...data });
  console.log(typeParser(type)(type), (typeof(data) == 'object' && JSON.stringify(data) || typeof(data) == 'array' && JSON.stringify(data) || data));
}

/**
 * Read audit log
 * @param {object} options
 * @param {string|null} options.type - filter by type
 * @param {Date|null} options.since - filter by timestamp
 */
export function readLog({ type = null, since = null } = {}) {
  if (!fs.existsSync(AUDIT_FILE)) return [];
  const lines = fs.readFileSync(AUDIT_FILE, 'utf8').trim().split(/\n/);
  return lines
    .map(l => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .filter(e => {
      if (type && e.type !== type) return false;
      if (since && new Date(e.ts) < since) return false;
      return true;
    });
}

/**
 * Clear audit log (dangerous!)
 */
export function clearLog() {
  if (fs.existsSync(AUDIT_FILE)) fs.writeFileSync(AUDIT_FILE, '');
}

export default { log, readLog, clearLog };
