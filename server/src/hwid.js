
import crypto from 'node:crypto';
export function permHWID({ cpu, mem, os, hostname, net }) {
  const payload = JSON.stringify({ cpu, mem, os, hostname, net });
  return crypto.createHash('sha256').update(payload).digest('hex');
}
export function tempHWID({ ips, boot }) {
  const payload = JSON.stringify({ ips, boot });
  return crypto.createHash('sha256').update(payload).digest('hex');
}
