
import os from 'node:os';
import crypto from 'node:crypto';
export function getPermanentHWID(){
  const cpu = os.cpus()?.map(c=>c.model).join('|')||'';
  const mem = os.totalmem();
  const ost = `${os.platform()}-${os.release()}`;
  const host = os.hostname();
  const net = Object.values(os.networkInterfaces()).flat().map(n=>n?.mac).filter(Boolean).join('|');
  return crypto.createHash('sha256').update(JSON.stringify({cpu,mem,ost,host,net})).digest('hex');
}
export function getTemporaryHWID(){
  const ips = Object.values(os.networkInterfaces()).flat().map(n=>n?.address).filter(Boolean).join('|');
  const boot = Date.now() - os.uptime()*1000;
  return crypto.createHash('sha256').update(JSON.stringify({ips,boot})).digest('hex');
}
