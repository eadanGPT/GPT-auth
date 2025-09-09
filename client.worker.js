// client.worker.js — sandboxed module runner
import { parentPort, workerData } from 'node:worker_threads';
import vm from 'node:vm';
import crypto from 'node:crypto';
import module_ from 'node:module';

const { createRequire } = module_;
const hostRequire = createRequire(import.meta.url);

function verifyContextSig(ctx) {
  const { sig, ...bare } = ctx || {};
  if (!sig || !ctx?.pub) return false;
  const data = Buffer.from(JSON.stringify(bare));
  const sigBuf = Buffer.from(sig, 'base64');
  const key = crypto.createPublicKey(ctx.pub);
  return crypto.verify(null, data, key, sigBuf);
}

function makeSandboxRequire(perms) {
  const ALLOW = new Set(perms.allowModules || []);
  const CORE_OK = new Set(['events','buffer','node:path','path']);
  const DENY_CORE = new Set([
    'fs','node:fs','child_process','node:child_process',
    'vm','node:vm','worker_threads','node:worker_threads',
    'net','node:net','tls','node:tls','http','node:http',
    'https','node:https','dgram','node:dgram','cluster','node:cluster',
    'process','node:process','os','node:os','perf_hooks','node:perf_hooks',
    'async_hooks','node:async_hooks'
  ]);
  return new Proxy(hostRequire, {
    apply(_t,_this,args){
      const request = String(args[0]||'');
      if (DENY_CORE.has(request)) throw new Error(`Denied core module: ${request}`);
      if (CORE_OK.has(request)) return hostRequire(request);
      if (!ALLOW.has(request)) throw new Error(`Module not allowed by policy: ${request}`);
      return hostRequire(request);
    }
  });
}

(async function (){
  try {
    const { moduleId, moduleCodeB64, moduleContext } = workerData || {};
    if (!moduleId || !moduleCodeB64 || !moduleContext) {
      return parentPort.postMessage({ ok:false, error:'missing workerData' });
    }
    if (!verifyContextSig(moduleContext)) {
      return parentPort.postMessage({ ok:false, error:'invalid context signature' });
    }
    if (moduleContext.exp && moduleContext.exp < Date.now()) {
      return parentPort.postMessage({ ok:false, error:'context expired' });
    }
    const codeBuf = Buffer.from(moduleCodeB64, 'base64');
    const hash = crypto.createHash('sha256').update(codeBuf).digest('hex');
    if (moduleContext.hash && moduleContext.hash !== hash) {
      return parentPort.postMessage({ ok:false, error:'module hash mismatch' });
    }
    const perms = Object.assign({ fs:false, env:false, child_process:false, allowModules:[], network:[] }, moduleContext.permissions || {});
    const safeProcess = {
      argv: [], execArgv: [], pid: process.pid,
      versions: Object.freeze({ node: process.versions.node }),
      env: perms.env ? Object.freeze(process.env) : Object.freeze({})
    };
    const sandbox = {
      module: { exports: {} },
      exports: {},
      Buffer,
      console,
      setTimeout, setInterval, clearTimeout, clearInterval,
      require: makeSandboxRequire(perms),
      process: safeProcess
    };
    vm.createContext(sandbox);
    const code = codeBuf.toString('utf8');
    vm.runInContext(code, sandbox, { filename: `${moduleId}.js`, timeout: 10000 });
    parentPort.postMessage({ ok:true, msg:`Module "${moduleId}" loaded` });
    parentPort.on('message', async (cmd)=>{
      try{
        const mod = sandbox.module?.exports || {};
        const fn = typeof mod.run==='function' ? mod.run : mod.onCommand;
        if (!fn) return parentPort.postMessage({ ok:false, error:'No run()/onCommand()' });
        const res = await fn(cmd);
        parentPort.postMessage({ ok:true, result:res });
      }catch(e){ parentPort.postMessage({ ok:false, error:String(e.message||e) }); }
    });
  } catch(e){
    parentPort.postMessage({ ok:false, error:String(e.message||e) });
  }
})();
