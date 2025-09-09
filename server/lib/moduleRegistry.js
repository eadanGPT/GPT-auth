import fs from 'node:fs';
import path from 'node:path';
import bytenode from 'bytenode';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

const srcDir = 'server/modules';
const manifestPath = path.join('server', 'modules.manifest.json');

let MODULES = {};
try {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const names = (manifest.modules || []).map(m => m.name);
  for (const name of names) {
    const jsc = path.join(srcDir, name + '.jsc');
    const js = path.join(srcDir, name + '.js');
    if (fs.existsSync(jsc)) MODULES[name] = jsc;
    else if (fs.existsSync(js)) MODULES[name] = js;
  }
} catch {
  MODULES = {};
}

export async function ensureCompiled() {
  const entries = fs.readdirSync(srcDir).filter(f => f.endsWith('.js'));
  for (const f of entries) {
    const inPath = path.join(srcDir, f);
    const outPath = path.join(srcDir, f.replace(/\.js$/, '.jsc'));
    if (!fs.existsSync(outPath)) {
      await bytenode.compileFile({ filename: inPath, output: outPath });
    }
  }
  MODULES = Object.fromEntries(
    entries.map(f => [f.replace(/\.js$/, ''), path.join(srcDir, f.replace(/\.js$/, '.jsc'))])
  );
}

export const ModuleRegistry = {
  listModules() {
    return Object.keys(MODULES);
  },
  loadCompiled(moduleId) {
    const p = MODULES[moduleId];
    if (!p) throw new Error('Unknown moduleId');
    if (!fs.existsSync(p)) throw new Error('Module file not found: ' + p);
    return require(path.resolve(p));
  }
};

export function verifyRpcChunks(manifestEntry, providedChunks) {
  if (!manifestEntry?.rpc_chunks) return true;
  return manifestEntry.rpc_chunks.every(c => providedChunks.includes(c));
}
export default { verifyRpcChunks, ModuleRegistry, ensureCompiled };
