import fs from 'node:fs';
import path from 'node:path';
import bytenode from 'bytenode';
import { fileURLToPath } from 'node:url';

const srcDir = 'server/modules';
const outDir = 'server/modules';
fs.mkdirSync(outDir, { recursive: true });

const entries = fs.readdirSync(srcDir).filter(f=>f.endsWith('.js'));
for (const f of entries) {
  const inPath = path.join(srcDir, f);
  const outPath = path.join(outDir, f.replace(/\.js$/, '.jsc'));
  await bytenode.compileFile({ filename: inPath, output: outPath });
  console.log('Compiled', inPath, '->', outPath);
}
