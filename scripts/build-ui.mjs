/**
 * BUILD THE BROWSER BUNDLE - without a bundler.
 *
 * The browser needs three things the CLI already has:
 *   1. the compiled engine, minus every module that touches Node
 *   2. tree-sitter's browser build
 *   3. the .wasm grammars, served over HTTP instead of read from node_modules
 *
 * There is exactly one transformation: the bare specifier `web-tree-sitter`
 * becomes a real URL. Browsers cannot resolve bare specifiers, and import maps
 * do not apply inside module workers - which is where our scan runs - so a
 * one-line rewrite is simpler and more honest than pulling in a bundler.
 *
 * NODE-ONLY MODULES ARE DELIBERATELY NOT COPIED. If the browser could import
 * scan.js or human.js, it eventually would, and the "one engine" promise would
 * rot from the inside. The list below is the seam, written down.
 */

import { cp, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);
const root = path.resolve(import.meta.dirname, '..');

/** Modules that only make sense on Node. The browser gets its own equivalents. */
const NODE_ONLY = new Set([
  'cli.js',
  'engine/scan.js',
  'engine/walk.js',
  'parse/node-grammars.js',
  'report/human.js',
  'report/json.js',
  'report/colors.js',
]);

/**
 * DERIVED FROM THE LANGUAGE REGISTRY, never typed.
 *
 * This was a hand-written list of seven names, and it went stale the moment C
 * and C++ were added: the CLI could scan them and the browser could not, which
 * quietly breaks the one promise this project makes about the two shells - that
 * they run the same engine. Nothing would have failed loudly. A .c file dropped
 * into the page would simply have been "unsupported", in a tool whose whole
 * pitch is that it tells you what it did not look at.
 *
 * It is the fifth hand-maintained list in this repository to go stale (see the
 * README counts, the benchmark headline, the escaper list and the test-path
 * list), so it is now computed from LANGUAGES - primary grammars plus every
 * dialect grammar - and adding a language can no longer forget the browser.
 */
const { LANGUAGES } = await import(new URL('../dist/src/parse/languages.js', import.meta.url));
const GRAMMARS = [
  ...new Set(
    LANGUAGES.flatMap((language) => [
      language.grammar,
      ...(language.dialects ?? []).map((dialect) => dialect.grammar),
    ]),
  ),
];

async function copyEngine(from, to, prefix = '') {
  await mkdir(to, { recursive: true });
  for (const entry of await readdir(from, { withFileTypes: true })) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      await copyEngine(path.join(from, entry.name), path.join(to, entry.name), relative);
      continue;
    }
    if (!entry.name.endsWith('.js')) continue; // skip .d.ts and source maps
    if (NODE_ONLY.has(relative)) continue;

    const source = await readFile(path.join(from, entry.name), 'utf8');
    await writeFile(
      path.join(to, entry.name),
      source.replaceAll("from 'web-tree-sitter'", "from '/vendor/web-tree-sitter/tree-sitter.js'"),
    );
  }
}

const engineOut = path.join(root, 'ui', 'engine');
await rm(engineOut, { recursive: true, force: true });
await copyEngine(path.join(root, 'dist', 'src'), engineOut);

// tree-sitter's own browser build + its runtime wasm.
// `web-tree-sitter` blocks subpath access to its package.json, so resolve the
// entry point it DOES export and walk up from there.
const treeSitterDir = path.dirname(require.resolve('web-tree-sitter'));
const vendorOut = path.join(root, 'ui', 'vendor', 'web-tree-sitter');
await mkdir(vendorOut, { recursive: true });
for (const file of ['tree-sitter.js', 'tree-sitter.wasm']) {
  await cp(path.join(treeSitterDir, file), path.join(vendorOut, file));
}

// the language grammars
const grammarSrc = path.join(
  path.dirname(require.resolve('tree-sitter-wasms/package.json')),
  'out',
);
const grammarOut = path.join(root, 'ui', 'grammars');
await mkdir(grammarOut, { recursive: true });
for (const grammar of GRAMMARS) {
  const name = `tree-sitter-${grammar}.wasm`;
  await cp(path.join(grammarSrc, name), path.join(grammarOut, name));
}

console.log(
  `ui/ built: engine (minus ${NODE_ONLY.size} Node-only modules), ` +
    `tree-sitter runtime, ${GRAMMARS.length} grammars`,
);
