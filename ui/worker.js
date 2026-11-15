/**
 * THE BROWSER SHELL.
 *
 * The mirror image of src/engine/scan.ts. That one walks a directory and reads
 * bytes off a disk; this one receives files a person dropped onto a page. Both
 * then call exactly the same `analyze()` - not a port of it, not a subset, the
 * same compiled module.
 *
 * It runs in a Web Worker because a scan is CPU-bound: parsing a few hundred
 * files on the main thread would freeze the tab, and a frozen tab looks broken
 * even when the analysis is going perfectly.
 */

import { Parser } from '/vendor/web-tree-sitter/tree-sitter.js';
import { configureParsing } from '/engine/parse/parser.js';
import { analyze } from '/engine/core/analyze.js';
import { scoreAnalysis } from '/engine/core/score.js';
import { ENGINE_CAPABILITIES } from '/engine/core/finding.js';
import { checkRuntimeVersions, runtimeFileKind } from '/engine/platform/runtime-version.js';

// The one place the browser differs from Node: grammars arrive over HTTP
// instead of being read out of node_modules.
configureParsing({
  init: () => Parser.init({ locateFile: (file) => `/vendor/web-tree-sitter/${file}` }),
  loadGrammar: (grammar) => `/grammars/tree-sitter-${grammar}.wasm`,
});

self.addEventListener('message', async (event) => {
  const { files, options } = event.data ?? {};
  if (!Array.isArray(files)) return;

  try {
    // Same split as src/engine/scan.ts: declarations go to the runtime version
    // check, everything else to analyze().
    const isRuntime = (f) => runtimeFileKind(f.path.split('/').pop() ?? '') !== null;
    const sourceFiles = files.filter((f) => !isRuntime(f));
    const analysis = await analyze(sourceFiles, {
      /**
       * A quarter of the terminal's tree budget, because a browser tab is not
       * a terminal. Chrome gives a WebAssembly heap a hard limit and reaching
       * it is not a slow scan, it is a dead tab with no report in it - so the
       * shell that can afford the failure least gets the smallest budget. A
       * project too big for it is parsed more than once and takes longer,
       * which is the trade this whole design exists to make.
       */
      treeBudgetBytes: 256 * 1024 * 1024,
      ...(options ?? {}),
      onProgress: (done, total, file) => {
        self.postMessage({ type: 'progress', done, total, file });
      },
    });
    const runtimeVersions = checkRuntimeVersions(
      files.filter(isRuntime).map((f) => ({ path: f.path, text: f.source })),
      { today: new Date().toISOString().slice(0, 10), phpFilesScanned: analysis.byLanguage['php'] ?? 0 },
    );
    const result = {
      ...analysis,
      findings: [...analysis.findings, ...runtimeVersions.findings],
      runtimeVersions,
    };
    // Scored HERE, not on the page. The gauge numbers are analysis output like
    // any finding - if app.js computed them, the browser could show a score the
    // terminal never would, and the one-engine promise would be half true.
    self.postMessage({
      type: 'done',
      result: { ...result, score: scoreAnalysis(result, sourceFiles.length) },
    });
  } catch (error) {
    self.postMessage({
      type: 'error',
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
  }
});

self.postMessage({ type: 'ready', engine: ENGINE_CAPABILITIES });
