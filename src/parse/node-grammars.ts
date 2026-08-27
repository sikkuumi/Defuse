/**
 * THE NODE SHELL for grammar loading and file reading.
 *
 * Everything in here is the half of the tool that only makes sense on a
 * machine with a filesystem. The browser has its own equivalent in
 * ui/worker.js, and the analysis code in between never learns which one it got.
 */

import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { configureParsing, parseSourceFile, type ParseOutcome } from './parser.js';

const require = createRequire(import.meta.url);

/** Folder inside node_modules that holds the prebuilt .wasm grammar files. */
const GRAMMAR_DIR = path.join(
  path.dirname(require.resolve('tree-sitter-wasms/package.json')),
  'out',
);

/** Point the parser at node_modules. Called once, before any scan. */
export function useNodeGrammars(): void {
  configureParsing({
    loadGrammar: (grammar) => path.join(GRAMMAR_DIR, `tree-sitter-${grammar}.wasm`),
  });
}

/** Read a file off disk, then hand the text to the platform-agnostic parser. */
export async function parseFile(filePath: string): Promise<ParseOutcome> {
  try {
    const source = await readFile(filePath, 'utf8');
    return parseSourceFile(filePath, source);
  } catch (error) {
    return {
      status: 'skipped',
      path: filePath,
      reason: `unreadable: ${(error as Error).message}`,
    };
  }
}
