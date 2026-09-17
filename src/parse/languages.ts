/**
 * LANGUAGE REGISTRY
 * =================
 *
 * A scanner has to answer "what language is this file?" before it can answer
 * "is this file dangerous?". This file is the single place that knows.
 *
 * ARCHITECTURAL DECISION (matters in Phase 5, language expansion):
 * languages are DATA, not code. Adding Ruby later means adding one object to
 * the array below plus one query file per rule - it does not mean editing the
 * parser, the engine, the CLI, or any existing rule. If adding a language ever
 * requires touching the engine, we designed it wrong.
 *
 * WHY WASM GRAMMARS INSTEAD OF NATIVE ONES:
 * Tree-sitter ships two ways to run a grammar - a native C module you compile
 * on your machine, or a WebAssembly (.wasm) file that runs anywhere. We chose
 * WASM for three reasons:
 *   1. No compiler toolchain needed. `npm install` just works, on any OS.
 *   2. The SAME grammar files run in a browser. Phase 2 is a browser UI - it
 *      will run this identical engine instead of a reimplementation of it.
 *   3. The tree-sitter-wasms package already ships 36 grammars, so Phase 5's
 *      language expansion is mostly unlocking files we already have on disk.
 */

/** The languages NS-1 supports. */
export type LanguageId =
  | 'javascript'
  | 'typescript'
  | 'python'
  | 'java'
  | 'go'
  | 'php'
  | 'c'
  | 'cpp';

export interface Dialect {
  /** File extensions handled by this dialect. */
  readonly extensions: readonly string[];
  /** Grammar name inside tree-sitter-wasms, i.e. tree-sitter-<name>.wasm */
  readonly grammar: string;
}

export interface LanguageSpec {
  readonly id: LanguageId;
  readonly displayName: string;
  /** Primary extensions -> primary grammar. */
  readonly extensions: readonly string[];
  readonly grammar: string;
  /**
   * Variants of the same language that need a DIFFERENT grammar file but share
   * rules. e.g. .tsx needs the tsx grammar, but a SQL-injection rule written for
   * TypeScript matches .tsx code perfectly well.
   */
  readonly dialects?: readonly Dialect[];
  /** Interpreter names seen in a `#!` shebang line, for extensionless scripts. */
  readonly shebangs?: readonly string[];
  /** Honest notes about what this language's support does and does not include. */
  readonly notes: string;
}

export const LANGUAGES: readonly LanguageSpec[] = [
  {
    id: 'javascript',
    displayName: 'JavaScript',
    extensions: ['.js', '.mjs', '.cjs', '.jsx'],
    grammar: 'javascript',
    shebangs: ['node'],
    notes:
      'The javascript grammar parses JSX natively, so .jsx needs no separate grammar. ' +
      'Vue/Svelte single-file components are NOT supported - their <script> blocks are ' +
      'not extracted. Documented gap, not a silent one.',
  },
  {
    id: 'typescript',
    displayName: 'TypeScript',
    extensions: ['.ts', '.mts', '.cts'],
    grammar: 'typescript',
    dialects: [{ extensions: ['.tsx'], grammar: 'tsx' }],
    notes:
      'Type annotations are parsed but NOT used for analysis. Knowing that ' +
      'a parameter is typed `string` tells us nothing about whether it is attacker-' +
      'controlled, so we deliberately do not pretend it does. .d.ts files are skipped.',
  },
  {
    id: 'python',
    displayName: 'Python',
    extensions: ['.py', '.pyi'],
    grammar: 'python',
    shebangs: ['python', 'python2', 'python3'],
    notes:
      'Python 3 grammar. Python 2 print-statements will produce parse errors, which we ' +
      'report rather than swallow.',
  },
  {
    id: 'java',
    displayName: 'Java',
    extensions: ['.java'],
    grammar: 'java',
    notes:
      'Plain Java only. .jsp, .kt (Kotlin) and .scala are separate languages and are not ' +
      'covered by these rules even though a Java-ish pattern might appear in them.',
  },
  {
    id: 'php',
    displayName: 'PHP',
    extensions: ['.php', '.phtml'],
    grammar: 'php',
    notes:
      'PHP source only. A .php file is parsed as a whole document, so HTML outside ' +
      '<?php ?> is text rather than markup - an XSS sink written in raw HTML with a ' +
      'short echo tag (<?= $x ?>) IS matched, but HTML attributes around it are not ' +
      'analysed. Blade (.blade.php) and Twig (.twig) templates are NOT parsed.',
  },
  {
    id: 'go',
    displayName: 'Go',
    extensions: ['.go'],
    grammar: 'go',
    notes:
      'Go source only; go.mod, go.sum and generated protobuf files are skipped as noise.',
  },
  {
    id: 'c',
    displayName: 'C',
    extensions: ['.c'],
    grammar: 'c',
    notes:
      'MEMORY SAFETY IS NOT ANALYSED. C is famous for buffer overflows, use-after-free, ' +
      'double-free and integer overflow, and this engine models none of them - it tracks ' +
      'values, not sizes, allocations or pointer aliasing. What IS analysed is the same ' +
      'thing analysed in every other language: attacker-controlled data reaching a ' +
      'dangerous call. In C that means shells (system, popen, exec*), format strings ' +
      '(printf-family, where a tainted FORMAT argument is CWE-134 and a taint engine ' +
      'catches it exactly), and copies with no length bound (strcpy, strcat, sprintf, ' +
      'gets). A finding that data reaches an unbounded copy is NOT a claim that the ' +
      'destination is too small - that needs size analysis we do not have - so the ' +
      'wording says "reaches a copy with no length bound" and means only that. ' +
      'THE PREPROCESSOR IS NOT RUN: #include is not followed, #ifdef branches are all ' +
      'parsed as though taken, and a macro that hides a sink (#define RUN(x) system(x)) ' +
      'is invisible.',
  },
  {
    id: 'cpp',
    displayName: 'C++',
    extensions: ['.cpp', '.cc', '.cxx', '.c++', '.hpp', '.hh', '.hxx', '.h'],
    grammar: 'cpp',
    notes:
      'Every C limitation applies, plus: templates are parsed but not instantiated, so a ' +
      'sink reached only through a template specialisation is missed, and operator ' +
      'overloading is not resolved - a custom operator<< that executes a command reads ' +
      'as an ordinary stream write. ' +
      'THE .h EXTENSION IS TREATED AS C++, deliberately and against appearances. It is ' +
      'ambiguous - most .h files in the world are C - but the two grammars are not ' +
      'symmetric: measured on this project\'s own fixtures, the C++ grammar parses C ' +
      'with zero error nodes while the C grammar produces eleven on C++. Choosing the ' +
      'superset costs a C project a cosmetic mislabel in the per-language counts; ' +
      'choosing C would cost a C++ header every std:: sink in it, silently. A wrong ' +
      'label is better than a missing finding.',
  },
];

const BY_ID = new Map<LanguageId, LanguageSpec>(LANGUAGES.map((l) => [l.id, l]));

/** Extension -> { language, grammar-to-use }. Built once at module load. */
const BY_EXTENSION = new Map<string, { spec: LanguageSpec; grammar: string }>();
for (const spec of LANGUAGES) {
  for (const ext of spec.extensions) {
    BY_EXTENSION.set(ext, { spec, grammar: spec.grammar });
  }
  for (const dialect of spec.dialects ?? []) {
    for (const ext of dialect.extensions) {
      BY_EXTENSION.set(ext, { spec, grammar: dialect.grammar });
    }
  }
}

export interface LanguageMatch {
  readonly spec: LanguageSpec;
  /** Which .wasm grammar to actually load (may differ from spec.grammar for dialects). */
  readonly grammar: string;
  /** How we decided. Reported in --json so detection is auditable, never magic. */
  readonly detectedBy: 'extension' | 'shebang';
}

/** Files we never scan, because scanning them is noise, not security. */
const SKIP_FILE_PATTERNS: readonly RegExp[] = [
  /\.d\.ts$/,
  /\.min\.js$/,
  /\.bundle\.js$/,
  /\.pb\.go$/,
  /_pb2\.py$/,
  /\.generated\./,
];

/**
 * Decide which language a file is.
 *
 * Step 1: file extension. Boring, fast, right ~99% of the time.
 * Step 2: if there is no useful extension, read the first line and look for a
 *         "shebang" - the `#!/usr/bin/env python3` line that tells Unix which
 *         interpreter to run. This is how we catch a CLI script named `deploy`
 *         with no extension at all.
 *
 * Returns null for "we don't handle this", which is a normal answer, not an error.
 */
export function detectLanguage(filePath: string, firstLine?: string): LanguageMatch | null {
  const lower = filePath.toLowerCase();

  for (const pattern of SKIP_FILE_PATTERNS) {
    if (pattern.test(lower)) return null;
  }

  const dot = lower.lastIndexOf('.');
  const slash = Math.max(lower.lastIndexOf('/'), lower.lastIndexOf('\\'));
  if (dot > slash) {
    const hit = BY_EXTENSION.get(lower.slice(dot));
    if (hit) return { spec: hit.spec, grammar: hit.grammar, detectedBy: 'extension' };
  }

  if (firstLine?.startsWith('#!')) {
    // "#!/usr/bin/env python3" -> we want the word "python3"
    const words = firstLine.slice(2).trim().split(/[\s/]+/);
    for (const spec of LANGUAGES) {
      if (spec.shebangs?.some((s) => words.includes(s))) {
        return { spec, grammar: spec.grammar, detectedBy: 'shebang' };
      }
    }
  }

  return null;
}

export function languageById(id: LanguageId): LanguageSpec {
  const spec = BY_ID.get(id);
  if (!spec) throw new Error(`Unknown language id: ${id}`);
  return spec;
}

/** Every extension we will attempt to open. Used by the file walker. */
export const SCANNABLE_EXTENSIONS: readonly string[] = [...BY_EXTENSION.keys()];
