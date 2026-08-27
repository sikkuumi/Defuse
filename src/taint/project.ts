/**
 * THE PROJECT INDEX  (cross-file resolution)
 * ==========================================
 *
 * Up to now the tracer could follow a value anywhere inside one file and no
 * further. `helper(dirty)` where `helper` lives in `./helpers.js` was the end of
 * the road, and on real code that is where most of the road is: applications put
 * their database access in `db.js`, their escaping in `util/html.py`, their
 * command runners in `Shell.java`.
 *
 * This module answers one question: **"file F calls a function named N - which
 * file, if any, is that?"**
 *
 * THE RULE IT PLAYS BY: answer only when the answer is unambiguous.
 *
 * If two imported modules both define `sanitize`, we say nothing and record
 * that we declined. Picking one at random would let the tool print a
 * step-by-step "proof" through a function that never runs - which is worse than
 * printing nothing, because it looks like evidence. The count of declined
 * resolutions is reported in every scan.
 *
 * HOW IMPORTS ARE FOUND, per language:
 *
 *   JS/TS   `import x from './a'` and `require('./a')`, resolved relative to the
 *           importing file, trying the usual extensions and `/index`.
 *   Python  `from .a import x`, `from pkg.a import x`, `import pkg.a` - resolved
 *           against the files actually present in the scan.
 *   Java    `import com.x.Bar;` resolves to a file named `Bar.java`, PLUS every
 *           file in the same directory, because Java classes in the same
 *           package see each other with no import at all.
 *   Go      every file in the same directory, because that is one package. Go
 *           imports name packages rather than files, and resolving those needs
 *           module metadata we do not read.
 *
 * WHAT IT DOES NOT DO, stated here and in the scan report:
 *   - It does not check that the function is actually EXPORTED. A module-private
 *     helper with the same name as an exported one could be entered.
 *   - It does not follow re-exports (`export * from './a'`).
 *   - It does not resolve node_modules, third-party packages, or aliases from
 *     tsconfig `paths` / webpack config.
 *   - Dynamic imports and computed requires are invisible.
 */

import type { Node } from 'web-tree-sitter';
import { basenameOf, dirnameOf, joinPath, resolveFrom, toPosix } from '../core/paths.js';
import type { LanguageId } from '../parse/languages.js';
import type { ParsedFile } from '../parse/parser.js';
import { collectFunctions, type CrossFileResolver, type LocalFunction } from './tracer.js';

interface IndexedFile {
  /** The path exactly as the shell gave it to us - what reports will show. */
  readonly path: string;
  /** The same path, slashes normalised. All comparisons use this one. */
  readonly posix: string;
  readonly directory: string;
  readonly language: LanguageId;
  readonly functions: Map<string, LocalFunction>;
  /** Absolute paths of files this one imports, as far as we could resolve them. */
  readonly imports: Set<string>;
}

export interface ProjectIndexStats {
  readonly filesIndexed: number;
  readonly functionsIndexed: number;
  readonly importEdges: number;
  /** Times a cross-file call WAS followed. */
  readonly resolved: number;
  /** Times several files defined the name and we refused to choose. */
  readonly ambiguous: number;
}

export interface ProjectIndex extends CrossFileResolver {
  readonly stats: () => ProjectIndexStats;
}

/* -------------------------------------------------------------------------- *
 * Import extraction - from the syntax tree, not from a text search, for the
 * same reason the rules use the tree: a `require('./db')` inside a comment or a
 * string is not an import.
 * -------------------------------------------------------------------------- */

const IMPORT_NODES: Record<LanguageId, readonly string[]> = {
  javascript: ['import_statement', 'call_expression'],
  typescript: ['import_statement', 'call_expression'],
  python: ['import_statement', 'import_from_statement'],
  java: ['import_declaration'],
  go: [],
  // PHP's require/include are function-like statements, and Composer autoloading
  // resolves classes with no import line at all. Cross-file tracing in PHP is
  // therefore NOT implemented - stated here rather than half-attempted.
  php: [],
};

function unquote(raw: string): string {
  return raw.replace(/^[a-zA-Z]?["'`]/, '').replace(/["'`]$/, '');
}

/** The raw module specifiers this file mentions, e.g. "./db", "app.helpers". */
function importSpecifiers(root: Node, language: LanguageId): string[] {
  const wanted = new Set(IMPORT_NODES[language]);
  if (wanted.size === 0) return [];
  const specifiers: string[] = [];

  const visit = (node: Node, depth: number): void => {
    if (depth > 6) return; // imports live near the top; no need to walk bodies

    if (wanted.has(node.type)) {
      if (node.type === 'call_expression') {
        // require('./db') - only when the callee really is `require`.
        const callee = node.childForFieldName('function');
        if (callee?.text === 'require') {
          const args = node.childForFieldName('arguments');
          const first = args?.namedChildren.find((c): c is Node => c !== null);
          if (first) specifiers.push(unquote(first.text ?? ''));
        }
      } else {
        const source =
          node.childForFieldName('source') ??
          node.childForFieldName('module_name') ??
          node.childForFieldName('name') ??
          null;
        const raw = (source ?? node).text ?? '';
        specifiers.push(unquote(raw.replace(/^import\s+|;$/g, '').trim()));
      }
    }

    for (const child of node.namedChildren) if (child) visit(child, depth + 1);
  };
  visit(root, 0);
  return specifiers.filter(Boolean);
}

const JS_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts'];

/** Turn a specifier into a path we actually have, or null. */
function resolveSpecifier(
  specifier: string,
  fromFile: IndexedFile,
  known: ReadonlySet<string>,
): string | null {
  const tryAll = (base: string): string | null => {
    if (known.has(base)) return base;

    /**
     * TypeScript's ESM convention: source says `import './languages.js'` but the
     * file on disk is `languages.ts`. The compiler rewrites nothing, so a
     * resolver that only tries the literal specifier finds nothing - which is
     * exactly what happened the first time NS-1 scanned its own source and
     * reported zero import edges.
     */
    const rewritten = base.replace(/\.(js|mjs|cjs)$/, '');
    if (rewritten !== base) {
      for (const extension of JS_EXTENSIONS) {
        if (known.has(rewritten + extension)) return rewritten + extension;
      }
    }

    for (const extension of JS_EXTENSIONS) {
      if (known.has(base + extension)) return base + extension;
      if (known.has(joinPath(base, `index${extension}`))) {
        return joinPath(base, `index${extension}`);
      }
    }
    return null;
  };

  if (fromFile.language === 'javascript' || fromFile.language === 'typescript') {
    // Only relative specifiers. A bare 'express' is a package, not our code.
    if (!specifier.startsWith('.')) return null;
    return tryAll(resolveFrom(fromFile.directory, specifier));
  }

  if (fromFile.language === 'python') {
    const leadingDots = /^\.+/.exec(specifier)?.[0].length ?? 0;
    const body = specifier.slice(leadingDots).replace(/\./g, '/');
    if (leadingDots > 0) {
      let base = fromFile.directory;
      for (let i = 1; i < leadingDots; i++) base = dirnameOf(base);
      const candidate = body ? joinPath(base, body) : base;
      return known.has(`${candidate}.py`) ? `${candidate}.py` : tryAll(candidate);
    }
    // Absolute-ish: match any known file whose path ends with the module path.
    const suffix = `/${body}.py`;
    const matches = [...known].filter((p) => p.endsWith(suffix) || p === `${body}.py`);
    return matches.length === 1 ? (matches[0] ?? null) : null;
  }

  if (fromFile.language === 'java') {
    // `com.example.Helper` -> a file called Helper.java, if there is exactly one.
    const className = specifier.split('.').pop() ?? '';
    if (!className || className === '*') return null;
    const matches = [...known].filter((p) => basenameOf(p) === `${className}.java`);
    return matches.length === 1 ? (matches[0] ?? null) : null;
  }

  return null;
}

export function buildProjectIndex(files: readonly ParsedFile[]): ProjectIndex {
  const byPath = new Map<string, IndexedFile>();
  // Resolution happens in normalised space; lookups map back to the original.
  const known = new Set(files.map((f) => toPosix(f.path)));
  const originalOf = new Map(files.map((f) => [toPosix(f.path), f.path]));

  for (const file of files) {
    byPath.set(file.path, {
      path: file.path,
      posix: toPosix(file.path),
      directory: dirnameOf(file.path),
      language: file.language.id,
      functions: collectFunctions(file.root, file.language.id),
      imports: new Set<string>(),
    });
  }

  // Second pass: resolve specifiers now that every path is known.
  let importEdges = 0;
  for (const file of files) {
    const entry = byPath.get(file.path);
    if (!entry) continue;
    for (const specifier of importSpecifiers(file.root, file.language.id)) {
      const resolvedPosix = resolveSpecifier(specifier, entry, known);
      const resolved = resolvedPosix ? originalOf.get(resolvedPosix) : undefined;
      if (resolved && resolved !== file.path) {
        entry.imports.add(resolved);
        importEdges++;
      }
    }
  }

  // Same-package visibility: Java and Go files in one directory see each other
  // with no import statement at all, so the directory IS the import edge.
  const byDirectory = new Map<string, string[]>();
  for (const entry of byPath.values()) {
    if (entry.language !== 'java' && entry.language !== 'go') continue;
    const list = byDirectory.get(entry.directory) ?? [];
    list.push(entry.path);
    byDirectory.set(entry.directory, list);
  }

  /**
   * Function name -> the files that define it.
   *
   * The first version of resolve() walked every sibling file in the directory
   * looking for the name. That is fine for a normal package and catastrophic
   * for OWASP's benchmark, which puts 2,766 Java files in ONE directory: every
   * unresolved call scanned all 2,766 siblings, and a 12-second scan became 60.
   *
   * Indexing by name first turns that inner loop from "all files in the
   * package" into "the handful of files that define this exact name".
   */
  const byFunctionName = new Map<string, IndexedFile[]>();
  for (const entry of byPath.values()) {
    for (const name of entry.functions.keys()) {
      const list = byFunctionName.get(name);
      if (list) list.push(entry);
      else byFunctionName.set(name, [entry]);
    }
  }

  let resolved = 0;
  let ambiguous = 0;
  let functionsIndexed = 0;
  for (const entry of byPath.values()) functionsIndexed += entry.functions.size;

  return {
    resolve(fromPath: string, name: string) {
      const from = byPath.get(fromPath);
      if (!from) return null;

      // Start from "who defines this name at all", then keep only the ones
      // this file can actually see.
      const definers = byFunctionName.get(name);
      if (!definers) return null;

      const samePackage = from.language === 'java' || from.language === 'go';
      const hits = definers.filter(
        (candidate) =>
          candidate.path !== fromPath &&
          candidate.language === from.language &&
          (from.imports.has(candidate.path) ||
            (samePackage && candidate.directory === from.directory)),
      );

      if (hits.length === 0) return null;
      if (hits.length > 1) {
        ambiguous++;
        return null; // several files define it - we do not guess.
      }

      const winner = hits[0];
      const fn = winner?.functions.get(name);
      if (!winner || !fn) return null;
      resolved++;
      return { path: winner.path, fn };
    },

    noteAmbiguous() {
      ambiguous++;
    },

    stats: () => ({
      filesIndexed: byPath.size,
      functionsIndexed,
      importEdges,
      resolved,
      ambiguous,
    }),
  };
}
