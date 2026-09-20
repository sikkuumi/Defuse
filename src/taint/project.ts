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
import { nodeAtRange, type TreeStore } from '../parse/tree-store.js';
import { collectFunctions, type CrossFileResolver } from './tracer.js';

/**
 * A function recorded as COORDINATES rather than as a syntax node.
 *
 * This is the change that lets the memory ceiling go away. The index used to
 * hold a live Node for every function body in the project, and a Node keeps its
 * whole tree alive - so indexing the project pinned every tree in it, whether
 * or not anything ever traced into them. Holding two integers and a string
 * instead lets the trees be freed, at the cost of parsing a file again on the
 * rare occasion the tracer actually descends into it.
 *
 * bodyType is recorded alongside the offsets because a byte range alone is not
 * always unique: a node can share its exact extent with its parent. The type is
 * what tells them apart, and a lookup that cannot match both is refused.
 */
export interface IndexedFunction {
  readonly name: string;
  readonly params: readonly string[];
  readonly bodyStart: number;
  readonly bodyEnd: number;
  readonly bodyType: string;
}

/**
 * What buildProjectIndex needs from each file. Everything here is extracted
 * while the file's tree is hot during the first pass, so the index itself never
 * touches a tree and never holds one.
 */
export interface IndexedFileInput {
  readonly path: string;
  readonly language: LanguageId;
  readonly functions: ReadonlyMap<string, IndexedFunction>;
  /** Raw module specifiers, already read out of the tree. */
  readonly importSpecifiers: readonly string[];
}

/** Turn a file's functions into coordinates, using the tracer's own definition. */
export function indexFunctions(
  root: Node,
  language: LanguageId,
): Map<string, IndexedFunction> {
  const indexed = new Map<string, IndexedFunction>();
  for (const [name, fn] of collectFunctions(root, language)) {
    indexed.set(name, {
      name: fn.name,
      params: fn.params,
      bodyStart: fn.body.startIndex,
      bodyEnd: fn.body.endIndex,
      bodyType: fn.body.type,
    });
  }
  return indexed;
}

interface IndexedFile {
  /** The path exactly as the shell gave it to us - what reports will show. */
  readonly path: string;
  /** The same path, slashes normalised. All comparisons use this one. */
  readonly posix: string;
  readonly directory: string;
  readonly language: LanguageId;
  readonly functions: ReadonlyMap<string, IndexedFunction>;
  /** Absolute paths of files this one imports, as far as we could resolve them. */
  readonly imports: Set<string>;
}

export interface ProjectIndexStats {
  readonly filesIndexed: number;
  readonly functionsIndexed: number;
  readonly importEdges: number;
  /**
   * Import statements we READ but could not point at a file in this scan.
   *
   * Counted because it is the difference between "this code imports nothing"
   * and "this code imports 117 things and you gave me none of them". A beginner
   * scanned juice-shop's server.ts on its own, got zero findings, and concluded
   * the tool was broken. It was not: server.ts is a wiring file whose 117
   * imports all pointed outside the scan, so every trace stopped at the first
   * module boundary. The same repository's routes/ directory produces seven
   * findings, two of them flow-verified.
   *
   * The report had the evidence - importEdges was 0 - and never said what it
   * meant. An undeclared blind spot is exactly what this project refuses to
   * ship, so it is declared now.
   */
  readonly importsUnresolved: number;
  /** Times a cross-file call WAS followed. */
  readonly resolved: number;
  /** Times several files defined the name and we refused to choose. */
  readonly ambiguous: number;
  /**
   * Times a function was found in the index but could not be located again in
   * the re-parsed tree, and the resolution was declined rather than guessed.
   *
   * This should be zero forever: the parse is deterministic, so a node recorded
   * at bytes 400-980 as a `block` is a `block` at bytes 400-980 every time the
   * same file is parsed with the same grammar. It is counted anyway, because
   * "should be impossible" is how a tool ends up tracing into the wrong
   * function and printing a confident proof of it.
   */
  readonly relocationsFailed: number;
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
  /*
   * `scoped_type_identifier` is here because an import statement is not the
   * only way Java names another file.
   *
   *     new org.owasp.benchmark.helpers.SeparateClassRequest(request)
   *
   * names a class as precisely as any import does and produces no
   * import_declaration at all, so the edge was never built and the call was
   * never followed.
   *
   * This was not a corner. It was EVERY ONE of the 69 cases the OWASP
   * benchmark scored as a complete miss - 48 xss, 20 cmdi, 1 sqli, all of them
   * a request wrapped in a helper class referenced by its full name. Proven by
   * adding a single import line to one test case and changing nothing else,
   * which turned a silent file into a finding.
   *
   * A complete miss is the only failure mode that gets somebody hacked, and
   * this one was a hundred percent of ours.
   */
  java: ['import_declaration', 'scoped_type_identifier'],
  go: [],
  // PHP's require/include are function-like statements, and Composer autoloading
  // resolves classes with no import line at all. Cross-file tracing in PHP is
  // therefore NOT implemented - stated here rather than half-attempted.
  php: [],
  /*
   * C and C++ resolve calls at LINK time, not through anything written in the
   * source, and that is a harder problem than it first looks.
   *
   * `#include` brings in DECLARATIONS, not definitions - the body of the
   * function lives in a .c file the header never names, chosen by a Makefile
   * we do not read. So following an include would lead to a prototype and stop.
   *
   * Same-directory resolution, which is what makes Java and Go work above, is
   * actively unsafe here: `static` gives a C function FILE scope, and every
   * large C project has a dozen different `static int init(void)` definitions
   * sitting in the same folder. Matching by name would let the tracer walk into
   * a function the caller provably cannot see, and print a step-by-step proof
   * through it. That is the exact failure this project exists to refuse, so
   * cross-file tracing in the C family is NOT implemented and says so.
   */
  c: [],
  cpp: [],
};

function unquote(raw: string): string {
  return raw.replace(/^[a-zA-Z]?["'`]/, '').replace(/["'`]$/, '');
}

/** The raw module specifiers this file mentions, e.g. "./db", "app.helpers". */
export function importSpecifiers(root: Node, language: LanguageId): string[] {
  const wanted = new Set(IMPORT_NODES[language]);
  if (wanted.size === 0) return [];
  const specifiers: string[] = [];

  /*
   * Six levels is enough for every language whose edges are declarations at
   * the top of the file. Java's are not: a fully-qualified type reference sits
   * inside a method body, which is twenty-odd levels down, so the walk stopped
   * short of the very thing it needed to see.
   *
   * 48 is past any hand-written nesting and still far under the tracer's own
   * MAX_AST_DEPTH of 400, and it applies only to Java - nothing else pays for
   * it.
   */
  const maxDepth = language === 'java' ? 48 : 6;

  const visit = (node: Node, depth: number): void => {
    if (depth > maxDepth) return;

    if (wanted.has(node.type)) {
      if (node.type === 'scoped_type_identifier') {
        /*
         * `a.b.C` parses as scoped_type_identifier nested inside
         * scoped_type_identifier: the whole name, then `a.b`, then `a`. Only
         * the outermost is the class being named; the inner ones are package
         * fragments and would each try to resolve as a class of their own.
         *
         * The resolver below already requires exactly one file to match the
         * final segment, so a fragment that matches nothing is harmless and a
         * name that matches two files is declined rather than guessed. This
         * check is about not asking the question, rather than about surviving
         * the answer.
         */
        if (node.parent?.type !== 'scoped_type_identifier') {
          specifiers.push((node.text ?? '').trim());
        }
      } else if (node.type === 'call_expression') {
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
     * exactly what happened the first time Defuse scanned its own source and
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

/**
 * @param files  one record per scanned file, with functions and import
 *               specifiers ALREADY extracted from its tree.
 * @param store  where trees come from. Only touched when a resolution actually
 *               succeeds, which on real projects is a small fraction of files -
 *               the index itself is built without a single tree in hand.
 */
export function buildProjectIndex(
  files: readonly IndexedFileInput[],
  store: TreeStore,
): ProjectIndex {
  const byPath = new Map<string, IndexedFile>();
  // Resolution happens in normalised space; lookups map back to the original.
  const known = new Set(files.map((f) => toPosix(f.path)));
  const originalOf = new Map(files.map((f) => [toPosix(f.path), f.path]));

  for (const file of files) {
    byPath.set(file.path, {
      path: file.path,
      posix: toPosix(file.path),
      directory: dirnameOf(file.path),
      language: file.language,
      functions: file.functions,
      imports: new Set<string>(),
    });
  }

  // Second pass: resolve specifiers now that every path is known.
  let importEdges = 0;
  let importsUnresolved = 0;
  for (const file of files) {
    const entry = byPath.get(file.path);
    if (!entry) continue;
    for (const specifier of file.importSpecifiers) {
      const resolvedPosix = resolveSpecifier(specifier, entry, known);
      const resolved = resolvedPosix ? originalOf.get(resolvedPosix) : undefined;
      if (resolved && resolved !== file.path) {
        entry.imports.add(resolved);
        importEdges++;
      } else if (!/^[a-z@][\w@/.-]*$/i.test(specifier) || specifier.startsWith('.')) {
        // A RELATIVE import that resolved to nothing means the file it names is
        // outside the scan. A bare specifier (`express`, `@angular/core`) is a
        // package and is expected not to resolve - counting those would drown
        // the real signal in node_modules noise.
        importsUnresolved++;
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
  let relocationsFailed = 0;
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
      const indexed = winner?.functions.get(name);
      if (!winner || !indexed) return null;

      /* ---- materialise: coordinates back into a live syntax node ----
       *
       * This is the only place in the scan that can pull a tree back off disk,
       * and it is deliberately the LAST thing that happens - after the file has
       * been chosen and the ambiguity check has passed. Resolving first and
       * parsing second means a project with thousands of files that never
       * resolve into each other never re-parses anything.
       *
       * The pin lasts until the caller releases it, because the Node handed
       * back here points into this tree's memory and nothing else keeps it
       * alive.                                                               */
      store.pin(winner.path);
      const tree = store.get(winner.path);
      const body = nodeAtRange(
        tree.rootNode,
        indexed.bodyStart,
        indexed.bodyEnd,
        indexed.bodyType,
      );
      if (!body) {
        relocationsFailed++;
        return null;
      }

      resolved++;
      return { path: winner.path, fn: { name: indexed.name, params: indexed.params, body } };
    },

    noteAmbiguous() {
      ambiguous++;
    },

    stats: () => ({
      filesIndexed: byPath.size,
      functionsIndexed,
      importEdges,
      importsUnresolved,
      resolved,
      ambiguous,
      relocationsFailed,
    }),
  };
}
