/**
 * WHAT IS AN AST? (read this once, then the rest of the project makes sense)
 * =========================================================================
 *
 * When you write:
 *
 *     const total = price + tax;
 *
 * your computer does not see a sentence. It sees a TREE. "AST" stands for
 * Abstract Syntax Tree: "abstract" because it throws away things that don't
 * change meaning (spaces, most punctuation), "syntax" because it captures the
 * grammar of the language, and "tree" because code nests inside code.
 *
 * That line becomes something like:
 *
 *     lexical_declaration
 *      +- variable_declarator
 *          +- name: identifier          "total"
 *          +- value: binary_expression
 *              +- left:     identifier  "price"
 *              +- operator: "+"
 *              +- right:    identifier  "tax"
 *
 * Why this matters enormously for a security scanner:
 *
 * The old way (what most cheap scanners do, and what earlier versions of this
 * project did) is to search the raw TEXT with regular expressions. Text search
 * cannot tell the difference between:
 *
 *     db.query("SELECT * FROM users WHERE id = " + userId)   <- real problem
 *     // db.query("SELECT * FROM users WHERE id = " + userId)  <- a comment
 *     log("db.query is unsafe when you do \" + userId\"")      <- a string
 *
 * All three contain the same characters. Only one is a vulnerability. An AST
 * knows which is which, because the parser already decided "this is a comment",
 * "this is a string literal", "this is a real function call". We get that
 * accuracy for free, and it is the entire reason we use tree-sitter.
 *
 * Tree-sitter is Github's parser toolkit. It is fast, it is error-tolerant
 * (it produces a usable tree even for code that doesn't compile - important,
 * because real repositories contain broken files), and it has mature grammars
 * for dozens of languages that all behave the same way.
 */

import { Language, Parser, type Node, type Tree } from 'web-tree-sitter';
import { detectLanguage, type LanguageSpec } from './languages.js';

/**
 * WHERE DO THE .wasm GRAMMARS COME FROM?
 *
 * On Node they are files in node_modules. In a browser they are URLs fetched
 * over HTTP. That is the ONLY difference between the two platforms in the whole
 * analysis path, so it is the only thing abstracted: everything else - parsing,
 * rules, taint - is identical code running in both places.
 *
 * A loader returns whatever `Language.load` accepts: a path, a URL, or bytes.
 */
export type GrammarLoader = (grammar: string) => string | Uint8Array | Promise<string | Uint8Array>;

let grammarLoader: GrammarLoader | null = null;
let engineInit: (() => Promise<void>) | null = null;

/** Called once by whichever shell is in charge (CLI or browser worker). */
export function configureParsing(options: {
  loadGrammar: GrammarLoader;
  init?: () => Promise<void>;
}): void {
  grammarLoader = options.loadGrammar;
  engineInit = options.init ?? null;
  engineReady = null;
  parserCache.clear();
  languageCache.clear();
}

let engineReady: Promise<void> | null = null;

/**
 * Boot the WebAssembly runtime. Must happen once before any parsing.
 * We memoise the promise so calling this from ten places still only boots once.
 */
export async function initEngine(): Promise<void> {
  engineReady ??= engineInit ? engineInit() : Parser.init();
  await engineReady;
}

/** Grammar name -> loaded Parser. Loading a grammar costs ~10-40ms, so we cache. */
const parserCache = new Map<string, Parser>();

async function getParser(grammar: string): Promise<Parser> {
  const cached = parserCache.get(grammar);
  if (cached) return cached;

  await initEngine();
  if (!grammarLoader) {
    throw new Error(
      'No grammar loader configured. Call configureParsing() first - ' +
        'src/parse/node-grammars.ts for the CLI, ui/worker.js for the browser.',
    );
  }
  const language = await Language.load(await grammarLoader(grammar));
  const parser = new Parser();
  parser.setLanguage(language);
  parserCache.set(grammar, parser);
  return parser;
}

/** The tree-sitter Language object, needed to compile queries. */
const languageCache = new Map<string, Language>();

export async function getLanguage(grammar: string): Promise<Language> {
  const cached = languageCache.get(grammar);
  if (cached) return cached;
  const parser = await getParser(grammar);
  const language = parser.language;
  if (!language) throw new Error(`Grammar ${grammar} loaded but exposed no language`);
  languageCache.set(grammar, language);
  return language;
}

/** A place where tree-sitter could not make sense of the source. */
export interface ParseIssue {
  readonly kind: 'ERROR' | 'MISSING';
  readonly line: number;
  readonly column: number;
  readonly text: string;
}

/** Everything downstream code needs about one parsed file. */
export interface ParsedFile {
  readonly path: string;
  readonly language: LanguageSpec;
  /** May differ from language.grammar for dialects (.tsx uses the tsx grammar). */
  readonly grammar: string;
  readonly detectedBy: 'extension' | 'shebang';
  readonly source: string;
  readonly tree: Tree;
  readonly root: Node;
  /**
   * Parse problems, reported not hidden. A file with issues is still scanned -
   * tree-sitter recovers - but the report says so, because findings from a
   * partially-understood file deserve less trust.
   */
  readonly parseIssues: readonly ParseIssue[];
}

export type ParseOutcome =
  | { readonly status: 'parsed'; readonly file: ParsedFile }
  | { readonly status: 'skipped'; readonly path: string; readonly reason: string };

const MAX_REPORTED_ISSUES = 25;

/**
 * Walk the whole tree looking for the two ways tree-sitter admits defeat:
 *   ERROR   - "I found characters here I cannot fit into the grammar"
 *   MISSING - "the grammar says something must be here; I inserted a fake one"
 *
 * We use an explicit stack rather than recursion because deeply nested files
 * (minified code, generated code) can blow the JavaScript call stack.
 */
function collectParseIssues(root: Node): ParseIssue[] {
  if (!root.hasError) return [];
  const issues: ParseIssue[] = [];
  const stack: Node[] = [root];

  while (stack.length > 0 && issues.length < MAX_REPORTED_ISSUES) {
    const node = stack.pop();
    if (!node) break;

    if (node.type === 'ERROR' || node.isMissing) {
      issues.push({
        kind: node.isMissing ? 'MISSING' : 'ERROR',
        line: node.startPosition.row + 1,
        column: node.startPosition.column + 1,
        text: (node.text ?? '').replace(/\s+/g, ' ').trim().slice(0, 60),
      });
      // Don't descend into an error subtree; its children are noise.
      continue;
    }

    // Only descend where an error actually lives - a huge speed win.
    if (node.hasError) {
      for (let i = node.childCount - 1; i >= 0; i--) {
        const child = node.child(i);
        if (child) stack.push(child);
      }
    }
  }
  return issues;
}

/** Parse a string of code you already have in memory. Used by tests and by `ast`. */
export async function parseSource(source: string, grammar: string): Promise<Tree> {
  const parser = await getParser(grammar);
  const tree = parser.parse(source);
  if (!tree) throw new Error(`Parser returned no tree for grammar ${grammar}`);
  return tree;
}

/**
 * Work out a file's language and parse it, from text already in memory.
 * No filesystem, no platform assumptions - this is what the browser calls too.
 */
export async function parseSourceFile(filePath: string, source: string): Promise<ParseOutcome> {
  // A binary file that happens to end in .js would waste a parse and produce
  // garbage findings. NUL bytes are the cheap, reliable binary tell.
  if (source.includes('\u0000')) {
    return { status: 'skipped', path: filePath, reason: 'binary file' };
  }

  const firstLine = source.slice(0, source.indexOf('\n') + 1 || 200);
  const match = detectLanguage(filePath, firstLine);
  if (!match) {
    return { status: 'skipped', path: filePath, reason: 'unsupported file type' };
  }

  const tree = await parseSource(source, match.grammar);
  return {
    status: 'parsed',
    file: {
      path: filePath,
      language: match.spec,
      grammar: match.grammar,
      detectedBy: match.detectedBy,
      source,
      tree,
      root: tree.rootNode,
      parseIssues: collectParseIssues(tree.rootNode),
    },
  };
}
