/**
 * WHY IS EACH "TO REVIEW" FINDING STILL UNSETTLED?
 * ================================================
 *
 * A sorting aid for deciding what to teach the engine next - not a scanner and
 * not a proof. It reads the code around each signature-based finding in a scan
 * and sorts it by the most likely reason the tracer could not settle it:
 * request input that was nearby but not connected, data read back from a
 * database, a value arriving as a function parameter, a helper called with
 * fixed values only, session or global state, an error message - or a pattern
 * rule that is not a data-flow question at all. It also lists the functions
 * the engine does not model that proven paths rest on.
 *
 * HEURISTIC BY DESIGN: it looks at assignments and parameters in the enclosing
 * function, by text and syntax, and its output says so. Use it to rank work,
 * then confirm each case in the code.
 *
 * Usage (after npm run build):
 *   npm run review-reasons -- <scan.json> <folder the scan was run from> [label]
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { useNodeGrammars } from '../dist/src/parse/node-grammars.js';
import { initEngine, parseSourceFile } from '../dist/src/parse/parser.js';
import { TAINT_DICTIONARIES } from '../dist/src/taint/dictionaries.js';
import { isTestPath } from '../dist/src/rules/lib/strings.js';

const [scanPath, root, label = path.basename(root)] = process.argv.slice(2);
const scan = JSON.parse(readFileSync(scanPath, 'utf8'));
useNodeGrammars();
await initEngine();

const TAINT_RULES = new Set(['sql-injection', 'xss', 'command-injection', 'code-injection', 'ssrf', 'unsafe-deserialization']);
const FUNC = new Set(['function_definition', 'method_declaration', 'anonymous_function', 'arrow_function', 'function_declaration',
  'function_expression', 'method_definition', 'lambda', 'func_literal', 'method_declaration', 'constructor_declaration', 'function_item']);
const ASSIGN = new Set(['assignment_expression', 'augmented_assignment_expression', 'assignment', 'augmented_assignment',
  'variable_declarator', 'short_var_declaration', 'assignment_statement', 'local_variable_declaration']);
const IDENT = new Set(['variable_name', 'identifier', 'shorthand_property_identifier']);
const STORED = /fetch|\$row\b|\brow\[|\brows?\b|\.objects\.|cursor|\.execute\(|mysqli_query|->query\(|\.query\(|findOne|\.find\(|first\(\)|\.all\(\)|\.filter\(|DB::|->get\(|get_option|get_post|\.findById|\.findAll|Scan\(|QueryRow/;
const parsed = new Map();
async function parse(file) {
  if (!parsed.has(file)) {
    try {
      const abs = path.join(root, file);
      const o = await parseSourceFile(abs, readFileSync(abs, 'utf8'));
      parsed.set(file, o.status === 'parsed' ? o.file : null);
    } catch { parsed.set(file, null); }
  }
  return parsed.get(file);
}
const walk = (n, fn) => { fn(n); for (const c of n.namedChildren) if (c) walk(c, fn); };
const bare = (t) => t.replace(/^\$/, '');

function isSource(lang, text) {
  const d = TAINT_DICTIONARIES[lang];
  return !!d && d.sources.some((s) => s.pattern.test(text));
}
const SESSION = /\$_SESSION|\$_SERVER\[\s*['"](?:PHP_SELF|SCRIPT_NAME|SERVER_NAME|DOCUMENT_ROOT)|\bsession\[|\.session\b|getSession\(|\$GLOBALS\b/;
/** A call whose every argument is a literal - e.g. echo helper('https://...'). */
function callWithFixedArgs(n) {
  let call = n;
  while (call && !/call|invocation/.test(call.type) && call.namedChildren.length === 1) call = call.namedChildren[0];
  if (!call || !/call|invocation/.test(call.type)) return false;
  if (/member_call|method_call|scoped_call/.test(call.type)) return false;
  const callee = call.childForFieldName('function') ?? call.childForFieldName('name') ?? call.namedChildren[0];
  if (callee && /[.>]/.test(callee.text)) return false;
  const args = call.childForFieldName('arguments');
  return !!args && onlyLiterals(args);
}
function onlyLiterals(n) {
  let ok = true;
  walk(n, (c) => { if (IDENT.has(c.type) || /call|invocation/.test(c.type)) ok = false; });
  return ok;
}

const RANK = ['request', 'stored', 'session', 'exception', 'parameter', 'object-state', 'global', 'other', 'fixed-call', 'constant'];
const tally = new Map();
const samples = new Map();
const bump = (k, f, why) => {
  tally.set(k, (tally.get(k) ?? 0) + 1);
  if (!samples.has(k)) samples.set(k, []);
  if (samples.get(k).length < (process.env.ALL ? 999 : 3)) samples.get(k).push(`${f.location.file}:${f.location.startLine}  ${why}`.slice(0, 160));
};

const review = scan.findings.filter((f) => f.confidence === 'signature-based');
for (const f of review) {
  if (!TAINT_RULES.has(f.ruleId)) {
    const where = isTestPath(f.location.file) ? 'in test code, already ranked low and listed apart' : 'in application code';
    bump(`${f.ruleId} (a pattern check, not a data-flow question) - ${where}`, f, f.location.snippet);
    continue;
  }
  const r = f.reasoning ?? '';
  if (/BRANCH THIS ENGINE DOES NOT EVALUATE|COLLECTION THAT TOOK MORE THAN ONE|INSIDE QUOTES/.test(r)) { bump('traced, then downgraded for an assumption', f, r.slice(0, 80)); continue; }
  const file = await parse(f.location.file);
  if (!file) { bump('could not re-read the file', f, ''); continue; }
  const lang = file.language.id;
  const L = f.location;
  const node = file.root.descendantForPosition({ row: L.startLine - 1, column: L.startColumn - 1 }, { row: L.endLine - 1, column: L.endColumn - 1 });
  if (isSource(lang, node.text)) { bump('request input is ON the line, but no path was proven', f, node.text.slice(0, 80)); continue; }
  let fn = node.parent;
  while (fn && !FUNC.has(fn.type)) fn = fn.parent;
  const scope = fn ?? file.root;
  const params = new Set();
  const plist = fn?.childForFieldName('parameters');
  if (plist) walk(plist, (c) => { if (IDENT.has(c.type)) params.add(bare(c.text)); });
  const names = new Set();
  walk(node, (c) => { if (IDENT.has(c.type)) names.add(bare(c.text)); });
  const globals = new Set();
  const caught = new Set();
  walk(scope, (c) => {
    if (c.type === 'global_declaration') walk(c, (g) => { if (IDENT.has(g.type)) globals.add(bare(g.text)); });
    if (/catch_clause|except_clause/.test(c.type)) walk(c, (g) => { if (IDENT.has(g.type) && g.parent && !/call/.test(g.parent.type)) caught.add(bare(g.text)); });
  });
  const assigns = [];
  walk(scope, (c) => {
    if (!ASSIGN.has(c.type) || c.startPosition.row >= L.startLine - 1 + 1) return;
    const left = c.childForFieldName('left') ?? c.childForFieldName('name') ?? c.namedChildren[0];
    const right = c.childForFieldName('right') ?? c.childForFieldName('value') ?? c.namedChildren[c.namedChildren.length - 1];
    if (left && right) assigns.push({ name: bare(left.text), right, row: c.startPosition.row });
  });
  let best = 'other';
  let why = `no assignment found for ${[...names].slice(0, 3).join(', ')}`;
  const consider = (cls, w) => { if (RANK.indexOf(cls) < RANK.indexOf(best)) { best = cls; why = w; } };
  if (names.size === 0) { best = onlyLiterals(node) ? 'constant' : callWithFixedArgs(node) ? 'fixed-call' : 'other'; why = node.text.slice(0, 70); }
  else if (callWithFixedArgs(node)) { best = 'fixed-call'; why = node.text.slice(0, 70); }
  let sawConstantOnly = names.size > 0;
  for (const name of names) {
    const mine = assigns.filter((a) => a.name === name || a.name.endsWith(`.${name}`)).sort((a, b) => b.row - a.row);
    if (mine.length === 0) {
      sawConstantOnly = false;
      if (caught.has(name)) consider('exception', `${name} is a caught exception`);
      else if (globals.has(name)) consider('global', `${name} is a global set elsewhere`);
      else if (params.has(name)) consider('parameter', `${name} is a parameter of the enclosing function`);
      else if (/^this$|^self$/.test(name)) consider('object-state', `read from ${name}`);
      continue;
    }
    for (const a of mine) {
      const rt = a.right.text;
      if (isSource(lang, rt)) { consider('request', `${name} = ${rt.slice(0, 60)}`); sawConstantOnly = false; }
      else if (STORED.test(rt)) { consider('stored', `${name} = ${rt.slice(0, 60)}`); sawConstantOnly = false; }
      else if (SESSION.test(rt)) { consider('session', `${name} = ${rt.slice(0, 60)}`); sawConstantOnly = false; }
      else if (callWithFixedArgs(a.right)) { consider('fixed-call', `${name} = ${rt.slice(0, 60)}`); }
      else if ([...params].some((p) => new RegExp(`\\b${p.replace(/[$]/g, '\\$&')}\\b`).test(rt))) { consider('parameter', `${name} = ${rt.slice(0, 60)}`); sawConstantOnly = false; }
      else if (!onlyLiterals(a.right)) { sawConstantOnly = false; consider('other', `${name} = ${rt.slice(0, 60)}`); }
    }
  }
  if (sawConstantOnly && best === 'other') { best = 'constant'; why = 'every value spliced in is a literal in this function'; }
  const words = {
    request: 'request input reaches it in this function, but no path was proven (a tracer gap)',
    stored: 'data read back from a database or store (second-order)',
    parameter: 'arrives as a function parameter (the caller was not traced)',
    'object-state': 'read from object state ($this / self)',
    session: 'session or server-side state (set elsewhere - may be user data from an earlier request)',
    exception: 'an error or exception message',
    global: 'a global variable set in another file',
    'fixed-call': 'a function called with fixed values only',
    other: 'origin not classified by this measurement',
    constant: 'only fixed values from the code',
  };
  bump(words[best], f, why);
}

const total = review.length;
console.log(`\n${label}: ${total} to-review findings  (HEURISTIC measurement - reads the code around each sink)`);
for (const [k, v] of [...tally].sort((a, b) => b[1] - a[1])) {
  console.log(`  ${String(v).padStart(4)}  ${(100 * v / total).toFixed(0).padStart(3)}%  ${k}`);
  for (const s of samples.get(k)) console.log(`              e.g. ${s}`);
}
// The other half: proofs that rest on a function the engine does not model.
const hops = new Map();
let restOnGuess = 0;
const proven = scan.findings.filter((f) => f.confidence === 'flow-verified');
for (const f of proven) {
  const names = (f.flowPath ?? []).flatMap((s) => [...(s.description ?? '').matchAll(/passed through `([^`]+)\(\)`, which (?:is NOT in our dictionary|resolves by name)/g)].map((m) => m[1]));
  if (names.length) restOnGuess++;
  for (const n of new Set(names)) hops.set(n, (hops.get(n) ?? 0) + 1);
}
console.log(`\n  proven: ${proven.length}, of which ${restOnGuess} rest on at least one function the engine does not model`);
console.log(`  most common unmodelled functions on proven paths: ${[...hops].sort((a, b) => b[1] - a[1]).slice(0, 12).map(([n, c]) => `${n}() x${c}`).join(', ') || 'none'}`);
