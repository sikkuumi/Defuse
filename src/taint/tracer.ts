/**
 * THE TAINT TRACER
 * ================
 *
 * This is the engine that turns "signature-based" into "flow-verified".
 *
 * HOW IT WORKS, in one paragraph:
 * We read each function body top to bottom, keeping a notebook of which
 * variables currently hold dirty data. When a line assigns something, we work
 * out whether the right-hand side is dirty and write that in the notebook. When
 * a line calls something dangerous, we look up its arguments in the notebook.
 * If a dirty value reaches a sink and no sanitiser washed it on the way, we can
 * finally say the thing a pattern match never could: *this specific value, from
 * this specific source, reaches this specific sink.* And we can show every hop.
 *
 * WHAT IT DELIBERATELY DOES NOT DO - each of these is a documented gap, not an
 * oversight, and each is printed in the scan report:
 *
 *   1. BOUNDED REACH. Functions defined in this file are followed, and so are
 *      functions in another file when a relative import resolves to it. What
 *      still ends a trace: a call into a third-party package, a dynamic or
 *      aliased import, a name several modules define (we decline rather than
 *      guess), and any chain deeper than four calls.
 *
 *   2. STATEMENT ORDER, NOT BRANCH LOGIC. We read lines in order and ignore
 *      whether an `if` is true. So a value cleaned only inside `if (isAdmin)`
 *      is treated as cleaned afterwards. That direction of error loses findings
 *      rather than inventing them, which is the right way to be wrong.
 *
 *   3. UNKNOWN FUNCTIONS CARRY TAINT, AND SAY SO. `foo(dirty)` keeps the taint
 *      and records the hop as UNMODELLED, naming `foo` on the finding. Treating
 *      unknowns as clean was tried first and produced ZERO verified flows across
 *      2,766 Java files, every one a known vulnerability - so the quiet option
 *      was not the honest one. This is the weakest link in any path we print,
 *      which is exactly why it is printed rather than smoothed over.
 *
 *   4. CONTAINERS ARE TAINTED WHOLE. `list.add(dirty)` dirties the list, not
 *      the slot - so a clean element read back out of that list is treated as
 *      dirty too. Following values into objects at all requires this trade; the
 *      alternative was the previous behaviour, which was to lose the value
 *      entirely the moment it entered a StringBuilder or a List.
 *
 *   5. NO LOOP FIXPOINT. A variable that becomes dirty at the bottom of a loop
 *      and is used at the top is missed on the first pass. Real analysers
 *      iterate to a fixpoint; we do not, yet.
 *
 * Every one of those makes the tool MISS things (false negatives). None of them
 * makes it invent things. That asymmetry is deliberate: a flow-verified label is
 * a promise, and a promise that is sometimes wrong is worth less than no promise
 * at all.
 */

import type { Node } from 'web-tree-sitter';
import type { FlowStep } from '../core/finding.js';
import type { LanguageId } from '../parse/languages.js';
import { nodeLocation } from '../parse/location.js';
import type { ParsedFile } from '../parse/parser.js';
import { analyzeStringExpression, looksLikeHtml, looksLikeSql } from '../rules/lib/strings.js';
import { TAINT_DICTIONARIES } from './dictionaries.js';
import { SINK_KIND_RULE, type SinkKind, type TaintDictionary } from './types.js';

/* -------------------------------------------------------------------------- *
 * Internal step type: a FlowStep that also remembers which sink kinds a
 * sanitiser actually covers. See buildPath() for why this matters.
 * -------------------------------------------------------------------------- */
interface InternalStep extends FlowStep {
  readonly sanitizesKinds?: readonly SinkKind[];
}

interface Taint {
  readonly steps: readonly InternalStep[];
  readonly sanitizedFor: ReadonlySet<SinkKind>;
  readonly origin: string;
  /**
   * Names of functions on this path that we do NOT model. See the note on
   * unknown calls in evaluateCall - these are the hops where our claim is
   * weakest, so we carry them all the way onto the finding.
   */
  readonly unknownHops: readonly string[];
}

/**
 * A flow that reached a sink but was correctly sanitised on the way.
 * Not a vulnerability - evidence that this line is fine.
 */
export interface SanitizedFlow {
  readonly ruleId: string;
  readonly kind: SinkKind;
  readonly sinkNode: Node;
  /** The file the sink is in - may not be the file being scanned. */
  readonly filePath: string;
}

/** One confirmed source-to-sink flow, ready to become a finding. */
export interface FlowResult {
  readonly ruleId: string;
  readonly kind: SinkKind;
  /** The exact tainted expression - what the finding points at. */
  readonly node: Node;
  /** The whole sink call or assignment - used to match up with signature findings. */
  readonly sinkNode: Node;
  readonly path: readonly FlowStep[];
  readonly origin: string;
  readonly sinkDescription: string;
  /** Functions on the path that we do not model. Named on the finding. */
  readonly unknownHops: readonly string[];
  /** The file the sink is in - may not be the file being scanned. */
  readonly filePath: string;
}

/* -------------------------------------------------------------------------- *
 * Language-specific node vocabulary. Small enough to keep here rather than in
 * the dictionaries, because it describes the GRAMMAR, not a framework.
 * -------------------------------------------------------------------------- */

const FUNCTION_NODES: Record<string, readonly string[]> = {
  javascript: [
    'function_declaration', 'function_expression', 'arrow_function',
    'method_definition', 'generator_function_declaration', 'generator_function',
  ],
  typescript: [
    'function_declaration', 'function_expression', 'arrow_function',
    'method_definition', 'generator_function_declaration', 'generator_function',
  ],
  python: ['function_definition', 'lambda'],
  java: ['method_declaration', 'constructor_declaration', 'lambda_expression'],
  go: ['function_declaration', 'method_declaration', 'func_literal'],
  php: [
    'function_definition',
    'method_declaration',
    'anonymous_function_creation_expression',
    'arrow_function',
  ],
};

/**
 * Node types that ARE a reference to a variable by name.
 *
 * This started as a bare `node.type === 'identifier'` check, which is right for
 * four of the five languages and silently wrong for PHP: `$x` parses as
 * `variable_name`, so every PHP variable read fell through to "not a variable",
 * every binding was ignored, and taint died at the first assignment. Direct
 * source-to-sink flows still verified, which is the dangerous kind of bug -
 * it looked like the language worked.
 */
const VARIABLE_NODES = new Set(['identifier', 'variable_name']);

const UNWRAP_NODES = new Set([
  'parenthesized_expression',
  'await_expression',
  'as_expression',
  'satisfies_expression',
  'non_null_expression',
  'type_assertion',
  'expression_statement',
  /*
   * `(String) map.get("keyB")` - a Java cast.
   *
   * TypeScript's three ways of saying the same thing were all here from the
   * start; Java's was not, and the omission cost more than every cross-file
   * idea tried this session put together. A cast changes what the compiler
   * calls a value. It does not change the value, so it cannot change whether
   * an attacker chose it.
   *
   * Found by a ten-line fixture that put a tainted value into a HashMap three
   * different ways. Two came out traced; the one with a cast in front did not.
   * Written before touching the engine, on purpose - the hypothesis it killed
   * ("the container machinery is broken") was the third wrong guess in a row
   * that a benchmark run alone would not have corrected.
   */
  'cast_expression', // Java, C-style casts
]);

const MEMBER_NODES = new Set([
  'member_expression', // JS/TS   a.b
  'attribute', // Python  a.b
  'selector_expression', // Go      a.b
  'field_access', // Java    a.b
  'subscript_expression',
  'subscript',
  'index_expression',
  'array_access', // Java    a[i]
]);

/**
 * Calls that COMPILE a query and hand back a statement handle.
 *
 * After `stmt, err := db.Prepare(sql)`, the arguments to `stmt.QueryRow(uid)`
 * are bound parameters - the database keeps them separate from the
 * instruction, which is the whole point of preparing. Reporting them as
 * injection punishes the correct fix, which is the worst thing a SQL rule can
 * do. So we remember which local names hold a prepared statement.
 *
 * Note what this does NOT excuse: `db.Prepare(dynamicSql)` is still a sink,
 * because a query assembled from user input is dangerous whether or not it is
 * prepared afterwards.
 */
const PREPARE_CALLS = new Set([
  'Prepare',
  'PrepareContext',
  'Preparex',
  'PrepareNamed',
  'prepareStatement',
  'prepareCall',
]);

const CALL_NODES = new Set([
  'call_expression',
  'call',
  'new_expression',
  'method_invocation', // Java
  'object_creation_expression', // Java  new Foo(...)
  'function_call_expression', // PHP  foo(...)
  'member_call_expression', // PHP  $obj->foo(...)
  'scoped_call_expression', // PHP  Foo::bar(...)
]);

const STRING_NODES = new Set([
  'string',
  'template_string',
  'concatenated_string',
  'string_literal', // Java
  'text_block', // Java
  'interpreted_string_literal', // Go
  'raw_string_literal', // Go
  'encapsed_string', // PHP  "text $var"
  'heredoc', // PHP
]);

const INTERPOLATION_NODES = new Set(['template_substitution', 'interpolation']);

/**
 * Nodes that BUILD a container out of listed elements.
 *
 * `Object[] obj = {"a", bar};` then `writer.format(fmt, obj)` is one of the
 * commonest real XSS shapes in Java, and the trace used to die at the brace:
 * `bar` was tainted, `obj` was not, and the sink saw a clean array.
 *
 * A container is tainted WHOLE, exactly as ENGINE_CAPABILITIES already says for
 * `list.add(dirty)`. That is imprecise - element 0 here is the literal "a" and
 * is perfectly clean - but a container holding one dirty element is a dirty
 * container for every purpose a sink cares about, and erring the other way
 * loses the finding entirely.
 */
/**
 * Nodes whose body may or may not run.
 *
 * Used for one narrow decision: whether a CLEAN assignment is allowed to erase
 * a variable's taint. Consider the shape that dominates the OWASP benchmark:
 *
 *     if ((500 / 42) + num > 200) bar = param;   // param is attacker input
 *     else bar = "This should never happen";
 *
 * Reading statements in order, the else branch is simply the last write, so
 * `bar` came out clean and the finding vanished - even though the two branches
 * are mutually exclusive and one of them hands the attacker's value straight
 * to the page.
 *
 * We do not evaluate the condition; that is a different and much larger piece
 * of work. We make the weaker claim that a conditional write cannot PROVE a
 * value clean. So taint set anywhere survives a clean write inside a branch,
 * while an unconditional write still clears it, because that one really does
 * happen every time.
 *
 * The direction matters: this errs toward reporting a value that might be
 * clean, rather than staying silent about one that might be dirty.
 */
const CONDITIONAL_NODES = new Set([
  'if_statement',
  'else_clause',
  'switch_statement',
  'switch_block',
  'switch_expression',
  'ternary_expression',
  'conditional_expression',
  'case_statement',
  'match_statement',
  'try_statement',
  'catch_clause',
  'for_statement',
  'while_statement',
  'do_statement',
  'enhanced_for_statement',
  'for_in_statement',
  'for_range_loop',
  'foreach_statement',
]);

const CONTAINER_NODES = new Set([
  'array_initializer', // Java   {"a", bar}
  'array_creation_expression', // Java   new String[]{...}   PHP  array(...)
  'array', // JS/TS  [a, b]
  'list', // Python [a, b]
  'tuple',
  'set',
  'dictionary',
  'composite_literal', // Go     []string{a, b}
]);

function text(node: Node | null | undefined): string {
  return (node?.text ?? '').replace(/\s+/g, ' ').trim();
}

/**
 * The method name at the end of a callee expression.
 *
 * The first version cut the string at the first "(" and then split on dots.
 * That worked for `db.query` and broke silently on Java's
 * `Runtime.getRuntime().exec` - cutting at the paren left "Runtime.getRuntime",
 * so the name came back as `getRuntime` and the command-injection sink never
 * matched. Taking the trailing identifier instead is both simpler and correct
 * for every chained call.
 */
function lastSegment(value: string): string {
  const match = value.match(/([A-Za-z_$][\w$]*)\s*$/);
  return match?.[1] ?? value.trim();
}

/**
 * "What is being called, and on what?"
 *
 * Every grammar spells this differently. JS and Python put the whole callee in
 * a `function` field. Java's `method_invocation` does NOT - it keeps the
 * receiver and the method name as separate children, so `stmt.executeQuery(x)`
 * has no single node meaning "stmt.executeQuery". We rebuild it here so the
 * rest of the tracer can stay grammar-agnostic.
 */
function calleeOf(callNode: Node): { node: Node | null; text: string; receiver: Node | null } {
  const fn =
    callNode.childForFieldName('function') ?? callNode.childForFieldName('constructor') ?? null;
  if (fn) {
    const receiver = MEMBER_NODES.has(fn.type)
      ? fn.childForFieldName('object') ??
        fn.childForFieldName('operand') ??
        fn.namedChildren[0] ??
        null
      : null;
    return { node: fn, text: text(fn), receiver };
  }

  const name = callNode.childForFieldName('name'); // Java method_invocation
  const object = callNode.childForFieldName('object');
  if (name) {
    return {
      node: name,
      text: object ? `${text(object)}.${text(name)}` : text(name),
      receiver: object,
    };
  }

  const type = callNode.childForFieldName('type'); // Java new Foo(...)
  if (type) return { node: type, text: text(type), receiver: null };

  return { node: null, text: '', receiver: null };
}

function argumentsOf(callNode: Node): Node[] {
  const argsNode = callNode.childForFieldName('arguments');
  if (!argsNode) return [];
  return argsNode.namedChildren
    .filter((n): n is Node => n !== null)
    // PHP wraps each argument in an `argument` node - unwrap it, or every
    // argument the tracer inspects is a container rather than the expression.
    .map((n) => (n.type === 'argument' ? (n.namedChildren.find((c) => c !== null) ?? n) : n));
}

/**
 * The parameter NAMES of a function, in whichever way its grammar spells them.
 * We need names, not types: to follow a value into a function we bind the
 * incoming taint to the name the body will use to refer to it.
 */
function parameterNames(fnNode: Node): string[] {
  const container = fnNode.childForFieldName('parameters');
  if (!container) {
    // Single-parameter arrow function: `x => ...` has no parameter list node.
    const bare = fnNode.childForFieldName('parameter');
    return bare ? [text(bare)] : [];
  }
  const names: string[] = [];
  for (const child of container.namedChildren) {
    if (!child) continue;
    if (VARIABLE_NODES.has(child.type)) {
      names.push(text(child));
      continue;
    }
    // typed_parameter / required_parameter / formal_parameter / parameter_declaration
    const named =
      child.childForFieldName('name') ?? child.childForFieldName('pattern') ?? null;
    if (named) {
      names.push(text(named));
      continue;
    }
    const identifier = child.namedChildren.find(
      (c): c is Node => c !== null && VARIABLE_NODES.has(c.type),
    );
    names.push(identifier ? text(identifier) : '');
  }
  return names;
}

/** A function we can follow a value into. */
export interface LocalFunction {
  readonly name: string;
  readonly params: readonly string[];
  readonly body: Node;
}

const FUNCTION_TYPES_BY_LANGUAGE = FUNCTION_NODES;

/**
 * Index every function in a tree by name. Exported because the cross-file
 * resolver needs exactly the same view of another file that the tracer has of
 * this one - if the two disagreed about what counts as a function, a value
 * could be followed into something that is not there.
 */
export function collectFunctions(root: Node, language: LanguageId): Map<string, LocalFunction> {
  const functionTypes = new Set(FUNCTION_TYPES_BY_LANGUAGE[language] ?? []);
  const found = new Map<string, LocalFunction>();

  const register = (name: string, fnNode: Node): void => {
    if (!name || found.has(name)) return;
    const body = fnNode.childForFieldName('body') ?? fnNode;
    found.set(name, { name, params: parameterNames(fnNode), body });
  };

  const visit = (node: Node): void => {
    if (functionTypes.has(node.type)) {
      const nameNode = node.childForFieldName('name');
      if (nameNode) register(text(nameNode), node);
    }
    // `const helper = (x) => {...}` - the name is on the declarator.
    const value = node.childForFieldName('value') ?? node.childForFieldName('right');
    const name = node.childForFieldName('name') ?? node.childForFieldName('left');
    if (value && name && functionTypes.has(value.type)) register(text(name), value);

    for (const child of node.namedChildren) if (child) visit(child);
  };
  visit(root);
  return found;
}

/**
 * How the tracer asks "is there a function called X in a file this one imports?"
 * Implemented by src/taint/project.ts; absent when scanning a single file.
 */
export interface CrossFileResolver {
  resolve(
    fromPath: string,
    name: string,
  ): { readonly path: string; readonly fn: LocalFunction } | null;
  /** Called when several files export that name and we refuse to guess. */
  noteAmbiguous(fromPath: string, name: string, candidates: number): void;
}

/* -------------------------------------------------------------------------- *
 * The tracer
 * -------------------------------------------------------------------------- */

interface Scope {
  readonly body: Node;
  readonly env: Map<string, Taint>;
  /**
   * Which file this scope's nodes live in. Once the tracer can step into
   * another file, "the current file" stops being a property of the SCAN and
   * becomes a property of wherever we happen to be standing.
   */
  readonly filePath: string;
  /** Local names holding a prepared statement handle. See PREPARE_CALLS. */
  readonly prepared: Set<string>;
  /**
   * Local names holding a StringBuilder / StringBuffer.
   *
   * `append` is a genuine XSS sink on a servlet writer - `response.getWriter()
   * .append(userInput)` writes straight to the page. It is nothing of the sort
   * on a StringBuilder, which is just a rope of characters. Without the
   * distinction, `sb.append(param)` reported XSS on every string-building loop
   * in Java, and adding receiver mutation was about to make that shape the
   * commonest thing the tracer sees.
   */
  readonly builders: Set<string>;
  /**
   * Set only while analysing a called function, so the caller can learn what
   * the callee gives BACK. `const clean = strip(dirty)` needs this.
   */
  readonly onReturn?: (taint: Taint | null, node: Node) => void;
}

/**
 * Where this trace RAN OUT, counted.
 *
 * The engine has always documented these limits in prose - "call chains deeper
 * than four functions are not followed" sits in the capability block on every
 * scan. But a general disclaimer and a measurement are different products. The
 * disclaimer says the gap could exist; the count says it happened 38 times in
 * YOUR code, which is the version a person can act on.
 *
 * A comment in this file used to claim these were "recorded as misses". They
 * were not - they returned null and vanished. Now the claim is true.
 */
export interface TraceLimits {
  /** Calls not followed because the chain already ran four deep. */
  readonly depthTruncations: number;
  /** Calls not re-entered because the function was already on the stack. */
  readonly recursionStops: number;
  /** Hops through a function we do not model, where taint was carried anyway. */
  readonly unmodelledHops: number;
}

export interface TraceOutcome {
  readonly flows: readonly FlowResult[];
  readonly sanitized: readonly SanitizedFlow[];
  readonly limits: TraceLimits;
}

export function traceFile(
  file: ParsedFile,
  language: LanguageId,
  resolver?: CrossFileResolver,
  /**
   * Absolute path -> the path a human should see. Resolution needs absolute
   * paths; reports need short ones. Keeping both straight matters more once a
   * single finding can name two different files.
   */
  toDisplay: (absolutePath: string) => string = (p) => p,
): TraceOutcome {
  /**
   * Blind spots, counted by SITE rather than by visit.
   *
   * A note on why, because the obvious reading of this code is wrong. A scan
   * reported "3 hops through functions we do not model" while the printed flow
   * paths showed only two, which looks exactly like double-counting: the
   * tracer can reach one expression from both the expression walk and the
   * statement walk, so a tally would plausibly count it twice.
   *
   * It was measured, and that is NOT what was happening - raw visits equalled
   * distinct sites on every corpus tried. The third hop was a real, separate
   * site (`db.Query(query)`, whose tainted RESULT flows on) that simply never
   * reached a sink, so no finding carried it.
   *
   * The Set stays, because counting a site twice would be wrong if the walk
   * ever changed. But it fixed nothing that was broken, and saying otherwise
   * here would be the same kind of confident wrong answer this file exists to
   * avoid. What was actually wrong was the LABEL - see the blind-spot text in
   * core/score.ts, which now says these are scan-wide rather than per-finding.
   */
  const seenDepth = new Set<string>();
  const seenRecursion = new Set<string>();
  const seenUnmodelled = new Set<string>();
  const siteOf = (n: Node, filePath: string) => `${filePath}#${n.id}`;

  const dictionary = TAINT_DICTIONARIES[language];
  // Java and Go: no dictionary yet. Reported in the coverage section, not hidden.
  const limits = (): TraceLimits => ({
    depthTruncations: seenDepth.size,
    recursionStops: seenRecursion.size,
    unmodelledHops: seenUnmodelled.size,
  });

  if (!dictionary) return { flows: [], sanitized: [], limits: limits() };

  const functionTypes = new Set(FUNCTION_NODES[language] ?? []);
  const results: FlowResult[] = [];
  const sanitized: SanitizedFlow[] = [];

  /**
   * The file we are standing in RIGHT NOW - not necessarily the file we were
   * asked to scan. Saved and restored around every cross-file descent.
   *
   * A single mutable is safe here only because the walk is depth-first and
   * synchronous: steps created during a descent get the callee's path, and the
   * restore happens before the caller creates any more. If this ever becomes
   * async, this variable becomes a bug.
   */
  let currentPath = file.path;

  // Scopes are processed as a queue. The module top level is the first one;
  // every nested function becomes another, seeded with a SNAPSHOT of the
  // enclosing notebook so that callbacks can see variables defined outside them.
  const queue: Scope[] = [
    {
      body: file.root,
      env: new Map(),
      filePath: file.path,
      prepared: new Set(),
      builders: new Set(),
    },
  ];

  /* ---------------------------------------------------------------- *
   * PHASE 3b: the call graph.
   *
   * Phase 3a stopped at the function boundary. `helper(req.query.id)` was the
   * end of the trace, because guessing what `helper` does would have been
   * exactly the kind of confident wrong answer this project refuses to give.
   *
   * Now we do not guess - we go and look. Every function defined in this file
   * is indexed by name; when a tainted value is passed to one, we bind it to
   * the parameter name and analyse that body with the taint already in place.
   * Sinks inside the callee become findings whose path spans both functions.
   *
   * Three guards keep this honest and terminating:
   *   MAX_CALL_DEPTH  stop after 4 nested calls. Deeper chains are missed and
   *                   that is a stated gap, not a silent one.
   *   callStack       a function already being analysed is not re-entered, so
   *                   recursion cannot loop forever.
   *   descendCache    each call site is followed once; both the expression path
   *                   and the statement path read the same cached answer.
   * ---------------------------------------------------------------- */
  const MAX_CALL_DEPTH = 4;
  const localFunctions = new Map<string, LocalFunction>();
  const callStack: string[] = [];
  const descendCache = new Map<string, Taint | null>();

  const localFunctionsFound = collectFunctions(file.root, language);
  for (const [name, fn] of localFunctionsFound) localFunctions.set(name, fn);

  // Assigned after `walk` exists; `evaluateCall` reaches it through this box.
  let descendIntoLocalCall: (
    node: Node,
    scope: Scope,
    depth: number,
  ) => { handled: boolean; taint: Taint | null } = () => ({ handled: false, taint: null });

  const step = (
    kind: FlowStep['kind'],
    node: Node,
    description: string,
    sanitizesKinds?: readonly SinkKind[],
  ): InternalStep => ({
    kind,
    location: nodeLocation(node, toDisplay(currentPath)),
    description,
    ...(sanitizesKinds ? { sanitizesKinds } : {}),
  });

  /** Does this expression's text look like a known attacker-controlled source? */
  const sourceTaint = (node: Node, expression: string): Taint | null => {
    for (const source of dictionary.sources) {
      if (!source.pattern.test(expression)) continue;
      return {
        steps: [
          step('source', node, `\`${expression.slice(0, 60)}\` is ${source.description}`),
        ],
        sanitizedFor: new Set(),
        origin: expression.slice(0, 60),
        unknownHops: [],
      };
    }
    return null;
  };

  const addStep = (taint: Taint, node: Node, description: string): Taint => ({
    steps: [...taint.steps, step('propagation', node, description)],
    sanitizedFor: taint.sanitizedFor,
    origin: taint.origin,
    unknownHops: taint.unknownHops,
  });

  /**
   * The heart of it: "is this expression dirty, and how did it get that way?"
   * Returns null for "clean, or we cannot tell" - deliberately the same answer,
   * because the engine never claims cleanliness it has not proven.
   */
  const evaluate = (node: Node | null, scope: Scope, depth = 0): Taint | null => {
    if (!node || depth > 24) return null;
    const expression = text(node);

    if (UNWRAP_NODES.has(node.type)) {
      /*
       * Take the VALUE, not the first named child.
       *
       * Every wrapper here used to be unwrapped by grabbing child 0, which is
       * right for `(x)` and `await x` and wrong for a Java cast: the first
       * named child of `(String) map.get("k")` is the type name `String`, so
       * the tracer solemnly evaluated the word "String" and reported the value
       * clean. `value` is the field the Java grammar gives the expression; the
       * last named child is the fallback for wrappers that name no field.
       */
      const inner =
        node.childForFieldName('value') ??
        (node.type === 'cast_expression'
          ? node.namedChildren.filter((c): c is Node => c !== null).pop() ?? null
          : node.namedChildren.find((c): c is Node => c !== null) ?? null);
      return evaluate(inner, scope, depth + 1);
    }

    // Go writes `a, b := f(), g()`. A single-valued list is just the value.
    // A multi-valued one we do not split - documented as a Go imprecision.
    if (node.type === 'expression_list' && node.namedChildCount === 1) {
      return evaluate(node.namedChildren[0] ?? null, scope, depth + 1);
    }

    if (VARIABLE_NODES.has(node.type)) {
      const known = scope.env.get(expression);
      if (known) return known;
      return sourceTaint(node, expression);
    }

    if (MEMBER_NODES.has(node.type)) {
      // `req.query.id` matches a source pattern as a whole.
      const direct = sourceTaint(node, expression);
      if (direct) return direct;
      // Otherwise dirt flows outward: if `data` is dirty, so is `data.name`.
      const object =
        node.childForFieldName('object') ??
        node.childForFieldName('value') ??
        node.namedChildren.find((c): c is Node => c !== null) ??
        null;
      const inner = evaluate(object, scope, depth + 1);
      return inner ? addStep(inner, node, `read out of a tainted value as \`${expression.slice(0, 50)}\``) : null;
    }

    if (node.type === 'binary_expression' || node.type === 'binary_operator') {
      const operator = node.childForFieldName('operator')?.text ?? '';
      // `.` is PHP's concatenation operator. Every other language here uses
      // `+`, and `%` is Python's old-style format.
      if (operator !== '+' && operator !== '%' && operator !== '.') return null;
      const left = evaluate(node.childForFieldName('left'), scope, depth + 1);
      const right = evaluate(node.childForFieldName('right'), scope, depth + 1);
      const taint = left ?? right;
      if (!taint) return null;
      // If both sides are dirty, keep the union of what has been washed.
      const merged: Taint =
        left && right
          ? {
              steps: left.steps,
              sanitizedFor: new Set(
                [...left.sanitizedFor].filter((k) => right.sanitizedFor.has(k)),
              ),
              origin: left.origin,
              unknownHops: [...left.unknownHops, ...right.unknownHops],
            }
          : taint;
      return addStep(
        merged,
        node,
        operator === '%'
          ? 'formatted into a larger string with %'
          : `concatenated into a larger string with ${operator}`,
      );
    }

    if (CONTAINER_NODES.has(node.type)) {
      for (const element of node.namedChildren) {
        if (!element) continue;
        const taint = evaluate(element, scope, depth + 1);
        if (taint) {
          return addStep(
            taint,
            node,
            'placed into a container - we taint the container whole, not per element',
          );
        }
      }
      return null;
    }

    if (STRING_NODES.has(node.type)) {
      // A template literal or f-string: the dirt is inside the ${...} / {...}.
      for (const child of node.namedChildren) {
        if (!child) continue;
        // PHP splices a variable into a double-quoted string with no wrapper
        // node at all: "id = $id" holds a `variable_name` child directly, where
        // JS and Python wrap theirs in a substitution node. So the variable IS
        // the interpolation, and it is evaluated in place.
        const inner = INTERPOLATION_NODES.has(child.type)
          ? (child.namedChildren.find((c): c is Node => c !== null) ?? null)
          : VARIABLE_NODES.has(child.type) || MEMBER_NODES.has(child.type)
            ? child
            : null;
        if (!inner) continue;
        const taint = evaluate(inner, scope, depth + 1);
        if (taint) return addStep(taint, node, 'interpolated into a string template');
      }
      return null;
    }

    // `cond ? a : b` and Python's `a if cond else b`. We do not evaluate the
    // condition - if EITHER branch can be dirty, the result can be dirty.
    if (node.type === 'ternary_expression' || node.type === 'conditional_expression') {
      for (const child of node.namedChildren) {
        if (!child) continue;
        const taint = evaluate(child, scope, depth + 1);
        if (taint) return addStep(taint, node, 'returned from one branch of a conditional');
      }
      return null;
    }

    if (CALL_NODES.has(node.type)) {
      return evaluateCall(node, scope, depth);
    }

    return null;
  };

  const evaluateCall = (node: Node, scope: Scope, depth: number): Taint | null => {
    const { text: calleeText, receiver } = calleeOf(node);
    const name = lastSegment(calleeText);
    const args = argumentsOf(node);

    // Is the CALL ITSELF a source? e.g. searchParams.get('q'), input().
    //
    // Test the callee only, never the whole call. Testing the whole call text
    // was a real bug: `parseInt(req.query.id)` contains "req.query", so the
    // sanitiser was skipped and the SANITISED value was reported as a verified
    // vulnerability. A source is about where a value comes FROM, not about what
    // characters appear anywhere inside the expression.
    const asSource = sourceTaint(node, `${calleeText}(`);
    if (asSource) return asSource;

    // A sanitiser: the value stays traceable, but is marked washed for the
    // kinds this particular soap actually works on.
    const sanitizer = dictionary.sanitizers.find((s) => s.names.includes(name));
    if (sanitizer) {
      for (const arg of args) {
        const taint = evaluate(arg, scope, depth + 1);
        if (!taint) continue;
        return {
          steps: [
            ...taint.steps,
            step(
              'sanitizer',
              node,
              `passed through \`${name}()\` - ${sanitizer.description}`,
              sanitizer.kinds,
            ),
          ],
          sanitizedFor: new Set([...taint.sanitizedFor, ...sanitizer.kinds]),
          origin: taint.origin,
          unknownHops: taint.unknownHops,
        };
      }
      return null;
    }

    // A propagator: dirt survives. Check the receiver first (`dirty.trim()`),
    // then the arguments (`String(dirty)`, `",".join(dirty)`).
    if (dictionary.propagators.names.includes(name)) {
      let taint = evaluate(receiver, scope, depth + 1);
      if (!taint) {
        for (const arg of args) {
          taint = evaluate(arg, scope, depth + 1);
          if (taint) break;
        }
      }
      return taint ? addStep(taint, node, `passed through \`${name}()\``) : null;
    }

    /* A function we can actually read - in this file or, since cross-file
     * resolution, in a file this one imports. Ask the descent whether it
     * HANDLED the call, not merely whether it produced taint: the two are
     * different answers, and conflating them was a real bug. The gate used to
     * be `localFunctions.get(name)`, so a sanitiser living in another module
     * was never consulted and its call fell through to the "unknown function"
     * branch below, which preserves taint. Result: correctly-escaped code
     * reported as a vulnerability.                                          */
    const descended = descendIntoLocalCall(node, scope, depth);
    if (descended.handled) return descended.taint;

    /* ---- A function we do not model. The hardest judgement call here. ----
     *
     * Two wrong answers were available:
     *
     *   Treat it as CLEAN. Safe-sounding, and it made the tool useless on real
     *   Java: OWASP's own benchmark writes
     *       param = URLDecoder.decode(request.getHeader("x"), "UTF-8");
     *   and dropping the taint at `decode` produced ZERO verified flows across
     *   2,766 files, every one of which is a known vulnerability.
     *
     *   Treat it as SANITISING. Never - assuming an unknown function fixes the
     *   problem is how scanners miss real bugs.
     *
     * What we do instead: the value keeps its taint, and the hop is recorded as
     * UNMODELLED. The path shows exactly where our knowledge ran out, and the
     * finding's limitations names the function. If `decode` had been a custom
     * sanitiser, the reader can see that in one glance and dismiss it.
     *
     * That is the honest version of a guess: make it, then show your work.  */
    let carried: Taint | null = null;
    for (const arg of args) {
      carried = evaluate(arg, scope, depth + 1);
      if (carried) break;
    }
    carried ??= evaluate(receiver, scope, depth + 1);
    if (!carried) return null;
    seenUnmodelled.add(siteOf(node, scope.filePath));

    return {
      steps: [
        ...carried.steps,
        step(
          'propagation',
          node,
          `passed through \`${name}()\`, which is NOT in our dictionary - we assume it ` +
            `preserves the value; if it actually sanitises, this trace is wrong`,
        ),
      ],
      sanitizedFor: carried.sanitizedFor,
      origin: carried.origin,
      unknownHops: [...carried.unknownHops, name],
    };
  };

  /* ---- sinks ---- */

  const buildPath = (taint: Taint, sinkNode: Node, kind: SinkKind, description: string): FlowStep[] => {
    // Convert sanitiser steps that do NOT cover this sink kind into ordinary
    // propagation steps, with the mismatch spelled out. This is where the
    // kind-scoping becomes visible to the user: "you escaped it for HTML, and
    // then put it in a SQL query".
    const steps: FlowStep[] = taint.steps.map((s) => {
      if (s.kind !== 'sanitizer') return { kind: s.kind, location: s.location, description: s.description };
      if (s.sanitizesKinds?.includes(kind)) {
        return { kind: s.kind, location: s.location, description: s.description };
      }
      return {
        kind: 'propagation',
        location: s.location,
        description:
          `${s.description} - NOTE: this does not make a value safe for a ${kind} sink, ` +
          `so the value is still dangerous here`,
      };
    });
    steps.push({
      kind: 'sink',
      location: nodeLocation(sinkNode, toDisplay(currentPath)),
      description,
    });
    return steps;
  };

  /**
   * A tainted value has arrived somewhere dangerous. Decide which of the two
   * outcomes it is - a finding, or a proof that this line is fine.
   *
   * Factored out of checkCallSink so a second kind of sink cannot get half of
   * this right. Both branches matter equally: forgetting the sanitised branch
   * would mean correctly-escaped code gets reported, and this project treats
   * shouting at correct code as the worse failure of the two.
   */
  const checkTaintAtSink = (
    taint: Taint,
    valueNode: Node,
    kind: SinkKind,
    /** A NOUN PHRASE. The message reads "... reaches ${description}". */
    description: string,
    /** The sink step's own wording, which may say more than the headline. */
    pathDescription = `reaches ${description}`,
  ): void => {
    if (taint.sanitizedFor.has(kind)) {
      sanitized.push({
        ruleId: SINK_KIND_RULE[kind],
        sinkNode: valueNode,
        kind,
        filePath: toDisplay(currentPath),
      });
      return;
    }
    results.push({
      ruleId: SINK_KIND_RULE[kind],
      kind,
      node: valueNode,
      sinkNode: valueNode,
      path: buildPath(taint, valueNode, kind, pathDescription),
      origin: taint.origin,
      sinkDescription: description,
      unknownHops: taint.unknownHops,
      filePath: toDisplay(currentPath),
    });
  };

  /**
   * A tainted argument dirties the object it was handed to.
   *
   *     sb.append(param);      ->  `sb` is now tainted
   *     argList.add(param);    ->  `argList` is now tainted
   *
   * The existing propagator model could not express this: it carries taint out
   * through a RETURN VALUE, and these calls either discard theirs or hand back
   * a boolean. `append` sat in the Java propagator list the whole time and
   * caught nothing.
   *
   * HONEST ABOUT THE IMPRECISION THIS BUYS. The taint lands on the whole
   * container, not on the element - so after
   *
   *     list.add(cleanValue);
   *     list.add(dirtyValue);
   *
   * every read out of `list` is treated as dirty, including the clean one. That
   * is the standard container-insensitive trade and it errs toward reporting.
   * It is written into the flow path ("collected into ...") and into the
   * capability block, because a new source of imprecision that nobody announced
   * is exactly the kind of quiet overclaim this engine is built against.
   */
  const checkMutation = (node: Node, scope: Scope): void => {
    const mutators = dictionary.mutators;
    if (!mutators || mutators.length === 0) return;

    const callee = calleeOf(node);
    const method = lastSegment(callee.text);
    if (!mutators.includes(method)) return;

    // We can only dirty something we can NAME. `a.b().c(dirty)` gives us no
    // variable to bind, so it is left alone rather than guessed at.
    const receiverName = lastSegment(text(callee.receiver));
    if (!receiverName || !/^[A-Za-z_$][\w$]*$/.test(receiverName)) return;

    for (const arg of argumentsOf(node)) {
      const taint = evaluate(arg, scope);
      if (!taint) continue;
      scope.env.set(
        receiverName,
        addStep(taint, node, `collected into \`${receiverName}\` via \`${method}()\``),
      );
      return;
    }
  };

  /**
   * The dangerous call took no arguments - the payload is already inside the
   * object. `pb.command(list); pb.start();` is the canonical shape.
   */
  const checkReceiverSink = (node: Node, scope: Scope): void => {
    const sinks = dictionary.receiverSinks;
    if (!sinks || sinks.length === 0) return;
    const callee = calleeOf(node);
    const method = lastSegment(callee.text);
    for (const sink of sinks) {
      if (!sink.methods.includes(method)) continue;
      if (!callee.receiver) continue;
      // `new ProcessBuilder(argList).start()` already fired as an ARGUMENT
      // sink on the constructor. Firing again on the receiver reports one bug
      // twice at one line. This shape only adds something when the payload was
      // loaded on an earlier line, which means the receiver is a plain name.
      if (CALL_NODES.has(callee.receiver.type)) continue;
      const taint = evaluate(callee.receiver, scope);
      if (!taint) continue;
      checkTaintAtSink(
        taint,
        node,
        sink.kind,
        sink.description,
        `reaches ${sink.description} via \`${method}()\` - the value was loaded into ` +
          `\`${lastSegment(text(callee.receiver))}\` on an earlier line, so this call carries no arguments`,
      );
      return;
    }
  };

  const checkCallSink = (node: Node, scope: Scope): void => {
    const callee = calleeOf(node);
    const name = lastSegment(callee.text);
    const wholeCall = text(node);
    const args = argumentsOf(node);

    for (const sink of dictionary.callSinks) {
      if (!sink.methods.includes(name)) continue;
      if (sink.requiredReceivers && sink.requiredReceivers.length > 0) {
        const receiver = callee.receiver ? text(callee.receiver) : '';
        const last = receiver.split(/[.\s(\[]/).filter(Boolean).pop() ?? receiver;
        if (!sink.requiredReceivers.some((name) => last === name)) continue;
      }
      if (sink.receiverPattern) {
        const receiver = callee.receiver ? text(callee.receiver) : '';
        if (!sink.receiverPattern.test(receiver)) continue;
      }
      if (sink.requiresShellOption && !sink.requiresShellOption.test(wholeCall)) continue;
      // The safe form of a deserialiser is the same call with a restriction
      // added. Seeing that restriction means this is the FIX, not the bug.
      if (sink.unlessOption && sink.unlessOption.test(wholeCall)) continue;

      // `append`/`write`/`print` on a StringBuilder is string assembly, not a
      // write to the page. Only the ones we KNOW are builders are excluded, so
      // an unknown receiver is still treated as a possible writer.
      if (sink.kind === 'xss' && scope.builders.has(lastSegment(text(callee.receiver)))) continue;

      // Executing a PREPARED statement: the arguments are bound parameters, not
      // the instruction. Recorded as a clean flow so the signature-based guess
      // at this line is withdrawn too - correct code should end up silent.
      if (sink.kind === 'sql' && scope.prepared.has(lastSegment(text(callee.receiver)))) {
        sanitized.push({
          ruleId: SINK_KIND_RULE[sink.kind],
          sinkNode: node,
          kind: sink.kind,
          filePath: toDisplay(currentPath),
        });
        continue;
      }

      const indexes =
        sink.argIndexes === 'all' ? args.map((_, index) => index) : sink.argIndexes;

      for (const index of indexes) {
        const arg = args[index];
        if (!arg) continue;

        // Ambiguous method names need the content to agree - but ONLY when we
        // can actually see the content. `db.query(sql)` shows us nothing: the
        // query text was built on an earlier line. There we trust the sink name
        // plus the traced flow instead. Demanding visible SQL in that case was
        // a real bug - it silently discarded the most common verified flow of
        // all, the one that goes through a variable.
        if (sink.contentCheck) {
          const built = analyzeStringExpression(arg, language);
          if (built.literalText.length > 0) {
            const looksRight =
              sink.contentCheck === 'sql'
                ? looksLikeSql(built.literalText)
                : looksLikeHtml(built.literalText);
            if (!looksRight) continue;
          }
        }

        const taint = evaluate(arg, scope);
        if (!taint) continue;

        // Properly washed for THIS kind of sink. Not a finding - and worth
        // recording, because it lets the scan RETRACT the signature-based
        // guess at this line instead of nagging about code that is provably
        // correct. Confirmed-clean is a result too.
        if (taint.sanitizedFor.has(sink.kind)) {
          sanitized.push({
            ruleId: SINK_KIND_RULE[sink.kind],
            sinkNode: node,
            kind: sink.kind,
            filePath: toDisplay(currentPath),
          });
          continue;
        }

        results.push({
          ruleId: SINK_KIND_RULE[sink.kind],
          kind: sink.kind,
          node: arg,
          sinkNode: node,
          path: buildPath(taint, node, sink.kind, `reaches ${sink.description} via \`${callee.text}()\``),
          origin: taint.origin,
          sinkDescription: sink.description,
          unknownHops: taint.unknownHops,
          filePath: toDisplay(currentPath),
        });
      }
    }
  };

  const checkAssignSink = (assignNode: Node, target: Node, value: Node, taint: Taint): void => {
    const name = lastSegment(text(target)).replace(/^["']|["']$/g, '');
    for (const sink of dictionary.assignSinks) {
      if (!sink.properties.includes(name)) continue;
      if (taint.sanitizedFor.has(sink.kind)) {
        sanitized.push({
          ruleId: SINK_KIND_RULE[sink.kind],
          sinkNode: assignNode,
          kind: sink.kind,
          filePath: toDisplay(currentPath),
        });
        continue;
      }
      results.push({
        ruleId: SINK_KIND_RULE[sink.kind],
        kind: sink.kind,
        node: value,
        sinkNode: assignNode,
        path: buildPath(taint, assignNode, sink.kind, `assigned to \`${text(target)}\` - ${sink.description}`),
        origin: taint.origin,
        sinkDescription: sink.description,
        unknownHops: taint.unknownHops,
        filePath: toDisplay(currentPath),
      });
    }
  };

  /* ---- the statement walk ---- */

  /** Does this node sit inside a branch or loop body within the current scope? */
  const underCondition = (node: Node, body: Node): boolean => {
    let current: Node | null = node.parent;
    while (current && current !== body) {
      if (CONDITIONAL_NODES.has(current.type)) return true;
      current = current.parent;
    }
    return false;
  };

  const assignmentParts = (node: Node): { target: Node; value: Node } | null => {
    const pairs: Array<[string, string]> = [
      ['left', 'right'],
      ['name', 'value'],
      ['key', 'value'],
    ];
    for (const [targetField, valueField] of pairs) {
      const target = node.childForFieldName(targetField);
      const value = node.childForFieldName(valueField);
      if (target && value) return { target, value };
    }
    return null;
  };

  const ASSIGNMENT_NODES = new Set([
    'assignment_expression', // JS/TS, Java
    'augmented_assignment_expression',
    'variable_declarator', // JS/TS, Java
    'assignment', // Python
    'augmented_assignment',
    'pair',
    'public_field_definition',
    'short_var_declaration', // Go  x := ...
    'assignment_statement', // Go  x = ...
    'var_spec', // Go  var x = ...
    'const_spec', // Go  const x = ...
    'property_element', // PHP  class property with a default
  ]);

  /** PHP statements that write their argument straight to the response body. */
  const ECHO_NODES = new Set(['echo_statement', 'print_intrinsic']);

  const walk = (node: Node, scope: Scope): void => {
    // A nested function is a separate notebook. Queue it, don't descend.
    if (node !== scope.body && functionTypes.has(node.type)) {
      const body = node.childForFieldName('body') ?? node;
      queue.push({
        body,
        env: new Map(scope.env),
        filePath: scope.filePath,
        prepared: new Set(scope.prepared),
        builders: new Set(scope.builders),
      });
      return;
    }

    /*
     * PHP `echo $x;` and `print $x;`.
     *
     * These are statements, not assignments and not calls, so neither of the
     * two shapes below sees them - and `echo` is the single most common way a
     * PHP page writes attacker data into a page. The value it prints is the
     * same question an assign-sink asks, so it is routed there, with the `echo`
     * keyword itself standing in as the "property" being written.
     */
    if (ECHO_NODES.has(node.type)) {
      const keyword = node.child(0);
      for (const printed of node.namedChildren) {
        if (!printed) continue;
        const taint = evaluate(printed, scope);
        if (taint && keyword) checkAssignSink(node, keyword, printed, taint);
      }
    }

    if (ASSIGNMENT_NODES.has(node.type)) {
      const parts = assignmentParts(node);
      if (parts) {
        const taint = evaluate(parts.value, scope);
        if (taint) checkAssignSink(node, parts.target, parts.value, taint);

        // Record it in the notebook, but only for plain variable names.
        // `obj.field = dirty` is not tracked - tracking object fields properly
        // needs alias analysis, which is well beyond this phase.
        //
        // Go's `id, err := strconv.Atoi(x)` puts several names on the left. We
        // bind every one of them to the same taint. It is imprecise - only one
        // of the returned values really carries it - but erring this way keeps
        // the extremely common `value, err :=` idiom traceable, and it is
        // recorded in the Go coverage note rather than left as a surprise.
        const targetNames =
          parts.target.type === 'expression_list'
            ? parts.target.namedChildren.filter((c): c is Node => c !== null).map((c) => text(c))
            : [text(parts.target)];

        // `stmt, err := db.Prepare(sql)` - remember that `stmt` is a handle.
        // Go wraps the right-hand side in an expression_list, so unwrap first;
        // without this the check silently never fired.
        const valueNode =
          parts.value.type === 'expression_list' && parts.value.namedChildCount >= 1
            ? parts.value.namedChildren[0] ?? parts.value
            : parts.value;
        if (CALL_NODES.has(valueNode.type)) {
          const preparedBy = lastSegment(calleeOf(valueNode).text);
          if (/^(StringBuilder|StringBuffer)$/.test(preparedBy)) {
            for (const targetName of targetNames) scope.builders.add(targetName);
          }
          if (PREPARE_CALLS.has(preparedBy)) {
            for (const targetName of targetNames) scope.prepared.add(targetName);
          }
        }

        for (const targetName of targetNames) {
          if (!/^[A-Za-z_$][\w$]*$/.test(targetName)) continue;
          if (taint) {
            scope.env.set(targetName, addStep(taint, parts.target, `stored in \`${targetName}\``));
          } else if (scope.env.has(targetName) && underCondition(node, scope.body)) {
            // A clean write we cannot prove happens. Keep the dirt.
          } else {
            scope.env.delete(targetName); // reassigned to something clean
          }
        }

        // Still descend into the value: `const x = db.query(dirty)` has a sink
        // inside an assignment.
        //
        // All THREE dispatches, not just the argument one. `Process p =
        // pb.start();` is an assignment whose value is a receiver sink, and it
        // is the standard idiom - the return is captured even though the
        // dangerous act needs no arguments. Having one dispatch here and three
        // in the statement branch meant the same call was analysed differently
        // depending on whether anybody kept its result.
        for (const child of parts.value.namedChildren) if (child) walk(child, scope);
        if (CALL_NODES.has(parts.value.type)) {
          checkMutation(parts.value, scope);
          checkReceiverSink(parts.value, scope);
          checkCallSink(parts.value, scope);
        }
        return;
      }
    }

    if (node.type === 'return_statement') {
      const expression = node.namedChildren.find((c): c is Node => c !== null) ?? null;
      const returned = expression ? evaluate(expression, scope) : null;

      // Returning a page IS writing a page, in a framework where the view's
      // return value is the response body. Without this the most ordinary
      // reflected XSS in Flask - `return f"<h1>{name}</h1>"` - produced nothing
      // at all, and the correctly-escaped version of the same code looked
      // "clean" only because no sink existed for the escaping to be credited
      // against. Two cases passing for the wrong reason is worse than one
      // failing for the right one.
      // `return render_template_string("<h1>" + name)` is ALREADY a call sink.
      // Counting the return as a second sink reported the same bug twice at the
      // same line, and double-recorded the escaped version as clean. The return
      // only adds something when the returned expression IS the string.
      const returnsAString = expression !== null && !CALL_NODES.has(expression.type);

      if (
        dictionary.htmlReturnIsSink &&
        returned &&
        expression &&
        returnsAString &&
        looksLikeHtml(text(expression))
      ) {
        checkTaintAtSink(
          returned,
          expression,
          'xss',
          'an HTML response body returned by this function',
          'is returned from this function as an HTML string - in Flask/Django a view\'s ' +
            'return value IS the response body. We do not verify that this function is a ' +
            'route handler; if it is not, this string is rendered somewhere else instead.',
        );
      }

      // While analysing a called function, remember what it hands back.
      if (scope.onReturn) scope.onReturn(returned, node);
    }

    if (CALL_NODES.has(node.type)) {
      checkMutation(node, scope);
      checkReceiverSink(node, scope);
      checkCallSink(node, scope);
      // A bare call statement - `helper(req.query.id);` - is never evaluated as
      // an expression, so without this line the cross-function trace would only
      // work when the result was assigned to something. Easy gap to miss.
      descendIntoLocalCall(node, scope, 0);
    }

    for (const child of node.namedChildren) {
      if (child) walk(child, scope);
    }
  };

  /* ---- following a value into another function ---- */

  descendIntoLocalCall = (
    node: Node,
    scope: Scope,
    depth: number,
  ): { handled: boolean; taint: Taint | null } => {
    const { text: calleeText } = calleeOf(node);
    const calleeName = lastSegment(calleeText);

    /* ---- PHASE 3c: the function may live in another file. ----
     * We look locally first, then ask the project index. The index only
     * answers when the answer is UNAMBIGUOUS - one file, one function. If
     * three modules export `sanitize`, it says nothing and records that it
     * declined, which is printed in the report. Picking one at random would be
     * how a scanner ends up proving a path that does not exist.               */
    let local = localFunctions.get(calleeName);
    let targetPath = scope.filePath;
    if (!local && resolver) {
      const resolved = resolver.resolve(scope.filePath, calleeName);
      if (resolved) {
        local = resolved.fn;
        targetPath = resolved.path;
      }
    }
    if (!local) return { handled: false, taint: null };

    // Guards. Both are recorded as misses, never as invented answers.
    // The key includes the file, because two modules may both define `handle`.
    const stackKey = `${targetPath}::${local.name}`;
    if (callStack.length >= MAX_CALL_DEPTH) {
      seenDepth.add(siteOf(node, scope.filePath));
      return { handled: true, taint: null };
    }
    if (callStack.includes(stackKey)) {
      seenRecursion.add(siteOf(node, scope.filePath));
      return { handled: true, taint: null };
    }

    // Which arguments are dirty, and what is their history so far?
    const argumentTaints = argumentsOf(node).map((arg) => evaluate(arg, scope, depth + 1));

    /* ---- the cache key has to include WHICH ARGUMENTS ARE DIRTY ----
     *
     * It used to be the call site alone (`file#nodeId`), and that quietly
     * capped interprocedural tracing at ONE level.
     *
     * Why: the main walk visits every function body at top level, where the
     * parameters are unbound. So `return s2(x)` inside `s1` is evaluated once
     * with `x` clean, decides "no dirty arguments, nothing to do", and caches
     * NULL against that call site. Later, when the tracer descends into `s1`
     * from a real caller with `x` tainted, it reaches the same node id and gets
     * handed back that stale null. The taint dies one level in.
     *
     * The outermost call is never poisoned this way - it is only ever seen with
     * tainted arguments - which is exactly why `handler -> s1` worked and
     * `handler -> s1 -> s2` did not, and why it looked like a depth limit doing
     * its job. MAX_CALL_DEPTH is 4; the real reach was 1, and the capability
     * text claiming four was wrong by three.
     *
     * Keyed by taint shape, the same call with the same dirty arguments still
     * hits the cache - which is all the cache was ever for.                  */
    const taintShape = argumentTaints.map((t) => (t ? '1' : '0')).join('');
    const cacheKey = `${scope.filePath}#${node.id}#${taintShape}`;
    if (descendCache.has(cacheKey)) {
      return { handled: true, taint: descendCache.get(cacheKey) ?? null };
    }

    /**
     * A helper can be worth entering even with entirely clean arguments, if it
     * fetches attacker data ITSELF:
     *
     *     function readId(req) { return req.query.id; }
     *     const id = readId(req);          // <- `req` alone is not a source
     *     db.query("... " + id);
     *
     * `req` on its own does not match any source pattern (we only recognise
     * `req.query`-shaped expressions), so the argument looks clean and the old
     * check bailed out. Peeking at whether the body mentions a source at all is
     * a cheap text test that unlocks this very common shape.
     */
    const bodyText = (local.body.text ?? '').slice(0, 4000);
    const bodyFetchesASource = dictionary.sources.some((source) => source.pattern.test(bodyText));

    if (!argumentTaints.some((t) => t !== null) && !bodyFetchesASource) {
      descendCache.set(cacheKey, null);
      return { handled: true, taint: null };
    }

    // Bind each dirty argument to the NAME the callee will use for it. This one
    // line is the whole idea of interprocedural analysis: the value does not
    // change, only what it is called.
    const env = new Map<string, Taint>();
    local.params.forEach((parameter, index) => {
      const taint = argumentTaints[index];
      if (!parameter || !taint) return;
      env.set(
        parameter,
        addStep(
          taint,
          node,
          `passed into \`${local.name}()\` as parameter \`${parameter}\``,
        ),
      );
    });
    if (env.size === 0 && !bodyFetchesASource) {
      descendCache.set(cacheKey, null);
      return { handled: true, taint: null };
    }

    let returned: Taint | null = null;
    const calleeScope: Scope = {
      body: local.body,
      env,
      filePath: targetPath,
      prepared: new Set<string>(),
      builders: new Set<string>(),
      onReturn: (taint, returnNode) => {
        if (taint && !returned) {
          returned = addStep(taint, returnNode, `returned from \`${local.name}()\``);
        }
      },
    };

    callStack.push(stackKey);
    // Step into the callee's file for the duration of the descent, so every
    // hop recorded in there points at the right file and line. Restored below.
    const callerPath = currentPath;
    currentPath = targetPath;
    if (local.body.type === 'statement_block' || local.body.namedChildCount > 0) {
      for (const child of local.body.namedChildren) {
        if (child) walk(child, calleeScope);
      }
    }
    // A concise arrow body (`x => f(x)`) is an expression, not a block: its
    // value IS the return value, so evaluate it directly.
    if (local.body.type !== 'statement_block' && local.body.type !== 'block') {
      const direct = evaluate(local.body, calleeScope);
      if (direct && !returned) {
        returned = addStep(direct, local.body, `returned from \`${local.name}()\``);
      }
    }
    currentPath = callerPath;
    callStack.pop();

    descendCache.set(cacheKey, returned);
    return { handled: true, taint: returned };
  };

  // Process every scope. `queue` grows as nested functions are discovered.
  let processed = 0;
  while (processed < queue.length && processed < 500) {
    const scope = queue[processed];
    processed++;
    if (!scope) continue;
    currentPath = scope.filePath;
    for (const child of scope.body.namedChildren) {
      if (child) walk(child, scope);
    }
  }

  return { flows: results, sanitized, limits: limits() };
}

export { type TaintDictionary };
