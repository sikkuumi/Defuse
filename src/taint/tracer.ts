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
import { expressionIsFullyGuarded } from '../rules/lib/guards.js';
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
  /**
   * Set when this taint is sitting in a NAMED COMPARTMENT of an object rather
   * than being the object itself - `req.setAttribute("k", dirty)` leaves `req`
   * carrying a compartmented taint, `sb.append(dirty)` does not.
   *
   * It only matters in one place: an unmodelled call carries its receiver's
   * taint, and for a compartmented receiver that is wrong unless the call is
   * actually reading the compartment. Holds the reader method names that may.
   */
  readonly compartment?: readonly string[] | undefined;
  /**
   * Set when this taint SURVIVED a clean write only because the write was
   * inside a branch we cannot evaluate.
   *
   * The rule that keeps it - "a conditional write cannot PROVE a value clean" -
   * is deliberately conservative and right for a GUESS: it errs toward
   * reporting a value that might be clean rather than staying silent about one
   * that might be dirty. It is not right for a PROOF. Nothing was followed at
   * that point; an assumption was made, and `flowVerifiedFinding()` goes on to
   * print "this is not a pattern guess - the data flow was followed".
   *
   * Django drew this out. In contrib/admin/options.py a tainted `msg` is
   * assigned in an `except` block at line 1601 and a clean literal `msg` is
   * assigned in an `elif` forty lines later; the sink at 1646 is reachable only
   * through the second. The trace printed seven correct-looking hops across two
   * files and claimed proof of a flow that cannot happen.
   *
   * So the taint still travels and the finding is still reported - the caution
   * is preserved exactly - but it is reported as signature-based, because that
   * is what it is.
   */
  readonly branchAssumed?: boolean | undefined;
  /**
   * Set when this taint passed through a write into a COLLECTION THAT TOOK MORE
   * THAN ONE ELEMENT.
   *
   *     values.add("safe");
   *     values.add(dirty);
   *     values.add("alsosafe");
   *     out.println(values.get(2));     // which one is this?
   *
   * The tracer taints the container whole and says so in the path - "collected
   * into `values` via `add()`" - and then labelled the finding flow-verified
   * anyway. The admission and the claim contradicted each other inside one
   * report.
   *
   * Same treatment as branchAssumed, for the same reason: the taint still
   * travels, the finding is still reported, and only the LABEL changes. One
   * write leaves this unset, because then the value read is the value written
   * and the proof is real. Accumulators never set it - see elementMutators.
   */
  readonly containerGuess?: boolean | undefined;
  /**
   * The container this taint IS took more than one element write. On its own
   * that changes nothing - see ReceiverState.java, where `argList` takes three
   * adds and is then handed WHOLE to ProcessBuilder. Every element reaches the
   * process, so there is no ambiguity and the proof stands.
   *
   * The ambiguity only appears when something reads ONE element back out. So
   * this marks the container, and `containerGuess` is set later, at the read.
   */
  readonly collectedMany?: boolean | undefined;
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
  /**
   * The value reached this sink only because a clean write was skipped for
   * being conditional. The finding is still REPORTED - a missed bug is the one
   * failure this scanner cannot see in itself - but it is reported as a guess,
   * because a branch was assumed rather than followed. See branchAssumed.
   */
  readonly branchAssumed?: boolean;
  /**
   * The value reached this sink out of a collection that took several elements,
   * so which one came back is a guess. Reported, not certified. See
   * containerGuess.
   */
  readonly containerGuess?: boolean;
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
  /*
   * C nests the name one level down: a function_definition has a `declarator`
   * (the function_declarator) which in turn has the `declarator` that is the
   * identifier. There is no `name` field anywhere on it, which is why
   * functionNameOf() below exists - without it collectFunctions found zero C
   * functions and every cross-function trace in the language stopped dead at
   * the call, silently.
   */
  c: ['function_definition'],
  cpp: ['function_definition', 'lambda_expression'],
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

/**
 * Assignment targets that bind SEVERAL names at once.
 *
 *     const { syncUrl } = req.body;
 *     const [first] = request.args.getlist("x");
 *
 * The tracer read the whole pattern as one name - literally the string
 * "{ syncUrl }" - which matches nothing anyone ever looks up, so the taint was
 * recorded under a key no read could find and every destructured request field
 * came out clean.
 *
 * This is not an exotic shape. It is how modern JavaScript and TypeScript read
 * request fields, and it silently defeated every rule at once: a Gemini-written
 * Express app had `const { syncUrl } = req.body` two lines above an SSRF, and
 * the trace died at the brace.
 *
 * Every name in the pattern is bound to the taint of the whole right-hand side.
 * That is the container rule again - if the object is dirty, everything read
 * out of it is treated as dirty - and it errs toward reporting.
 */
const DESTRUCTURING_NODES = new Set([
  'object_pattern', // JS/TS  const { a, b } = x
  'array_pattern', // JS/TS  const [a, b] = x
  'pattern_list', // Python a, b = x
  'tuple_pattern',
  'list_pattern',
]);

/** Every plain name a destructuring pattern introduces, however nested. */
function namesBoundBy(pattern: Node): string[] {
  const names: string[] = [];
  const visit = (node: Node, depth: number): void => {
    if (depth > 6) return;
    for (const child of node.namedChildren) {
      if (!child) continue;
      // `{ a: renamed }` - the NAME the body will use is on the right.
      if (child.type === 'pair_pattern' || child.type === 'object_assignment_pattern') {
        const value = child.childForFieldName('value') ?? child.namedChildren[1] ?? null;
        if (value) visit(value.type === 'identifier' ? child : value, depth + 1);
        if (value && VARIABLE_NODES.has(value.type)) names.push(text(value));
        continue;
      }
      if (VARIABLE_NODES.has(child.type) || child.type === 'shorthand_property_identifier_pattern') {
        names.push(text(child));
        continue;
      }
      visit(child, depth + 1);
    }
  };
  visit(pattern, 0);
  return names;
}

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

/**
 * Wrappers whose FIRST named child is the type and whose LAST is the value.
 *
 * Everything else in UNWRAP_NODES puts the value first, which is why grabbing
 * child 0 worked for years before a Java cast walked in. This is the third
 * time the same shape has turned up wearing different clothes:
 *
 *     (String) map.get("k")        cast_expression   [type, value]
 *     <string>req.query.path       type_assertion    [type, value]
 *     req.query.path as string     as_expression     [value, type]   <- NOT here
 *
 * The first two look nothing alike and parse identically. The third looks
 * almost the same as the second and parses backwards, so it must stay on the
 * first-child path - which is the whole reason this is a set of node types
 * and not a guess about which spelling means a cast.
 *
 * `type_assertion` was in UNWRAP_NODES from the beginning and still did not
 * work, because being listed as a wrapper only says the node should be seen
 * through; it says nothing about which side the value is on. The tracer
 * solemnly evaluated the word `string` and reported the value clean. Found by
 * ts-only-syntax.ts, which was written to falsify the claim that TypeScript
 * behaves "identically to JavaScript" - and did, on the first run.
 */
const TYPE_FIRST_WRAPPERS = new Set(['cast_expression', 'type_assertion']);

/**
 * Binary operators whose result can still be attacker-chosen.
 *
 * Deliberately a short list. Every operator NOT here - `==`, `<`, `instanceof`,
 * `-`, `*` - produces a value whose shape the attacker no longer controls, and
 * carrying taint across those would manufacture flows that do not exist.
 * Arithmetic is the clearest case: whatever `dirty - 1` is, it is a number, and
 * a number cannot be a shell command.
 */
const BINARY_CARRIERS = new Set([
  '+', // concatenation in every language here, and addition
  '%', // Python's old-style format string
  '.', // PHP concatenation
  '??', // JS/TS nullish coalescing
  '||', // returns the left operand when it is truthy
  '&&', // returns the left operand when it is falsy
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
  /*
   * C and C++: `obj.field`, `ptr->field`, and `s.c_str`.
   *
   * Its receiver sits in the `argument` field rather than `object`, which is
   * why the lookup below tries several names. Without this entry `s.c_str()`
   * had no receiver at all, so a tainted std::string went clean the moment
   * anybody called the one method that gets the bytes out of it - which is the
   * only way a std::string ever reaches system().
   */
  'field_expression',
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

/**
 * The loop variable and the collection of a for-each, per grammar.
 *
 * Every language spells this differently and two of them hide the parts inside
 * an intermediate node, which is why a single childForFieldName() call would
 * have worked for Java and quietly returned nothing for the rest - the same
 * shape of mistake as the if-statement's `consequence` vs `body`, recorded in
 * rules/lib/guards.ts.
 */
const FOREACH_NODES = new Set([
  'enhanced_for_statement', // Java   for (String v : values)
  'for_in_statement',       // JS/TS  for (const v of values)
  'for_statement',          // Python for v in values      (also Go's plain for)
  'for_range_loop',         // Go     for _, v := range values
  'foreach_statement',      // PHP    foreach ($values as $v)
]);

interface ForeachBinding {
  readonly name: Node;
  readonly iterable: Node;
}

function foreachBinding(node: Node): ForeachBinding | null {
  // Java: `name` and `value` fields. JS/TS and Python: `left` and `right`.
  const name = node.childForFieldName('name') ?? node.childForFieldName('left');
  const iterable = node.childForFieldName('value') ?? node.childForFieldName('right');
  if (name && iterable) return { name, iterable };

  // Go hides both inside a range_clause child; PHP has no fields at all and
  // spells it `foreach (EXPR as $v)`, so the last variable before the body is
  // the binding and the first expression is the collection.
  const range = node.namedChildren.find((c): c is Node => c?.type === 'range_clause');
  if (range) {
    const left = range.childForFieldName('left');
    const right = range.childForFieldName('right');
    if (left && right) {
      // `for _, v := range values` - the VALUE is the second name, not the index.
      const names = left.namedChildren.filter((c): c is Node => c !== null);
      const chosen = names.length > 1 ? names[names.length - 1] : names[0];
      if (chosen) return { name: chosen, iterable: right };
    }
    return null;
  }

  if (node.type === 'foreach_statement') {
    const parts = node.namedChildren.filter((c): c is Node => c !== null);
    const body = node.childForFieldName('body');
    const beforeBody = body ? parts.filter((c) => c.startIndex < body.startIndex) : parts;
    const iterablePhp = beforeBody[0];
    const namePhp = beforeBody[beforeBody.length - 1];
    // `foreach ($a as $k => $v)` puts the pair in a `pair` node; take its value.
    const resolved =
      namePhp?.type === 'pair' || namePhp?.type === 'by_ref'
        ? namePhp.namedChildren[namePhp.namedChildCount - 1] ?? namePhp
        : namePhp;
    if (iterablePhp && resolved && iterablePhp !== resolved) {
      return { name: resolved, iterable: iterablePhp };
    }
  }
  return null;
}

/**
 * Calls that APPLY a function to every element of a collection.
 *
 * Deliberately tiny. These are the shapes where naming a sanitiser is the same
 * as calling it on each element; anything looser would let an arbitrary
 * callback argument read as proof of safety.
 */
const HIGHER_ORDER_APPLIERS = new Set(['map', 'imap', 'starmap', 'forEach']);

/** Comprehensions, which apply their element expression to every item. */
const COMPREHENSION_NODES = new Set([
  'list_comprehension',
  'dictionary_comprehension',
  'set_comprehension',
  'generator_expression',
]);

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
 * Strip a C declarator down to the name it declares.
 *
 * `char *user = getenv("X")` gives an assignment whose TARGET is the whole
 * declarator, `*user`, not the identifier. The binding loop below rejects any
 * name that is not a plain identifier - a deliberate guard against binding
 * taint to something it cannot name - so `*user` was silently dropped, `user`
 * read as clean, and every C flow through a pointer variable died on the
 * declaration line.
 *
 * It was invisible because the shapes that DO work are common enough to look
 * like success: `char buf[64]` is an array_declarator whose text is `buf[64]`,
 * whose last segment is a clean name, and a plain `p = argv[1]` never goes
 * through a declarator at all. Only the pointer form broke, which is most of
 * real C.
 *
 * Deliberately conservative: it removes leading `*` and `&` and any array
 * suffix, and returns the input unchanged if what is left is not a plain
 * identifier. A declarator this cannot reduce is still refused rather than
 * guessed at.
 */
function stripDeclarator(value: string): string {
  const stripped = value.trim().replace(/^[*&\s]+/, '').replace(/\s*\[[^\]]*\]\s*$/, '').trim();
  return /^[A-Za-z_$][\w$]*$/.test(stripped) ? stripped : value;
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
        fn.childForFieldName('argument') ?? // C/C++ field_expression
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
/**
 * The identifier a function definition binds, across grammars.
 *
 * Every language this engine supported until C put the name in a `name` field.
 * C puts it inside a declarator: function_definition.declarator is a
 * function_declarator, and ITS declarator is the identifier. Pointer-returning
 * functions nest one level deeper again (`char *f(void)` wraps the whole thing
 * in a pointer_declarator), so this walks down rather than assuming a depth.
 */
function functionNameOf(fnNode: Node): Node | null {
  const direct = fnNode.childForFieldName('name');
  if (direct) return direct;

  let node: Node | null = fnNode.childForFieldName('declarator');
  for (let depth = 0; node && depth < 6; depth++) {
    if (node.type === 'identifier' || node.type === 'field_identifier') return node;
    node = node.childForFieldName('declarator');
  }
  return null;
}

/** The parameter list, which C hangs off the declarator rather than the definition. */
function parameterListOf(fnNode: Node): Node | null {
  const direct = fnNode.childForFieldName('parameters');
  if (direct) return direct;
  let node: Node | null = fnNode.childForFieldName('declarator');
  for (let depth = 0; node && depth < 6; depth++) {
    const params = node.childForFieldName('parameters');
    if (params) return params;
    node = node.childForFieldName('declarator');
  }
  return null;
}

function parameterNames(fnNode: Node): string[] {
  const container = parameterListOf(fnNode);
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
      child.childForFieldName('name') ??
      child.childForFieldName('pattern') ??
      // C: parameter_declaration's name lives in `declarator`, and arrives with
      // its pointer stars attached (`*dst`). stripDeclarator removes them.
      child.childForFieldName('declarator') ??
      null;
    if (named) {
      names.push(stripDeclarator(text(named)));
      continue;
    }
    const identifier = child.namedChildren.find(
      (c): c is Node => c !== null && VARIABLE_NODES.has(c.type),
    );
    names.push(identifier ? text(identifier) : '');
  }
  return names;
}

/**
 * Parameter declarations with their FULL text, annotations included.
 *
 * `parameterNames` above deliberately returns only names, because binding a
 * caller's argument to a callee's name is all it is for. Recognising a Spring
 * binding needs the opposite half - the annotation sitting in front of the
 * name - so this returns both rather than making the other function lie about
 * what it does.
 */
function parameterDeclarations(fnNode: Node): Array<{ name: string; text: string; node: Node }> {
  const container = fnNode.childForFieldName('parameters');
  if (!container) return [];
  const out: Array<{ name: string; text: string; node: Node }> = [];
  for (const child of container.namedChildren) {
    if (!child) continue;
    const named =
      child.childForFieldName('name') ??
      child.childForFieldName('pattern') ??
      child.namedChildren.find((c): c is Node => c !== null && VARIABLE_NODES.has(c.type)) ??
      null;
    if (!named) continue;
    out.push({ name: text(named), text: text(child), node: child });
  }
  return out;
}


/**
 * DECLARED TYPES, so a receiver check can see past the variable's name.
 *
 * `receiverPattern` matches the TEXT in front of the call, which works for
 * `Runtime.getRuntime().exec(cmd)` and fails completely for the form
 * BenchmarkJava actually uses 188 times:
 *
 *     Runtime r = Runtime.getRuntime();
 *     r.exec(cmd);
 *
 * The receiver is `r`. Scoping `exec` to a runtime-looking receiver removed 16
 * false positives and 13 TRUE ones in the same change - a straight trade, not
 * an improvement, and the benchmark said so within a minute.
 *
 * Java, Go and TypeScript all write the type down at the declaration, so it is
 * there to be read. This is one shallow pass over the file collecting
 * `Type name = ...` and `var name Type`; it is not type inference and does not
 * pretend to be. A name declared twice with different types in one file is
 * recorded once and is a known imprecision - the alternative is threading a
 * type environment through every scope, which is a much larger change than the
 * problem justifies.
 */
function declaredTypes(root: Node, language: LanguageId): Map<string, string> {
  const types = new Map<string, string>();
  if (language !== 'java' && language !== 'go' && language !== 'typescript') return types;
  const visit = (node: Node, depth: number): void => {
    if (depth > 60) return;
    if (
      node.type === 'local_variable_declaration' ||
      node.type === 'field_declaration' ||
      node.type === 'var_declaration' ||
      node.type === 'var_spec'
    ) {
      const typeNode = node.childForFieldName('type');
      const typeText = typeNode ? text(typeNode) : '';
      if (typeText) {
        for (const child of node.namedChildren) {
          if (!child) continue;
          const nameNode =
            child.type === 'variable_declarator'
              ? child.childForFieldName('name')
              : VARIABLE_NODES.has(child.type)
                ? child
                : null;
          if (nameNode) types.set(text(nameNode), typeText);
        }
      }
    }
    for (const child of node.namedChildren) if (child) visit(child, depth + 1);
  };
  visit(root, 0);
  return types;
}


/**
 * The bare NAME of a receiver, with the language's decoration removed.
 *
 * PHP writes `$conn->query(...)`, and comparing "$conn" against a list holding
 * "conn" fails silently - which is exactly what happened: scoping the PHP SQL
 * sink dropped two asserted flow-verified findings and resurrected a false
 * positive in the safe fixture, because the receiver never matched anything and
 * the tracer stopped proving the sanitiser ran.
 *
 * Go pointers (`*db`), references (`&db`) and PHP's sigil are punctuation about
 * how the value is held, not about what it is. The last segment after a dot is
 * the object being called on.
 */
function ownerName(receiverText: string): string {
  const last = receiverText.split(/[.\s(\[]/).filter(Boolean).pop() ?? receiverText;
  return last.replace(/^[$*&]+/, '');
}


/**
 * LOCAL ALIASES OF A DANGEROUS FUNCTION.
 *
 *     import { exec } from "child_process";
 *     const execAsync = promisify(exec);
 *     await execAsync(command);            // <- invisible to a name list
 *
 * That is CVE-2025-53107, twenty-three vulnerable files, and we found zero of
 * them. The sink list holds `exec`; the call says `execAsync`. Nothing about
 * the danger changed - only the label on it.
 *
 * The near-identical CVE-2025-59046 WAS caught, and only because that author
 * happened to write `const exec = promisify(execCb)` - aliasing back to the
 * name we already knew. Two CVEs, one real difference between them, and it was
 * luck.
 *
 * `promisify` is the standard Node idiom for exactly these APIs, so this is not
 * an exotic shape; it is the normal one. This pass reads the file for
 * declarations that bind a known sink name to a new identifier and returns the
 * mapping, so the sink check can recognise both.
 *
 * FILE-LOCAL ONLY. An alias exported from another module is still missed, and
 * that is a documented gap rather than a silent one.
 */
function sinkAliases(root: Node, knownSinkNames: ReadonlySet<string>): Map<string, string> {
  const aliases = new Map<string, string>();
  const visit = (node: Node, depth: number): void => {
    if (depth > 40) return;
    if (node.type === 'variable_declarator' || node.type === 'short_var_declaration') {
      const nameNode = node.childForFieldName('name') ?? node.childForFieldName('left');
      const valueNode = node.childForFieldName('value') ?? node.childForFieldName('right');
      if (nameNode && valueNode) {
        const alias = text(nameNode);
        const initialiser = text(valueNode);
        // Only wrappers that PASS THE FUNCTION ALONG: promisify(fn),
        // util.promisify(fn), require('child_process').fn, cp.fn.
        if (/^(?:[\w.]*\bpromisify\s*\(|require\s*\(|[\w$]+\.)/.test(initialiser)) {
          for (const sinkName of knownSinkNames) {
            if (alias === sinkName) continue;
            if (new RegExp(`\\b${sinkName}\\b`).test(initialiser)) {
              aliases.set(alias, sinkName);
              break;
            }
          }
        }
      }
    }
    for (const child of node.namedChildren) if (child) visit(child, depth + 1);
  };
  visit(root, 0);
  return aliases;
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
      const nameNode = functionNameOf(node);
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
  /**
   * How many distinct places an attacker-controlled SOURCE was recognised.
   *
   * This exists because of a silence. Elasticsearch - 3,999 Java files, a REST
   * API, a network service - produced zero flow-verified findings, and the
   * report had no way to say why. It contains 0 `@RequestParam` and 0
   * `getParameter()`: it uses its own REST layer, which the dictionaries do not
   * model, so the tracer never found a single source to start from.
   *
   * Every number in a report is downstream of this one. Zero sources means
   * zero flows can exist no matter how good the tracer is, and a reader
   * deserves to be told that rather than reading "0 flow-verified" as good news.
   */
  readonly sourcesFound: number;
  /**
   * Statements not walked because the syntax tree was nested deeper than the
   * walk will go.
   *
   * Distinct from depthTruncations, which counts CALL chains. This one counts
   * places where a single EXPRESSION was too deep - and it exists because a
   * 25,809-file scan of the TypeScript repository died with "Maximum call stack
   * size exceeded" on a file containing one expression with 1,499 `+` operators.
   * The walk recursed 1,499 frames and took the process with it.
   *
   * A crash is the worst possible answer: it produces no report at all, so a
   * whole scan is lost to one pathological file. Stopping is better - but only
   * if we SAY we stopped, which is what this counter is for.
   */
  readonly astTruncations: number;
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
  /** Sites where the syntax tree was deeper than MAX_AST_DEPTH. */
  const seenDeepAst = new Set<string>();
  const siteOf = (n: Node, filePath: string) => `${filePath}#${n.id}`;

  const dictionary = TAINT_DICTIONARIES[language];
  // Java and Go: no dictionary yet. Reported in the coverage section, not hidden.
  const seenSources = new Set<string>();
  const limits = (): TraceLimits => ({
    astTruncations: seenDeepAst.size,
    depthTruncations: seenDepth.size,
    recursionStops: seenRecursion.size,
    unmodelledHops: seenUnmodelled.size,
    sourcesFound: seenSources.size,
  });

  if (!dictionary) return { flows: [], sanitized: [], limits: limits() };

  const functionTypes = new Set(FUNCTION_NODES[language] ?? []);
  const fileTypes = declaredTypes(file.root, language);
  const knownSinkNames = new Set<string>();
  for (const sink of dictionary.callSinks) for (const m of sink.methods) knownSinkNames.add(m);
  const fileAliases = sinkAliases(file.root, knownSinkNames);
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
      seenSources.add(siteOf(node, currentPath));
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
    compartment: taint.compartment,
    branchAssumed: taint.branchAssumed,
    containerGuess: taint.containerGuess,
    collectedMany: taint.collectedMany,
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
        (TYPE_FIRST_WRAPPERS.has(node.type)
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
      /*
       * Two different reasons an operator is on this list.
       *
       * COMPOSITION - `+`, `%`, `.` - builds a new value that CONTAINS the
       * operands. `.` is PHP's concatenation operator; every other language
       * here uses `+`, and `%` is Python's old-style format.
       *
       * SELECTION - `??`, `||`, `&&` - builds nothing and RETURNS one of the
       * operands unchanged. `dirty ?? "fallback"` is `dirty` on every run
       * where `dirty` exists, which is every run an attacker cares about.
       *
       * Selection was missing, and the cost was quiet: the tracer returned
       * null, the finding fell back to signature-based, and the report said a
       * pattern had been matched when a path was in fact walkable. Nothing was
       * hidden - the finding still appeared - but a provable claim was being
       * reported as a guess, which is the honesty contract failing in the
       * cautious direction rather than the loud one. Worth fixing for the same
       * reason the loud direction is: the label is supposed to mean something.
       *
       * This is yesterday's Java argument - a null default is not a sanitiser -
       * arriving in the languages that spell it with an operator instead of an
       * `if`. It went unnoticed there because JavaScript's version has no
       * statement to look at.
       *
       * The merge below is already right for both kinds. Composition needs the
       * union of what is dirty and the intersection of what was washed;
       * selection needs the same answer for a different reason, because either
       * operand could be the one that comes out.
       */
      if (!BINARY_CARRIERS.has(operator)) return null;
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

    /*
     * A COMPREHENSION THAT ESCAPES EVERY ELEMENT.
     *
     *     kwargs_safe = {k: conditional_escape(v) for (k, v) in kwargs.items()}
     *
     * The line directly below the map() call in Django's format_html. Both
     * idioms sit in the same six-line function, so covering one and not the
     * other would have left the very case that started this half-fixed - and
     * did, until the fixture caught it.
     *
     * Same rule as the higher-order applier: if EVERY element passes through a
     * sanitiser, the collection is washed for that sanitiser's kinds. The
     * element expression is the whole test - a comprehension whose body is a
     * bare name, or a call this engine does not know, proves nothing and is
     * asserted as still-reported in vulnerable/higher-order-escape-fence.py.
     */
    if (COMPREHENSION_NODES.has(node.type)) {
      const body = node.namedChildren.find((c): c is Node => c !== null);
      // A dict comprehension's body is a `pair`; the VALUE is what gets escaped.
      const element =
        body?.type === 'pair'
          ? body.childForFieldName('value') ?? body
          : body;
      const applied =
        element && CALL_NODES.has(element.type)
          ? dictionary.sanitizers.find((san) =>
              san.names.includes(lastSegment(calleeOf(element).text)),
            )
          : undefined;
      if (applied && element) {
        for (const child of node.namedChildren) {
          if (!child || child === body) continue;
          const iterated = child.childForFieldName('right') ?? child;
          const taint = evaluate(iterated, scope, depth + 1);
          if (!taint) continue;
          return {
            steps: [
              ...taint.steps,
              step(
                'sanitizer',
                node,
                `every element passed through \`${lastSegment(calleeOf(element).text)}()\` ` +
                  `by a comprehension - ${applied.description}`,
                applied.kinds,
              ),
            ],
            sanitizedFor: new Set([...taint.sanitizedFor, ...applied.kinds]),
            origin: taint.origin,
            unknownHops: taint.unknownHops,
          };
        }
      }
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

    /*
     * A SANITISER PASSED AS A VALUE, NOT CALLED.
     *
     *     args_safe = map(conditional_escape, args)          django/utils/html.py
     *
     * That is Django's format_html - the function its own docstring calls the
     * one you should use instead of str.format to build HTML - and this scanner
     * reported it as flow-verified XSS. Eighth time this project has punished a
     * fix, and the most prominent target yet.
     *
     * Everything needed was already present. `mark_safe` was a sink, correctly:
     * mark_safe(user_input) really is dangerous. `conditional_escape` was in the
     * sanitiser list. What nothing modelled is that the escaping happened
     * through a HIGHER-ORDER call: the sanitiser was never written as
     * `escape(x)` at a place the tracer watches, it was handed to map() as a
     * value and applied out of sight.
     *
     * A sanitiser recognised only in the shape `escape(x)` stops working the
     * moment somebody writes idiomatic Python - and both idioms sit on adjacent
     * lines of that one Django function, map() then a dict comprehension.
     *
     * The cost of missing it compounds: the second Django finding was a CALLER
     * of format_html. One unmodelled shape at the bottom of a framework
     * propagates into every place that uses it.
     */
    if (HIGHER_ORDER_APPLIERS.has(name)) {
      for (const arg of args) {
        const applied = dictionary.sanitizers.find((san) =>
          san.names.includes(lastSegment(text(arg))),
        );
        if (!applied) continue;
        // The collection being mapped over is the OTHER argument.
        for (const other of args) {
          if (other === arg) continue;
          const taint = evaluate(other, scope, depth + 1);
          if (!taint) continue;
          return {
            steps: [
              ...taint.steps,
              step(
                'sanitizer',
                node,
                `every element passed through \`${lastSegment(text(arg))}()\` by ` +
                  `\`${name}()\` - ${applied.description}`,
                applied.kinds,
              ),
            ],
            sanitizedFor: new Set([...taint.sanitizedFor, ...applied.kinds]),
            origin: taint.origin,
            unknownHops: taint.unknownHops,
          };
        }
      }
    }

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
      // A propagator reached through the RECEIVER of a multi-element container
      // is an element read - `map.get(k)`, `list.get(i)` - and `get` is in the
      // propagator list, which is why the unmodelled-call path never sees it.
      // Same rule, second doorway: reading one of several is a guess.
      const fromContainer = taint?.collectedMany ?? false;
      if (!taint) {
        for (const arg of args) {
          taint = evaluate(arg, scope, depth + 1);
          if (taint) break;
        }
      }
      if (!taint) return null;
      const carried = addStep(taint, node, `passed through \`${name}()\``);
      return fromContainer ? { ...carried, containerGuess: true } : carried;
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
    /*
     * TAINT ARRIVING FROM THE RECEIVER, which is where Jenkins went wrong.
     *
     * No argument was dirty, so the only way this call can be dirty is if the
     * OBJECT is. Usually that is right - `sb.toString()` on a dirtied
     * StringBuilder is exactly the dirty string. But when the object was
     * dirtied through a KEYED write, the taint is in a named compartment and
     * this call may have nothing to do with it:
     *
     *     req.setAttribute("loginForm", dirty);
     *     req.getContextPath()      // <- not the compartment. Not dirty.
     *
     * So a compartmented receiver only carries taint out through a reader of
     * that compartment. Reading it back DOES carry, and clears the compartment,
     * because the value is now in the caller's hands rather than filed away.
     */
    const fromReceiver = carried === null;
    carried ??= evaluate(receiver, scope, depth + 1);
    if (!carried) return null;
    let compartment = carried.compartment;
    if (fromReceiver && compartment) {
      if (!compartment.includes(name)) return null;
      compartment = undefined;
    }
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
      compartment,
      collectedMany: carried.collectedMany,
      /*
       * THE READ IS WHERE THE AMBIGUITY IS BORN, not the write.
       *
       * `argList.add(a); argList.add(b); pb.command(argList)` hands the whole
       * list over - every element arrives, nothing is guessed, and the trace
       * stays proven. `map.put(k1,clean); map.put(k2,dirty); map.get(k1)` pulls
       * ONE element out of several and this engine does not model which. Same
       * container, same write count; only the read tells them apart.
       */
      containerGuess: carried.containerGuess ?? (fromReceiver && carried.collectedMany ? true : undefined),
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
      /*
       * A SANITISER STEP FROM SOMEBODY ELSE'S VALUE.
       *
       * Scanning WordPress on the new page-buffer sink crashed the whole scan
       * on the engine's own invariant: "path contains a sanitiser - that is a
       * CLEAN flow, not a verified vulnerability." The invariant was right to
       * fire and right to crash rather than publish. The path was wrong.
       *
       *     $html .= '<a href="' . esc_url($u) . '">' . $label . '</a>';
       *
       * Two tainted values merge here. `esc_url($u)` is escaped; `$label` is
       * not. `sanitizedFor` correctly ends up WITHOUT xss - the finding is
       * real, because $label is raw - but the merged step list still carried
       * the esc_url sanitiser step from the other contributor. One narrative
       * assembled out of two different values' histories.
       *
       * So a step only stays a SANITISER when the value actually reaching this
       * sink was sanitised for this kind. Otherwise it is something that
       * happened to a sibling expression, and the path says so instead of
       * claiming a cleanliness the traced value never had.
       */
      const coversThisKind = s.sanitizesKinds?.includes(kind) ?? false;
      if (coversThisKind && taint.sanitizedFor.has(kind)) {
        return { kind: s.kind, location: s.location, description: s.description };
      }
      if (coversThisKind) {
        return {
          kind: 'propagation',
          location: s.location,
          description:
            `${s.description} - NOTE: this covered a DIFFERENT value in the same ` +
            `expression. The value followed here never went through it.`,
        };
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
   * ONE RETRACTION, THREE PLACES THAT CAN REPORT.
   *
   * `checkTaintAtSink` says in its own comment that it was factored out "so a
   * second kind of sink cannot get half of this right". It was, and then two
   * more emission sites grew their own inline copies of the sanitised check -
   * so when the validation guard was added to the one factored function, DVWA's
   * `exec/impossible.php` carried on being reported through a path that had
   * never heard of it.
   *
   * Every reason to NOT report belongs here, and `npm test` fails if a
   * `results.push` appears in this file without a `retracted()` guarding it.
   */
  const retracted = (taint: Taint, valueNode: Node, kind: SinkKind): 'sanitised' | null => {
    /*
     * WE ASSUMED A BRANCH. THAT IS NOT A PROOF.
     *
     * The value reached here only because a clean write was skipped for being
     * conditional - see the note on branchAssumed. Reporting is right; calling
     * it flow-verified is not, and the difference between those two sentences
     * is this project's whole product. The signature rules still cover the
     * line, so the caution survives and only the overclaim is dropped.
     *
     * This sits in the shared gate rather than in checkTaintAtSink, because the
     * first attempt put it in checkTaintAtSink alone and Django carried on being
     * reported: the finding came through one of the OTHER two emission sites.
     * That is the fourth-time-lesson recorded on this function - every reason
     * not to report belongs here, or it only half exists.
     */
    if (taint.sanitizedFor.has(kind)) return 'sanitised';
    // Cleanliness established by the control flow rather than by transforming
    // the value: inside `if (is_numeric($octet[0]) && ...)` the value provably
    // holds no metacharacter. See rules/lib/guards.ts.
    if (expressionIsFullyGuarded(valueNode, language)) return 'sanitised';
    return null;
  };

  const recordRetraction = (sinkNode: Node, kind: SinkKind): void => {
    sanitized.push({
      ruleId: SINK_KIND_RULE[kind],
      sinkNode,
      kind,
      filePath: toDisplay(currentPath),
    });
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
    const verdict = retracted(taint, valueNode, kind);
    if (verdict) {
      if (verdict === 'sanitised') recordRetraction(valueNode, kind);
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
      branchAssumed: taint.branchAssumed ?? false,
      containerGuess: taint.containerGuess ?? false,
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
  /**
   * THE OUTPUT-PARAMETER MUTATOR - C's version of the same idea, and the one
   * shape without which C coverage would be nearly zero.
   *
   * checkMutation below binds taint to the RECEIVER, because in every language
   * this engine supported until now the thing being filled sits to the left of
   * the dot:
   *
   *     sb.append(dirty)        ->  `sb`
   *
   * C has no receiver. The destination is argument ZERO, and the value goes in
   * after it:
   *
   *     sprintf(cmd, "ping %s", argv[1]);   ->  `cmd`
   *     strcpy(buf, argv[1]);               ->  `buf`
   *     strcat(path, getenv("X"));          ->  `path`
   *
   * That is not a corner case, it is THE C idiom - the two-line build-then-run
   * pattern that every command injection in the language is written in. With
   * only the receiver rule, `sprintf(cmd, ...)` would taint nothing, `cmd`
   * would read as clean, and `system(cmd)` on the next line would be silent.
   * Every fixture in vulnerable/cmdi.c is this shape.
   *
   * Argument zero is excluded from the tainted-value scan for the same reason
   * `writerArgPattern` excludes it on the sink side: it is where the output
   * goes, not what is written.
   */
  const checkOutParamMutation = (node: Node, scope: Scope): void => {
    const method = lastSegment(calleeOf(node).text);

    /*
     * READER FUNCTIONS: the call IS the source, and the bytes land in an
     * argument rather than in the return value.
     *
     *     fgets(line, sizeof(line), stdin);
     *     system(line);
     *
     * Nothing here is an expression the source patterns could match - fgets
     * returns a pointer nobody keeps, and `line` was declared clean on the
     * line above. Without this the two statements are unrelated and reading a
     * command from standard input is invisible, which is the oldest shape of
     * this bug there is.
     */
    for (const reader of dictionary.outParamSources ?? []) {
      if (!reader.names.includes(method)) continue;
      const destination = argumentsOf(node)[reader.destination];
      if (!destination) continue;
      const name = lastSegment(text(destination));
      if (!name || !/^[A-Za-z_][\w]*$/.test(name)) continue;
      seenSources.add(siteOf(node, currentPath));
      scope.env.set(name, {
        steps: [
          step('source', node, `\`${name}\` is filled by \`${method}()\` from ${reader.description}`),
        ],
        sanitizedFor: new Set(),
        origin: `${method}()`,
        unknownHops: [],
      });
      return;
    }

    const outParams = dictionary.outParamMutators;
    if (!outParams || outParams.length === 0) return;
    if (!outParams.includes(method)) return;

    const args = argumentsOf(node);
    const destination = args[0];
    if (!destination) return;

    // Only something we can name. `sprintf(ptr->buf, ...)` gives us no single
    // variable to bind, so it is left alone rather than guessed at.
    const destinationName = lastSegment(text(destination));
    if (!destinationName || !/^[A-Za-z_][\w]*$/.test(destinationName)) return;

    for (const arg of args.slice(1)) {
      const taint = evaluate(arg, scope);
      if (!taint) continue;
      scope.env.set(
        destinationName,
        addStep(taint, node, `written into \`${destinationName}\` by \`${method}()\``),
      );
      return;
    }
  };

  /**
   * HOW MANY THINGS WENT INTO THE BOX?
   *
   * Counts element writes to `receiverName` inside the function the write sits
   * in. One means the value later read out is the value written, and the trace
   * is sound. More than one means a read picks one of several and this engine
   * does not model which - so the finding keeps travelling but loses its claim
   * to proof.
   *
   * DELIBERATELY TEXTUAL, and the limitation is real: it counts writes that
   * appear anywhere in the enclosing function, including ones AFTER the read.
   * That over-counts, which costs confidence rather than findings - the error
   * lands on the side of claiming less. A precise version would need ordering
   * and reachability, which is the modelling this file has repeatedly decided
   * not to guess at.
   */
  const countElementWrites = (node: Node, receiverName: string): number => {
    const names = dictionary.elementMutators;
    if (!names || names.length === 0) return 0;
    let scopeNode: Node | null = node;
    while (scopeNode && !functionTypes.has(scopeNode.type)) scopeNode = scopeNode.parent;
    const escaped = receiverName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = new RegExp(`\\b${escaped}\\s*\\.\\s*(?:${names.join('|')})\\s*\\(`, 'g');
    return (text(scopeNode ?? node).match(pattern) ?? []).length;
  };

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

    // A keyed write files the value in a NAMED COMPARTMENT of an object that is
    // primarily something else. The object is dirty for reads of that store and
    // clean for everything else it does. See safe/keyed-container.java.
    const keyed = dictionary.keyedMutators?.includes(method) ?? false;
    const readers = dictionary.keyedReaders;

    // An element write into a collection that took several elements makes any
    // later read of it a guess about WHICH element. The taint is unchanged; only
    // the confidence label is. Accumulators are not in `elementMutators`, so
    // sb.append() keeps its proof however many times it runs.
    const manyElements =
      (dictionary.elementMutators?.includes(method) ?? false) &&
      countElementWrites(node, receiverName) > 1;

    for (const arg of argumentsOf(node)) {
      const taint = evaluate(arg, scope);
      if (!taint) continue;
      const stored = addStep(
        taint,
        node,
        keyed
          ? `filed into \`${receiverName}\` under a key via \`${method}()\` - reads of that ` +
            `store are tainted, other methods on \`${receiverName}\` are not`
          : `collected into \`${receiverName}\` via \`${method}()\``,
      );
      const marked = manyElements ? { ...stored, collectedMany: true } : stored;
      scope.env.set(
        receiverName,
        keyed && readers ? { ...marked, compartment: readers } : marked,
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
      // The name as written, or the sink it was locally aliased to.
      const aliasedTo = fileAliases.get(name);
      const effective = sink.methods.includes(name) ? name : aliasedTo;
      if (!effective || !sink.methods.includes(effective)) continue;
      if (sink.bareOnly && callee.receiver) {
        const owner = ownerName(text(callee.receiver));
        if (!(sink.allowedReceivers ?? []).includes(owner)) continue;
      }
      if (sink.requiredReceivers && sink.requiredReceivers.length > 0) {
        const receiver = callee.receiver ? text(callee.receiver) : '';
        const last = ownerName(receiver) || receiver;
        if (!sink.requiredReceivers.some((name) => last === name)) continue;
      }
      if (sink.receiverPattern) {
        const receiver = callee.receiver ? text(callee.receiver) : '';
        // The variable's NAME, or the type it was declared with. `r.exec(cmd)`
        // says nothing; `Runtime r = ...` two lines up says everything.
        const declared = fileTypes.get(receiver) ?? fileTypes.get(lastSegment(receiver)) ?? '';
        if (!sink.receiverPattern.test(receiver) && !sink.receiverPattern.test(declared)) continue;
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

      /*
       * Sinks whose destination is ARGUMENT ZERO, not the receiver.
       * `fmt.Fprintf(w, ...)` - see writerArgPattern in types.ts.
       */
      if (sink.writerArgPattern) {
        const writer = args[0] ? text(args[0]) : '';
        const declared = fileTypes.get(writer) ?? fileTypes.get(lastSegment(writer)) ?? '';
        if (!sink.writerArgPattern.test(writer) && !sink.writerArgPattern.test(declared)) continue;
      }

      for (const index of indexes) {
        // Argument zero is the destination, not the payload.
        if (sink.writerArgPattern && index === 0) continue;
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
        const verdict = retracted(taint, arg, sink.kind);
        if (verdict) {
          if (verdict === 'sanitised') recordRetraction(node, sink.kind);
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
          branchAssumed: taint.branchAssumed ?? false,
          containerGuess: taint.containerGuess ?? false,
          filePath: toDisplay(currentPath),
        });
      }
    }
  };

  const checkAssignSink = (assignNode: Node, target: Node, value: Node, taint: Taint): void => {
    // The sigil goes the same way it does for receivers: PHP writes $html and
    // the sink list holds html. See ownerName() for the receiver-side twin.
    const name = lastSegment(text(target)).replace(/^["']|["']$/g, '').replace(/^[$*&]+/, '');
    for (const sink of dictionary.assignSinks) {
      if (!sink.properties.includes(name)) continue;
      // A name-based sink has to see the shape it claims to parse. See the
      // note on contentCheck in types.ts - `$sql .= $where` is not a page.
      if (sink.contentCheck === 'html' && !looksLikeHtml(text(value))) continue;
      if (sink.contentCheck === 'sql' && !looksLikeSql(text(value))) continue;
      const verdict = retracted(taint, value, sink.kind);
      if (verdict) {
        if (verdict === 'sanitised') recordRetraction(assignNode, sink.kind);
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
        branchAssumed: taint.branchAssumed ?? false,
        containerGuess: taint.containerGuess ?? false,
        filePath: toDisplay(currentPath),
      });
    }
  };

  /* ---- the statement walk ---- */

  /** Does this node sit inside a branch or loop body within the current scope? */
  /**
   * A NULL DEFAULT IS NOT A SANITISER.
   *
   *     String param = request.getParameter("q");   // tainted
   *     if (param == null) param = "";              // clean write, conditional
   *
   * `underCondition` sees a clean write it cannot prove happens and marks the
   * taint `branchAssumed`, which costs the finding its proof. But the two cases
   * here are DISJOINT: the write fires only when the value is null, and the
   * taint exists only when it is not. Nothing was assumed - the tainted path is
   * the only path there is. And in the case the guard does fire, what reaches
   * the sink is a constant carrying no payload.
   *
   * THE OPERATOR IS THE WHOLE RULE. `if (x != null) x = "safe"` puts the clean
   * write exactly on the tainted value and really might clean it; that one must
   * stay a guess. So this matches equality-against-null only, on the same name
   * being written, and demands that EVERY enclosing conditional qualify - one
   * ordinary `if` in the chain and we know nothing again.
   *
   * Measured before building: 171 of BenchmarkJava's 320 found-but-unproven
   * real vulnerabilities are downgraded for an unevaluated branch, and this
   * idiom is the largest single shape among them. It is also ordinary Java
   * rather than a benchmark artefact, which is why it was worth doing first.
   */
  const NULL_LITERALS = 'null|NULL|None|nil|undefined';
  const guardCannotCleanTarget = (node: Node, body: Node, targetName: string): boolean => {
    const name = targetName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const test = new RegExp(
      `^\\(?\\s*(?:${name}\\s*={2,3}\\s*(?:${NULL_LITERALS})` +
        `|(?:${NULL_LITERALS})\\s*={2,3}\\s*${name}` +
        `|${name}\\s+is\\s+None)\\s*\\)?$`,
    );
    let current: Node | null = node.parent;
    let seen = 0;
    while (current && current !== body) {
      if (CONDITIONAL_NODES.has(current.type)) {
        // An `else` branch of a null test is the NON-null path - the opposite
        // case - so it never qualifies.
        if (current.type !== 'if_statement') return false;
        const condition = current.childForFieldName('condition');
        if (!condition) return false;
        if (!test.test(text(condition).trim())) return false;
        seen++;
      }
      current = current.parent;
    }
    return seen > 0;
  };

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
      // C and C++: `char *user = getenv("X")` is an init_declarator, whose
      // fields are `declarator` and `value` rather than any of the above.
      ['declarator', 'value'],
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
    /*
     * C/C++ declaration-with-initialiser: `char *user = getenv("X")`.
     *
     * THIS LIST AND THE SHAPE QUERIES IN engine/shapes.ts ARE THE SAME FACT
     * WRITTEN TWICE, and this entry is what that costs. The query knew about
     * init_declarator from the first commit; the tracer's own walk did not, so
     * every C value bound at its declaration read as clean while direct
     * arguments traced perfectly - `printf(getenv("X"))` was flow-verified and
     * `char *u = getenv("X"); printf(u);` was not, which is most of real C.
     *
     * It failed quietly because the shapes that DO work look like success: a
     * plain `p = argv[1]` is an assignment_expression and was always covered.
     */
    'init_declarator',
  ]);

  /** PHP statements that write their argument straight to the response body. */
  const ECHO_NODES = new Set(['echo_statement', 'print_intrinsic']);

  /**
   * How deep the statement walk will recurse into a syntax tree.
   *
   * `0 + 1 + 2 + ... + 1499` parses as a binary_expression nested 1,499 deep,
   * and each level is one stack frame here. Node's default stack takes roughly
   * a thousand of these frames before it gives up and kills the process, which
   * means one file in TypeScript's own test suite could destroy a 25,809-file
   * scan and return NOTHING - no findings, no report, no partial result.
   *
   * 400 is comfortably under the limit and far past any hand-written code.
   * Anything deeper is generated, minified or a stress test, and the honest
   * response is to stop and count it rather than to crash or to pretend the
   * file was fully examined.
   */
  const MAX_AST_DEPTH = 400;

  const walk = (node: Node, scope: Scope, depth = 0): void => {
    if (depth > MAX_AST_DEPTH) {
      seenDeepAst.add(siteOf(node, scope.filePath));
      return;
    }
    // A nested function is a separate notebook. Queue it, don't descend.
    if (node !== scope.body && functionTypes.has(node.type)) {
      const body = node.childForFieldName('body') ?? node;
      const env = new Map(scope.env);
      /*
       * PARAMETERS THAT ARE ALREADY ATTACKER-CONTROLLED WHEN THE BODY STARTS.
       *
       * Every other source is an expression the body evaluates. A framework
       * binding is not: Spring reads the query string, converts it, and hands
       * the method a plain String. By the time the body runs there is nothing
       * left to match - the only evidence is the annotation on the declaration,
       * which is why this has to happen HERE, as the scope is created, rather
       * than in sourceTaint().
       *
       * Zero flow-verified findings on OWASP WebGoat is what this cost. See the
       * long note on parameterSources in dictionaries.ts.
       */
      for (const source of dictionary.parameterSources ?? []) {
        for (const parameter of parameterDeclarations(node)) {
          if (!parameter.name || !source.pattern.test(parameter.text)) continue;
          seenSources.add(siteOf(parameter.node, scope.filePath));
          env.set(parameter.name, {
            steps: [
              step('source', parameter.node, `\`${parameter.name}\` is ${source.description}`),
            ],
            sanitizedFor: new Set(),
            origin: parameter.name,
            unknownHops: [],
          });
        }
      }
      queue.push({
        body,
        env,
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

    /*
     * A FOR-EACH INTRODUCES A NAME, AND NOTHING WAS BINDING IT.
     *
     *     String[] values = request.getParameterValues("q");
     *     out.write(values[0]);                  // flow-verified
     *     for (String v : values) out.write(v);  // signature-based only
     *
     * Subscripting a tainted array carried the taint; iterating the same array
     * threw it away, because `v` was never entered into the environment and so
     * evaluated to clean.
     *
     * The loop node types were ALREADY listed in CONDITIONAL_NODES - the tracer
     * knew a for-each was a branch, and used that to decide a clean write inside
     * one cannot prove a value safe. Knowing a construct exists and modelling
     * what it does are different things, and the first reads exactly like the
     * second until something measures it.
     *
     * Found by diagnosing BenchmarkJava's remaining 123 misses: every one had no
     * source recognised, and fourteen of them were `for (Cookie c :
     * request.getCookies())` - a source this engine has always known, thrown
     * away by the loop around it. It looked like a cookie bug and was not.
     *
     * Container-insensitive, like every other collection in this engine: the
     * loop variable takes the taint of the whole iterable, so iterating a list
     * with one dirty element treats every element as dirty. That errs toward
     * reporting, which is the direction this project takes on purpose.
     */
    if (FOREACH_NODES.has(node.type)) {
      const binding = foreachBinding(node);
      if (binding) {
        const taint = evaluate(binding.iterable, scope);
        const name = text(binding.name).replace(/^[$*&]+/, '').trim();
        if (taint && /^[A-Za-z_$][\w$]*$/.test(name)) {
          scope.env.set(
            name,
            addStep(taint, binding.name, `bound to \`${name}\` by a for-each over the collection`),
          );
        }
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
        const targetNames = (
          parts.target.type === 'expression_list'
            ? parts.target.namedChildren.filter((c): c is Node => c !== null).map((c) => text(c))
            : DESTRUCTURING_NODES.has(parts.target.type)
              ? namesBoundBy(parts.target)
              : [text(parts.target)]
        ).map(stripDeclarator);

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
            /*
             * A clean write we cannot prove happens. Keep the dirt - but record
             * that we ASSUMED rather than followed, so no proof is claimed on
             * the strength of it. See the note on branchAssumed.
             */
            const kept = scope.env.get(targetName);
            if (kept) {
              const certain = guardCannotCleanTarget(node, scope.body, targetName);
              scope.env.set(targetName, certain ? kept : { ...kept, branchAssumed: true });
            }
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
        for (const child of parts.value.namedChildren) if (child) walk(child, scope, depth + 1);
        if (CALL_NODES.has(parts.value.type)) {
          checkMutation(parts.value, scope);
          checkOutParamMutation(parts.value, scope);
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
      checkOutParamMutation(node, scope);
      checkReceiverSink(node, scope);
      checkCallSink(node, scope);
      // A bare call statement - `helper(req.query.id);` - is never evaluated as
      // an expression, so without this line the cross-function trace would only
      // work when the result was assigned to something. Easy gap to miss.
      descendIntoLocalCall(node, scope, 0);
    }

    for (const child of node.namedChildren) {
      if (child) walk(child, scope, depth + 1);
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

    /*
     * A FULLY QUALIFIED CALL IS NOT A LOCAL FUNCTION, however the names line up.
     *
     *     java.util.Collections.list(request.getParameterNames())
     *
     * resolved to a fixture's own `list(HttpServletRequest, HttpServletResponse)`
     * three files away, because resolution used the LAST SEGMENT of the callee
     * and threw the package path away. The descent then "handled" the call and
     * returned that unrelated method's answer, which was nothing - so a proof
     * that existed when the file was scanned alone disappeared when it was
     * scanned alongside its neighbours.
     *
     * That is the worst shape a bug can take here: the same code, analysed
     * twice, giving two answers, with no message either time.
     *
     * The engine's limitations already say "whether a function is actually
     * EXPORTED is not checked - a module-private helper with a matching name
     * could be entered". This is that, with a fact available to rule it out and
     * nobody reading it. `java.util.Collections` names one class in one package;
     * a local method cannot be it.
     *
     * The test is the Java package convention - lowercase segments then a
     * Capitalised type - which is deliberately narrow. `Utils.list(x)` and
     * `this.list(x)` are unqualified enough to still resolve locally, and are
     * left alone.
     */
    if (/^[a-z][\w$]*(?:\.[a-z][\w$]*)+\.[A-Z][\w$]*\.[\w$]+$/.test(calleeText.trim())) {
      return { handled: false, taint: null };
    }

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
