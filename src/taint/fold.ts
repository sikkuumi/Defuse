/**
 * THE CONSTANT FOLDER, SHARED.
 *
 * This lived inside traceFile() for as long as only the tracer needed it. Then
 * the signature rules needed it too: 65 of BenchmarkJava's remaining false
 * positives are SQL strings built from a `bar` that a decidable condition has
 * already set to a literal, and the SQL rule could not see that, because the
 * only thing that knew how to decide a condition was sealed inside the tracer.
 *
 * The alternative was a second, smaller folder in rules/lib. This project has
 * paid for "the same fact written twice" more than once - ASSIGNMENT_NODES below
 * carries a scar from exactly that - so the folder moved out instead, and both
 * callers now use the one copy. Moving it was checked with `npm run identity`,
 * which hashes every finding and every proof step on twelve fixed targets: the
 * move was meant to change nothing, and it had to be shown to change nothing.
 *
 * createFolder() returns a fresh folder per language, per file, so its caches
 * never leak an answer from one file into another.
 */

import type { Node } from 'web-tree-sitter';
import type { LanguageId } from '../parse/languages.js';

/** Whitespace-normalised node text. The tracer has its own copy of this one-liner. */
function text(node: Node | null | undefined): string {
  return (node?.text ?? '').replace(/\s+/g, ' ').trim();
}

export const assignmentParts = (node: Node): { target: Node; value: Node } | null => {
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

export const ASSIGNMENT_NODES = new Set([
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

export type Folded = number | boolean | undefined;

export interface Folder {
  /** Fold an expression to a number or boolean, or undefined when it cannot be decided. */
  readonly foldExpression: (node: Node | null, body: Node, depth: number) => Folded;
  /** True or false when a condition is decidable, undefined when it is not. */
  readonly conditionTruth: (node: Node | null, body: Node) => boolean | undefined;
  /** The three parts of a ternary, whatever the grammar calls them. */
  readonly ternaryParts: (node: Node) => { condition: Node | null; consequence: Node | null; alternative: Node | null };
  /** The arm of an if-statement that certainly does not run, if any. */
  readonly deadBranchOf: (node: Node, body: Node) => Node | null;
  /** Which cases of a switch can run, when the selector and every label fold. */
  readonly switchDecision: (node: Node, body: Node) => SwitchDecision | null;
  /** Whether a name receives any write that is not a plain `name = value`. */
  readonly writtenOtherwise: (name: string, body: Node) => boolean;
}

export function createFolder(language: LanguageId): Folder {
  /*
   * CONSTANT CONDITIONS, FOLDED - DELIBERATELY BADLY.
   *
   * The engine reads statements in order and does not evaluate conditions, so
   * a value on the losing side of a decision already made at compile time gets
   * carried anyway. That single blind spot was 128 of the 131 false positives
   * still wearing the proven label.
   *
   *     int num = 106;
   *     bar = (7 * 18) + num > 200 ? "constant" : param;
   *
   * 126 + 106 = 232. The tainted branch cannot run.
   *
   * THIS FOLDER IS SMALL ON PURPOSE. It understands integer and boolean
   * literals, parentheses, negation, arithmetic, comparison and the logical
   * connectives, plus a local variable bound exactly once to something it can
   * already fold. Everything else returns undefined, which means "cannot tell",
   * which means the branch is assumed live and nothing changes.
   *
   * The asymmetry matters. A folder that is too weak costs a false positive
   * that was already there. A folder that is too clever - one that decides
   * `"abc".length() > 2` by modelling String, or evaluates a call - eventually
   * gets a condition wrong in the other direction and DELETES A REAL FINDING.
   * A miss is the failure mode this tool exists to prevent, so every doubt
   * resolves toward keeping the flow.
   *
   * Grammar-agnostic by construction: it reads the `operator` field and the
   * node's own text rather than switching on per-language node names, because
   * eight grammars spell a literal eight ways and a name this list forgot
   * would fail silently toward undefined.
   */

  const foldLiteral = (raw: string): Folded => {
    const t = raw.trim();
    if (t === 'true' || t === 'True') return true;
    if (t === 'false' || t === 'False') return false;
    /*
     * A leading zero means OCTAL in Java, C, C++, Go, PHP and sloppy JavaScript:
     * `010` is 8, and reading it as ten decided `n < 9` the wrong way round. It
     * is not worth modelling - a leading-zero literal is "cannot tell".
     */
    if (/^-?0\d/.test(t)) return undefined;
    if (/^-?\d+$/.test(t)) return Number(t);
    if (/^-?\d+[lL]$/.test(t)) return Number(t.slice(0, -1));
    return undefined;
  };

  /**
   * The bare name out of whatever the grammar wrapped it in.
   *
   * `String bar` is Java declaring and naming in one node, so everything up to
   * the last space goes. `$num` is PHP, and the folder reaches the inner `name`
   * node - text `num` - while the assignment target is the outer `variable_name`
   * - text `$num`. Comparing those two raw is a mismatch that looks exactly
   * like "this variable is never assigned", which is a silent undefined.
   */
  const bareName = (raw: string): string => raw.trim().replace(/^.*\s/, '').replace(/^\$/, '');

  /**
   * A local name bound exactly once, to something foldable. Two assignments and
   * we stop: the value at this point would depend on order and reachability,
   * which is the very thing we are not modelling.
   */
  /*
   * One walk per name per function, not one per mention.
   *
   * Keyed on the body's SOURCE SPAN rather than on the node, because the
   * tree-sitter binding hands back a fresh wrapper object every time a child is
   * asked for - a Map keyed by Node would miss on every lookup and quietly
   * degrade into no cache at all, which is the same mistake that once made the
   * dead-branch skip compare two identical nodes and decide they differed.
   */
  const constantCache = new Map<string, Map<string, Folded>>();

  /*
   * THE CYCLE GUARD, AND THE DEPTH THAT USED TO RESET TO ZERO.
   *
   * Resolving a name folds whatever it was assigned, and folding that can hit
   * another name. `x = y + 1; y = x + 1` is a loop, and until now the recursion
   * had nothing to stop it: foldExpression carries a depth cap of 12, but the
   * call BACK into it from here passed 0, so every hop through a name reset the
   * budget and the cap could never be reached.
   *
   * That was survivable while the folder barely reached names at all. Reading
   * operators off the shape made it reach them constantly, and DVWA's packed
   * sha256 - one 10,417-character line, hundreds of one-letter names assigned
   * from each other - turned it into an out-of-memory on a 10KB file.
   *
   * Two changes, and each would have been enough on its own: the depth now
   * threads through instead of resetting, and a name currently being resolved
   * answers "cannot tell" if it is asked about again. Two, because the depth is
   * the principle and the cycle guard is the proof - a budget that merely runs
   * out still does the work first, and a loop should cost nothing at all.
   */
  const resolving = new Set<string>();

  /*
   * "BOUND EXACTLY ONCE" WAS NOT ENOUGH, AND IT WAS DELETING REAL FINDINGS.
   *
   * The rule used to be: find every `=` to this name in the function, and if
   * there is exactly one, the name IS that value. Probed before the switch
   * folding was built on top of it, that rule was wrong in every language here,
   * in ordinary code, and wrong in the dangerous direction:
   *
   *     void f(..., int num) { if (x) num = 500; bar = num > 200 ? "safe" : param; }
   *     for (int i = 0; i < 10; i++) { bar = i > 5 ? param : "safe"; }
   *     n := 0; fmt.Sscan(s, &n); if n > 5 { bar = param }
   *
   * One `=` each - so `num` was 500, `i` was 0 and `n` was 0, a branch that
   * really runs was declared dead, a real SQL injection went unreported, and
   * the SQL rule printed a receipt calling the line PROVABLY CONSTANT. A
   * parameter already holds the caller's value before any `=`; `i++` and `&n`
   * write without an `=`; a field is not this function's to fix.
   *
   * So the single write now has to be one that CANNOT be bypassed:
   *
   *   - a DECLARATION with its value (Java, C, C++, Go, JS let/const), and the
   *     use inside that declaration's block, after it. Block scoping is what
   *     makes it sound: nothing outside the block can name it, and nothing
   *     inside can read it before the declaration runs.
   *   - in Python, PHP and a JavaScript `var` there are no block-scoped
   *     declarations, so the write must sit at the TOP LEVEL of the function
   *     body - not inside an if, a loop, a try - and before the read. A write
   *     there cannot be skipped, so it replaces a parameter's value outright.
   *   - and nothing else may write to it: no `++`/`--`, no address taken, no
   *     loop or `with`/`as` binding, no `global`, and - in PHP and C++, where a
   *     call site does not show that an argument is passed by reference - not
   *     handed to any call at all.
   *
   * Anything else is "cannot tell". SwitchOnConstant.java and folder-soundness.*
   * are the fence; every case in them was a missed vulnerability.
   */
  const wordIn = (haystack: string, name: string): boolean =>
    new RegExp(`(^|[^\\w$])\\$?${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w$])`).test(haystack);

  /** Node types that write to a name without an `=`, and the field that names it. */
  const OTHER_BINDERS: ReadonlyArray<[string, string | null]> = [
    ['for_statement', 'left'], // Python   for i in ...
    ['for_in_statement', 'left'], // JS       for (x of xs)
    ['enhanced_for_statement', 'name'], // Java     for (String s : xs)
    ['range_clause', 'left'], // Go       for i := range xs
    ['for_range_loop', 'declarator'], // C++      for (auto x : xs)
    ['named_expression', 'name'], // Python   (x := ...)
    ['as_pattern_target', null], // Python   with ... as x, except E as x
    ['catch_formal_parameter', 'name'], // Java
    ['catch_clause', 'parameter'], // JS
    ['global_statement', null], // Python
    ['nonlocal_statement', null], // Python
    ['global_declaration', null], // PHP
    ['function_static_declaration', null], // PHP
    ['static_variable_declaration', null], // PHP
    ['foreach_statement', null], // PHP      checked below: the part after `as`
    ['case_pattern', null], // Python   match x: case n:  - a bare name CAPTURES
  ];
  const INCREMENT_NODES = new Set(['update_expression', 'inc_statement', 'dec_statement']);

  const BINDER_FIELD = new Map(OTHER_BINDERS);
  /** Where an address is taken, in the grammars that can take one. */
  const ADDRESS_OF = new Set([
    'pointer_expression', // C, C++   &n
    'unary_expression', // Go       &n
    'by_ref', // PHP      foreach ($a as &$v), function f(&$x)
    'reference_assignment_expression', // PHP  $y = &$n
  ]);

  /*
   * Checked on every node of the function for every name the folder asks
   * about, so it must decide by node TYPE before it reads any text: reading
   * the text of a large node copies it out of the parser, and doing that for
   * each node made a BenchmarkJava scan measurably slower.
   */
  const writesWithoutAssignment = (node: Node, name: string): boolean => {
    const type = node.type;
    if (INCREMENT_NODES.has(type)) return wordIn(node.text, name);
    // `&n` - C, C++, Go - and PHP's `&$n`: whoever holds the address can write.
    if (ADDRESS_OF.has(type)) {
      // Comments and parentheses are dropped first: `&(n)` and `&/*out*/n` are
      // both the address of n.
      const t = node.text;
      if (t.length > 200) return false;
      const flat = t.replace(/\/\*[\s\S]*?\*\//g, '').replace(/[()\s]/g, '');
      return new RegExp(`&\\$?${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w$])`).test(flat);
    }
    // Go: `n.Set(s)` takes &n implicitly when Set has a pointer receiver.
    if (language === 'go' && type === 'call_expression') {
      const fn = node.childForFieldName('function');
      if (fn?.type === 'selector_expression' && bareName(fn.childForFieldName('operand')?.text ?? '') === name) return true;
    }
    if (language === 'c' || language === 'cpp') {
      // A macro can assign to its argument - `SET_INT(n, s)` - and nothing at the
      // call says so. Upper-case callees are read as macros, by convention.
      if (type === 'call_expression' && /^[A-Z][A-Z0-9_]*$/.test(node.childForFieldName('function')?.text ?? '')) {
        const args = node.childForFieldName('arguments');
        if (args?.namedChildren.some((c) => !!c && bareName(c.text.replace(/[()\s]/g, '')) === name)) return true;
      }
      // `#define n ...` makes every later `n` something else entirely.
      if ((type === 'preproc_def' || type === 'preproc_function_def') && node.childForFieldName('name')?.text === name) {
        return true;
      }
    }
    const field = BINDER_FIELD.get(type);
    if (field !== undefined) {
      if (type === 'foreach_statement') {
        const afterAs = node.text.split(/\bas\b/)[1]?.split(')')[0] ?? '';
        return wordIn(afterAs, name);
      }
      const binder = field ? node.childForFieldName(field) : node;
      return !!binder && wordIn(binder.text, name);
    }
    // PHP and C++ pass by reference invisibly: `preg_match($re, $s, $n)` and
    // `void f(int &x); f(n);` both write to n with nothing at the call site.
    if (language === 'php' && type === 'argument') return bareName(node.text) === name;
    if (language === 'cpp') {
      if (type === 'argument_list') return node.namedChildren.some((c) => !!c && bareName(c.text) === name);
      // `std::cin >> n`, and `int &r = n` - a second name for the same storage.
      if (type === 'binary_expression' && node.childForFieldName('operator')?.text === '>>' &&
          bareName(node.childForFieldName('right')?.text ?? '') === name) return true;
      if (type === 'init_declarator' && node.childForFieldName('declarator')?.type === 'reference_declarator' &&
          bareName(node.childForFieldName('value')?.text ?? '') === name) return true;
    }
    return false;
  };

  /**
   * The region a single write governs, or null when that write can be bypassed.
   * See the note above: a block-scoped declaration governs its block; a plain
   * write governs the function only when it sits at the top of the body.
   */
  /*
   * WHAT RANGE A DECLARED TYPE CAN HOLD, because arithmetic does not wrap here
   * and does in the program. `int t = 30 * 24 * 60 * 60 * 1000` is NEGATIVE in
   * Java; `unsigned n = 0 - 1` is huge in C; `signed char c = 200` is -56. A
   * value outside what its type holds is "cannot tell". Null means the type is
   * not one whose numbers are modelled at all - unsigned, floating point, a
   * typedef, a class - and then no number bound to it is trusted.
   */
  const INT32: readonly [number, number] = [-2147483648, 2147483647];
  const INT16: readonly [number, number] = [-32768, 32767];
  const SAFE: readonly [number, number] = [-(2 ** 53), 2 ** 53];
  const rangeOfType = (typeText: string | undefined): readonly [number, number] | null => {
    const t = (typeText ?? '').replace(/\b(?:const|constexpr|static|final|volatile|register|signed)\b/g, ' ').replace(/\s+/g, ' ').trim();
    if (language === 'java') {
      if (t === 'int' || t === 'long' || t === 'var') return INT32;
      if (t === 'short') return INT16;
      if (t === 'byte') return [-128, 127];
      if (t === 'char') return [0, 65535];
      return null;
    }
    if (language === 'c' || language === 'cpp') {
      if (/^(?:int|long|long int|long long|long long int|short int|)$/.test(t)) return t === '' ? INT32 : INT32;
      if (t === 'short') return INT16;
      // Plain `char` may be signed or unsigned; 0-127 is the same either way.
      if (t === 'char') return [0, 127];
      return null;
    }
    if (language === 'go') {
      if (t === '' || t === 'int' || t === 'int32' || t === 'int64' || t === 'rune') return INT32;
      if (t === 'int16') return INT16;
      if (t === 'int8') return [-128, 127];
      if (t === 'byte' || t === 'uint8') return [0, 255];
      return null;
    }
    return SAFE;
  };

  const regionOfWrite = (write: Node, body: Node): { region: Node; range: readonly [number, number] | null } | null => {
    const found = regionNodeOfWrite(write, body);
    if (!found) return null;
    const parent = write.parent;
    let typeText: string | undefined;
    if (language === 'java' || language === 'c' || language === 'cpp') {
      typeText = parent?.childForFieldName('type')?.text;
      // C++ references and aliasing mean a mutable local cannot be read from
      // the text alone - `int &r{n}` writes n with no `n` in sight. Only a
      // `const` or `constexpr` local is a constant in C++.
      if (language === 'cpp' && !parent?.namedChildren.some((c) => c?.type === 'type_qualifier' && /^(?:const|constexpr)$/.test(c.text))) {
        return null;
      }
      // An unsigned or sized declaration keeps its qualifiers in the type node.
      if (language !== 'java') {
        const qualifiers = (parent?.namedChildren ?? []).filter((c) => c?.type === 'type_qualifier' || c?.type === 'storage_class_specifier').map((c) => c?.text ?? '');
        typeText = `${qualifiers.join(' ')} ${typeText ?? ''}`;
      }
    } else if (language === 'go' && write.type === 'var_spec') {
      typeText = write.childForFieldName('type')?.text;
    }
    return { region: found, range: rangeOfType(typeText) };
  };

  const regionNodeOfWrite = (write: Node, body: Node): Node | null => {
    const parent = write.parent;
    if (!parent) return null;
    const same = (a: Node | null, b: Node): boolean =>
      !!a && a.startIndex === b.startIndex && a.endIndex === b.endIndex;
    // The tracer hands over a function's BODY; the constant proof hands over the
    // FUNCTION. Both mean the same scope, and the top-level tests below need the
    // block either way.
    const block = body.childForFieldName('body') ?? body;

    if (language === 'java' && write.type === 'variable_declarator' && parent.type === 'local_variable_declaration') {
      return parent.parent;
    }
    if ((language === 'c' || language === 'cpp') && write.type === 'init_declarator' && parent.type === 'declaration') {
      return parent.parent;
    }
    if (language === 'go' && (write.type === 'short_var_declaration' || write.type === 'var_spec' || write.type === 'const_spec')) {
      const holder = write.type === 'short_var_declaration' ? parent : parent.parent;
      return holder ?? null;
    }
    if ((language === 'javascript' || language === 'typescript') && write.type === 'variable_declarator') {
      if (parent.type === 'lexical_declaration') return parent.parent;
      // `var` is function-scoped and hoisted: only the top of the body is safe.
      if (parent.type === 'variable_declaration' && same(parent.parent, block)) return block;
      return null;
    }
    /*
     * No parameter check is needed here, and that is not an oversight: a write
     * at the top of the body runs before any read after it, so it replaces the
     * caller's value rather than competing with it. What a parameter breaks is
     * a write that might NOT run - and that is exactly what "top level" rules out.
     */
    if ((language === 'python' || language === 'php') && parent.type === 'expression_statement' && same(parent.parent, block)) {
      return block;
    }
    return null;
  };

  interface WriteFacts {
    readonly write: Node;
    readonly value: Node;
    readonly region: Node;
    readonly range: readonly [number, number] | null;
  }
  interface WriteSurvey {
    /** Plain writes whose target IS the name. */
    readonly writes: ReadonlyArray<{ write: Node; value: Node }>;
    /** Any write the name receives some other way - or a function where that cannot be ruled out. */
    readonly otherWrite: boolean;
  }
  const surveyCache = new Map<string, WriteSurvey>();

  /*
   * NAMES THAT CANNOT BE READ FROM THE TEXT AT ALL. `with` and `eval` in
   * JavaScript, `$$name`, `${...}`, extract() and eval() in PHP, exec() and
   * locals() in Python: any of them in a function can write to any local in
   * it, under a name that appears nowhere. One of them present, and no name in
   * that function is a constant.
   */
  const dynamicScopeCache = new Map<string, boolean>();
  const DYNAMIC_CALLS = new Set(['eval', 'exec', 'extract', 'parse_str', 'locals', 'globals', 'vars']);
  const hasDynamicScope = (body: Node): boolean => {
    const key = `${body.startIndex}:${body.endIndex}`;
    const cached = dynamicScopeCache.get(key);
    if (cached !== undefined) return cached;
    /*
     * A function the grammar could not fully parse may hide a write inside the
     * part it gave up on - Java's grammar reads `(n) = x;` as an error, so that
     * write was invisible and the declaration looked like the only one.
     */
    let found = body.hasError;
    let walked = 0;
    const visit = (n: Node): void => {
      if (found || ++walked > 20000) {
        found = true;
        return;
      }
      const type = n.type;
      if (type === 'with_statement' && (language === 'javascript' || language === 'typescript')) found = true;
      else if (type === 'dynamic_variable_name') found = true;
      // C lets `goto` jump past `int n = 0;` into its block, leaving n unset.
      // (C++ refuses to compile that, so only C gives up here.)
      else if (type === 'goto_statement' && language === 'c') found = true;
      else if (type === 'identifier' && n.text === 'arguments' && (language === 'javascript' || language === 'typescript')) found = true;
      else if ((type === 'call_expression' || type === 'call' || type === 'function_call_expression') &&
               DYNAMIC_CALLS.has((n.childForFieldName('function')?.text ?? '').replace(/^\\/, ''))) found = true;
      if (!found) for (const c of n.namedChildren) if (c) visit(c);
    };
    visit(body);
    dynamicScopeCache.set(key, found);
    return found;
  };

  /** Every write to `name` in `body`, and whether any came some other way. */
  const survey = (name: string, body: Node): WriteSurvey => {
    const key = `${body.startIndex}:${body.endIndex}#${name}`;
    const cached = surveyCache.get(key);
    if (cached) return cached;

    const writes: Array<{ write: Node; value: Node }> = [];
    let otherWrite = hasDynamicScope(body);
    let walked = 0;
    const visit = (node: Node, walkDepth: number): void => {
      if (otherWrite) return;
      // Out of budget is "cannot tell", never "nothing more to see": a second
      // write in the 20th arm of an else-if chain is still a second write.
      if (walkDepth > 400 || ++walked > 20000) {
        otherWrite = true;
        return;
      }
      /*
       * ASSIGNMENT_NODES first, and this is not belt-and-braces.
       *
       * assignmentParts() looks for a `left`/`right` field pair, and a
       * comparison has exactly that - so `num > 200` was read as an assignment
       * of 200 to num. The folder then saw two assignments to `num` and gave
       * up, which is why every condition with a variable in it silently failed
       * to fold. The real tracer never hit this because it only ever calls
       * assignmentParts on nodes it has already checked.
       */
      const parts = ASSIGNMENT_NODES.has(node.type) ? assignmentParts(node) : null;
      if (parts) {
        const target = text(parts.target);
        if (bareName(target) === name && !/[()[\]{},]/.test(target)) {
          writes.push({ write: node, value: parts.value });
          // `n += 1` and Python's `n += 1` are writes the constant proof must see.
          if (/augmented/.test(node.type) || (node.childForFieldName('operator')?.text ?? '=') !== '=') otherWrite = true;
        } else if (wordIn(target, name)) {
          /*
           * The name is PART of what is written: `(n) = x`, `n, err := f()`,
           * `[n] = [x]`, `list($n) = ...`, `{ limit } = req.query`. None of those
           * was counted before, so the one plain `n := 0` looked like the only
           * write there was.
           */
          otherWrite = true;
          return;
        }
      } else if (writesWithoutAssignment(node, name)) {
        otherWrite = true;
        return;
      }
      for (const child of node.namedChildren) if (child) visit(child, walkDepth + 1);
    };
    visit(body, 0);

    const result = { writes, otherWrite };
    surveyCache.set(key, result);
    return result;
  };

  const writeCache = new Map<string, WriteFacts | null>();

  /** The one write that decides `name` in `body`, if there is exactly one sound one. */
  const soleWrite = (name: string, body: Node): WriteFacts | null => {
    const key = `${body.startIndex}:${body.endIndex}#${name}`;
    if (writeCache.has(key)) return writeCache.get(key) ?? null;
    const { writes, otherWrite } = survey(name, body);
    const only = writes.length === 1 && !otherWrite ? writes[0] : undefined;
    const found = only ? regionOfWrite(only.write, body) : null;
    const facts = only && found ? { write: only.write, value: only.value, region: found.region, range: found.range } : null;
    writeCache.set(key, facts);
    return facts;
  };

  /** For the constant proof: does `name` receive any write that is not a plain `name = value`? */
  const writtenOtherwise = (name: string, body: Node): boolean => survey(bareName(name), body).otherWrite;

  /** Does the sole write certainly run before `use`, and govern it? */
  const writeReaches = (facts: WriteFacts, use: Node | null): boolean =>
    !!use &&
    facts.write.endIndex <= use.startIndex &&
    use.startIndex >= facts.region.startIndex &&
    use.endIndex <= facts.region.endIndex;

  const constantOfName = (rawName: string, body: Node, depth: number, use: Node | null): Folded => {
    const name = bareName(rawName);
    const facts = soleWrite(name, body);
    if (!facts || !writeReaches(facts, use)) return undefined;

    const scopeKey = `${body.startIndex}:${body.endIndex}`;
    let perScope = constantCache.get(scopeKey);
    if (!perScope) {
      perScope = new Map<string, Folded>();
      constantCache.set(scopeKey, perScope);
    }
    if (perScope.has(name)) return perScope.get(name);

    const cycleKey = `${scopeKey}#${name}`;
    if (resolving.has(cycleKey)) return undefined;
    resolving.add(cycleKey);
    // `depth` is how many names deep the resolution itself is.
    let answer = foldExpression(facts.value, body, depth + 1);
    resolving.delete(cycleKey);
    if (typeof answer === 'number' && (!facts.range || answer < facts.range[0] || answer > facts.range[1])) {
      answer = undefined;
    }

    /*
     * Cached even when the answer was cut short by the depth budget. A budget
     * that ran out always answers undefined, which means "cannot tell", which
     * keeps the flow - so the worst a stale one can do is leave a false
     * positive that was already there. Caching a NARROWER answer would be the
     * dangerous direction, and undefined is never narrower.
     */
    perScope.set(name, answer);
    return answer;
  };

  /*
   * `s.charAt(i)` - THE ONE STRING METHOD, AND WHY ONLY THIS ONE.
   *
   * The note at the top says a folder that models String eventually deletes a
   * real finding, and that is still the policy. This is the exception, taken
   * because 299 of BenchmarkJava's cases decide a switch with it and because it
   * is as exact as arithmetic: a Java String is immutable, so a string literal,
   * or a local declared once with one, has one character at each index forever.
   * An index out of range throws at runtime, and folds to "cannot tell".
   *
   * Nothing else about strings is folded - not length(), not equals(), not
   * substring() - and a string that is a parameter, a field, or written twice
   * is not a string this knows.
   */
  const CHARACTER_LITERALS = new Set(['character_literal', 'char_literal', 'rune_literal']);

  const characterCode = (raw: string): Folded => {
    // Printable ASCII only, and no escapes: '\n' and 'é' are not worth being wrong about.
    const match = /^'([\x20-\x26\x28-\x5b\x5d-\x7e])'$/.exec(raw.trim());
    return match?.[1] !== undefined ? match[1].charCodeAt(0) : undefined;
  };

  const stringConstantOf = (node: Node, body: Node, depth: number): string | undefined => {
    if (depth > 12) return undefined;
    let n: Node = node;
    while (n.type === 'parenthesized_expression' && n.namedChildren.length === 1) n = n.namedChildren[0] ?? n;
    if (n.type === 'string_literal') {
      const match = /^"([^"\\]*)"$/.exec(n.text);
      return match?.[1];
    }
    if (n.type !== 'identifier') return undefined;
    const facts = soleWrite(n.text, body);
    if (!facts || !writeReaches(facts, n)) return undefined;
    const cycleKey = `${body.startIndex}:${body.endIndex}#string#${n.text}`;
    if (resolving.has(cycleKey)) return undefined;
    resolving.add(cycleKey);
    const value = stringConstantOf(facts.value, body, depth + 1);
    resolving.delete(cycleKey);
    return value;
  };

  const charAtOf = (call: Node, body: Node, depth: number): Folded => {
    if (call.childForFieldName('name')?.text !== 'charAt') return undefined;
    const args = (call.childForFieldName('arguments')?.namedChildren ?? []).filter((c): c is Node => c !== null);
    const receiver = call.childForFieldName('object');
    if (args.length !== 1 || !receiver) return undefined;
    const s = stringConstantOf(receiver, body, depth + 1);
    const index = foldExpression(args[0] ?? null, body, depth + 1);
    if (s === undefined || typeof index !== 'number' || index < 0 || index >= s.length) return undefined;
    return s.charCodeAt(index);
  };

  /*
   * THE OPERATOR IS NOT ALWAYS A FIELD, AND PYTHON IS WHY.
   *
   * Java, JavaScript, TypeScript, Go, PHP and the C family all name the two
   * sides of `a > b` left and right, and the `>` operator. Python names none of
   * the three, because Python allows `1 < x < 5` - a comparison there is a LIST
   * of operands with a LIST of operators, so there is no pair to name.
   *
   * The consequence was total rather than partial: no Python comparison folded
   * anywhere, so every constant-branch decoy in Python stayed a false positive
   * and nothing said so.
   *
   * The fallback reads the shape instead of the field names: exactly three
   * children, the outer two named, the middle one an unnamed token. That token
   * is the operator, whatever the grammar calls it. A chained comparison has
   * five children and returns null, which means "cannot tell", which is the
   * safe direction. `a.b` and `a instanceof B` match the shape and hand over
   * `.` and `instanceof`, neither of which the switch below knows, so they fold
   * to undefined exactly as they did before.
   */
  const binaryParts = (node: Node): { left: Node; right: Node; operator: string } | null => {
    const left = node.childForFieldName('left');
    const right = node.childForFieldName('right');
    const named = node.childForFieldName('operator')?.text ?? '';
    if (left && right && named) return { left, right, operator: named };

    const children = node.children.filter((c): c is Node => c !== null);
    if (children.length !== 3) return null;
    const [a, op, b] = children;
    if (!a || !op || !b) return null;
    if (!a.isNamed || !b.isNamed || op.isNamed) return null;
    return { left: a, right: b, operator: op.text };
  };

  /*
   * The same problem one operand down, and this one was not failing safe.
   *
   * Python's not_operator has no operator field either - `not` is an unnamed
   * child, like the `>` above. The unary branch needs an operator field so it
   * skipped, and the single-child unwrap below picked up a node with exactly
   * one named child and returned it. `not True` folded to TRUE.
   *
   * Everything else in this folder fails toward "cannot tell", where the worst
   * outcome is a false positive that was already there. This one failed toward
   * a CONFIDENT WRONG ANSWER: the engine believed a branch ran when it did not,
   * skipped the arm that really ran, and stopped reporting a real flow. That is
   * the failure this tool exists to prevent, and it was sitting inside the
   * feature that was supposed to be about precision.
   *
   * Restricted to the three operators the switch can actually resolve. An
   * unknown leading token is not treated as unary at all, and falls through to
   * the unwrap guard, which now refuses it.
   */
  const UNARY_TOKENS = new Set(['!', 'not', '-']);

  const unaryParts = (node: Node): { operand: Node; operator: string } | null => {
    const operand = node.childForFieldName('argument') ?? node.childForFieldName('operand');
    const operator = node.childForFieldName('operator')?.text ?? '';
    if (operand && operator) return { operand, operator };

    const children = node.children.filter((c): c is Node => c !== null);
    if (children.length !== 2) return null;
    const [op, value] = children;
    if (!op || !value || op.isNamed || !value.isNamed) return null;
    if (!UNARY_TOKENS.has(op.text)) return null;
    return { operand: value, operator: op.text };
  };

  /*
   * Unwrapping a single-child node is only safe when nothing was thrown away.
   *
   * `(x)` discards two brackets and means x. `not x` discards the word `not`
   * and does NOT mean x. Both have one named child, and the old test could not
   * tell them apart - which is how `not True` became true.
   *
   * So the test is on what gets discarded rather than on the node's name: every
   * unnamed child must be pure punctuation. A discarded WORD, or any symbol not
   * on this list, means the node transforms its operand in a way this folder
   * has not been taught, and the answer is "cannot tell".
   *
   * `$` is here for PHP, whose variable_name wraps a bare name in a `$` token.
   */
  const WRAPPER_PUNCTUATION = new Set(['(', ')', '[', ']', '{', '}', ',', ';', '$']);

  /*
   * CHECK THE OPERATOR BEFORE FOLDING THE OPERANDS, AND THIS IS NOT A TIDY-UP.
   *
   * Reading the operator off the shape instead of a field made binaryParts
   * match things it was never meant to: `a.b` is three children with the outer
   * two named, so is `a instanceof B`, so is every member access in every
   * minified file on earth. The switch below has no case for `.`, so all of
   * them still folded to undefined and the ANSWER was never wrong.
   *
   * The cost was. Folding an operand that turns out to be a bare name calls
   * constantOfName, and constantOfName walks the entire enclosing function
   * looking for assignments. DVWA ships an inlined sha256 - one 19KB function,
   * thousands of member accesses - and the scan went from finishing to running
   * out of memory on 1.1MB of source with 7GB free.
   *
   * It did not show up in the suite, the benchmark, or the metamorphic run.
   * Fixture files are small and tidy, and BenchmarkJava's generated cases are
   * about forty lines each; this needed one real file written by somebody
   * optimising for size. The corpus check is in the repo precisely so that
   * "all tests pass" is not the last word, and this is the first time it has
   * caught something the tests could not.
   *
   * So the operator is checked first. An operator with no case cannot change
   * any answer, and now it does not cost a tree walk to find that out.
   */
  const FOLDABLE_OPERATORS = new Set([
    '+', '-', '*', '/', '%',
    '>', '<', '>=', '<=', '==', '!=',
    '&&', 'and', '||', 'or',
  ]);

  const INTEGER_DIVISION = language === 'java' || language === 'c' || language === 'cpp' || language === 'go';
  /*
   * Where arithmetic stops being exact. Java, C, C++ and Go wrap at their type's
   * width - checked here at 32 bits, the narrowest `int` any of them uses - and
   * JavaScript, Python and PHP lose integer precision past 2^53. Outside that,
   * "cannot tell".
   */
  const inRange = (value: number): Folded =>
    INTEGER_DIVISION
      ? value >= -2147483648 && value <= 2147483647 ? value : undefined
      : Math.abs(value) <= 2 ** 53 ? value : undefined;

  const foldExpression = (node: Node | null, body: Node, depth: number): Folded => {
    if (!node || depth > 12) return undefined;

    // 'B' is 66 in Java, C, C++ and Go, where a character IS an integer. Only
    // the grammars that have a character literal get this; a quoted 'B' in
    // JavaScript, Python or PHP is a string, and strings are not folded.
    if (CHARACTER_LITERALS.has(node.type)) return characterCode(node.text);
    if (language === 'java' && node.type === 'method_invocation') return charAtOf(node, body, depth);

    const binary = binaryParts(node);

    if (binary) {
      const { left, right, operator } = binary;
      if (!FOLDABLE_OPERATORS.has(operator)) return undefined;
      const a = foldExpression(left, body, depth + 1);
      const b = foldExpression(right, body, depth + 1);
      if (a === undefined || b === undefined) return undefined;
      if (typeof a === 'number' && typeof b === 'number') {
        switch (operator) {
          case '+': return inRange(a + b);
          case '-': return inRange(a - b);
          case '*': return inRange(a * b);
          // Integer division truncates in Java, C, C++ and Go. In JavaScript,
          // Python and PHP `7 / 2` is 3.5, and in Python `-7 % 3` is 2.
          case '/': return b === 0 || !INTEGER_DIVISION ? undefined : inRange(Math.trunc(a / b));
          case '%': return b === 0 || (language === 'python' && (a < 0 || b < 0)) ? undefined : inRange(a % b);
          case '>': return a > b;
          case '<': return a < b;
          case '>=': return a >= b;
          case '<=': return a <= b;
          case '==': return a === b;
          case '!=': return a !== b;
          default: return undefined;
        }
      }
      if (typeof a === 'boolean' && typeof b === 'boolean') {
        switch (operator) {
          case '&&': case 'and': return a && b;
          case '||': case 'or': return a || b;
          case '==': return a === b;
          case '!=': return a !== b;
          default: return undefined;
        }
      }
      return undefined;
    }

    // `!x`, Python's `not x`, and unary minus.
    const unary = unaryParts(node);
    if (unary) {
      const value = foldExpression(unary.operand, body, depth + 1);
      if ((unary.operator === '!' || unary.operator === 'not') && typeof value === 'boolean') {
        return !value;
      }
      if (unary.operator === '-' && typeof value === 'number') return inRange(-value);
      return undefined;
    }

    // Parentheses and other single-child wrappers - see WRAPPER_PUNCTUATION.
    const named = node.namedChildren.filter((c): c is Node => c !== null);
    if (named.length === 1) {
      const discardsOnlyPunctuation = node.children.every(
        (c) => c === null || c.isNamed || WRAPPER_PUNCTUATION.has(c.text),
      );
      if (discardsOnlyPunctuation) return foldExpression(named[0] ?? null, body, depth + 1);
      return undefined;
    }

    if (named.length === 0) {
      const literal = foldLiteral(text(node));
      if (literal !== undefined) return literal;
      /*
       * A bare word that is not a literal is a name, and asking whether it is
       * bound to a constant is the whole point of constantOfName.
       *
       * This used to test `/identifier/` against the NODE TYPE, which is true
       * of Java's `identifier` and JavaScript's `identifier` and false of PHP -
       * a PHP variable is a `variable_name` wrapping a `name`, and neither
       * spelling contains the word. So no PHP variable folded, and every PHP
       * condition mentioning one was undecidable.
       *
       * Testing the TEXT covers all eight without a list of node names to keep
       * up to date. A keyword like `null` or `nil` reaches constantOfName,
       * finds no assignment, and returns undefined - the same answer it gave
       * before, by a shorter route.
       */
      if (/^[A-Za-z_][\w]*$/.test(text(node).trim())) {
        return constantOfName(text(node), body, depth, node);
      }
      return undefined;
    }

    return undefined;
  };

  /*
   * THE THREE PARTS OF A TERNARY, WHICH NOT EVERY GRAMMAR AGREES TO NAME.
   *
   * The first version of the folder read `condition`, `consequence` and
   * `alternative` as fields, which is right for Java, JavaScript, TypeScript,
   * Go and the C family - and quietly wrong for two of the eight:
   *
   *   python   no fields at all, children in WRITTEN order: A if C else B,
   *            so the middle child is the condition and the first is the value
   *   php      names `condition` and `alternative`, but not `consequence`
   *
   * Measured, not assumed. The folder was written against Java, verified
   * against Java, and would have shipped carrying a language-shaped hole -
   * Python would have kept tracing into dead branches while every other
   * language stopped, and nothing would have failed to say so.
   *
   * Python is matched on the language id rather than on a shape heuristic like
   * "no condition field and three children". A heuristic would be one grammar
   * away from silently reading a condition as a value, and that error deletes
   * findings rather than adding them.
   */
  const ternaryParts = (
    node: Node,
  ): { condition: Node | null; consequence: Node | null; alternative: Node | null } => {
    const named = node.namedChildren.filter((c): c is Node => c !== null);

    if (language === 'python' && named.length === 3) {
      return {
        consequence: named[0] ?? null,
        condition: named[1] ?? null,
        alternative: named[2] ?? null,
      };
    }

    const condition = node.childForFieldName('condition');
    const alternative = node.childForFieldName('alternative');
    let consequence = node.childForFieldName('consequence');

    // PHP leaves the middle one unnamed; it is whichever child is left over.
    if (!consequence && condition) {
      const same = (a: Node, b: Node | null): boolean =>
        b !== null && a.startIndex === b.startIndex && a.endIndex === b.endIndex;
      consequence = named.find((c) => !same(c, condition) && !same(c, alternative)) ?? null;
      /*
       * `$a ?: $b` has two operands, not three, so there IS no left-over child
       * and the search above finds nothing. In that form the value when the
       * condition holds is the condition itself.
       *
       * Falling back to the condition rather than to null matters because null
       * would make a decidable elvis select NOTHING, and selecting nothing is
       * how a folder deletes a flow instead of merely failing to narrow one.
       */
      consequence ??= condition;
    }

    return { condition, consequence, alternative };
  };

  /** True or false when the condition is decidable, undefined when it is not. */
  const conditionTruth = (node: Node | null, body: Node): boolean | undefined => {
    const value = foldExpression(node, body, 0);
    return typeof value === 'boolean' ? value : undefined;
  };

  /**
   * The branch of an if-statement that certainly does not run, if any.
   *
   * `consequence ?? body` is PHP, and it is the reason this was HALF broken
   * rather than broken - which is worse, because half a feature looks like a
   * working one. PHP names the else `alternative` like everyone else, so a
   * condition that folded TRUE correctly dropped the dead else. It calls the
   * then-block `body`, not `consequence`, so a condition that folded FALSE
   * asked for a field that does not exist, got null, and kept the dead arm.
   *
   * Same statement, same file, same folder: one direction fixed, one direction
   * silently untouched. Nothing failed, because "no dead branch here" is a
   * perfectly ordinary answer.
   */
  const deadBranchOf = (node: Node, body: Node): Node | null => {
    const truth = conditionTruth(node.childForFieldName('condition'), body);
    if (truth === undefined) return null;
    return truth
      ? node.childForFieldName('alternative')
      : (node.childForFieldName('consequence') ?? node.childForFieldName('body'));
  };

  /*
   * WHICH CASES OF A SWITCH CAN RUN.
   *
   * Decided only when the selector AND every case label fold to a number or a
   * boolean of the same kind. One label the folder cannot read - an enum
   * constant, a string, a pattern - and the whole switch is undecided, because
   * that label might be the one that matches.
   *
   * From the matching case (or `default` when none matches, or nothing at all
   * when there is no default), execution runs on into the next case until a
   * `break`, `return`, `throw` or `continue` sits DIRECTLY in a case - one
   * nested inside an `if` might not run, so it does not stop the fall. Go and
   * Java's arrow cases do not fall through; Go's explicit `fallthrough` does.
   * Every case outside that run is dead.
   *
   * C has one more way in: `goto`. A label inside the switch can be jumped to
   * whatever the selector says, and so can a case label buried inside a nested
   * block (Duff's device). Either one, and the switch is left undecided.
   *
   * `certain` answers a narrower question for the tracer: does this statement
   * run EVERY time the switch does? Only if it is in the run and no jump of any
   * kind - nested or not - comes before it in the run. A clean write that is
   * certain may clear a value; one that is merely possible may not.
   */
  const switchDecision = (node: Node, body: Node): SwitchDecision | null => {
    const shape = switchShape(node);
    if (!shape || !shape.selector) return null;
    const selector = foldExpression(shape.selector, body, 0);
    if (selector === undefined) return null;

    let matched = -1;
    let defaultIndex = -1;
    for (let i = 0; i < shape.groups.length; i++) {
      const group = shape.groups[i];
      if (!group) return null;
      if (group.labels === 'default') {
        if (defaultIndex === -1) defaultIndex = i;
        continue;
      }
      for (const label of group.labels) {
        const value = foldExpression(label, body, 0);
        if (value === undefined || typeof value !== typeof selector) return null;
        if (matched === -1 && value === selector) matched = i;
      }
    }
    const start = matched !== -1 ? matched : defaultIndex;

    const live: number[] = [];
    if (start !== -1) {
      for (let i = start; i < shape.groups.length; i++) {
        const group = shape.groups[i];
        if (!group) break;
        live.push(i);
        if (shape.fallthrough === 'never') break;
        if (shape.fallthrough === 'explicit') {
          if (group.statements[group.statements.length - 1]?.type !== 'fallthrough_statement') break;
          continue;
        }
        if (group.statements.some((s) => TERMINATORS.has(s.type))) break;
      }
    }
    const liveSet = new Set(live);
    const dead = shape.groups.filter((_, i) => !liveSet.has(i)).map((g) => g.node);
    const inside = (outer: Node, inner: Node): boolean =>
      inner.startIndex >= outer.startIndex && inner.endIndex <= outer.endIndex;

    const certain = (n: Node): boolean => {
      for (const i of live) {
        const group = shape.groups[i];
        if (!group) return false;
        const jumpBefore = containsJumpBefore(group.node, n.startIndex);
        if (inside(group.node, n)) return !jumpBefore;
        if (jumpBefore) return false;
      }
      return false;
    };

    const matchedGroup = matched !== -1 ? shape.groups[matched] : undefined;
    const line = node.startPosition.row + 1;
    const note =
      matchedGroup && matchedGroup.labels !== 'default'
        ? `the switch on line ${line} always takes \`case ${text(matchedGroup.labels.find((l) => foldExpression(l, body, 0) === selector) ?? null)}\``
        : start !== -1
          ? `the switch on line ${line} matches no case, so only \`default\` runs`
          : `the switch on line ${line} matches no case and has no default, so none of it runs`;

    return { dead, certain, note };
  };

  return { foldExpression, conditionTruth, ternaryParts, deadBranchOf, switchDecision, writtenOtherwise };
}

/** What a decided switch tells the tracer and the constant proof. */
export interface SwitchDecision {
  /** Case groups that cannot run. */
  readonly dead: readonly Node[];
  /** Whether a node inside the switch runs every time the switch does. */
  readonly certain: (node: Node) => boolean;
  /** A sentence for a receipt. */
  readonly note: string;
}

/** Every switch node type, in every grammar here - decided or not. */
export const SWITCH_NODES = new Set([
  'switch_statement', // JS, TS, C, C++, PHP
  'switch_expression', // Java - the statement form too
  'expression_switch_statement', // Go
]);

/** A statement that leaves a switch when it sits directly in a case. */
const TERMINATORS = new Set([
  'break_statement',
  'continue_statement',
  'return_statement',
  'throw_statement',
  'yield_statement',
  'goto_statement',
]);

/** Any statement that can leave early, wherever it is nested. */
const JUMPS = new Set([...TERMINATORS, 'labeled_statement']);

function containsJumpBefore(node: Node, before: number): boolean {
  if (node.startIndex >= before) return false;
  if (JUMPS.has(node.type)) return true;
  for (const child of node.namedChildren) {
    if (child && child.startIndex < before && containsJumpBefore(child, before)) return true;
  }
  return false;
}

interface SwitchGroup {
  readonly node: Node;
  readonly labels: readonly Node[] | 'default';
  readonly statements: readonly Node[];
}

interface SwitchShape {
  readonly selector: Node | null;
  readonly groups: readonly SwitchGroup[];
  readonly fallthrough: 'c-style' | 'never' | 'explicit';
}

const named = (n: Node | null | undefined): Node[] =>
  (n?.namedChildren ?? []).filter((c): c is Node => c !== null);

/**
 * Read a switch into one shape, whatever the grammar calls its parts. Five
 * grammars, five vocabularies - measured from each grammar's own trees, not
 * assumed from one. Null means "not a shape this knows", and an unknown shape
 * is an undecided switch.
 */
function switchShape(node: Node): SwitchShape | null {
  const defaultOf = (n: Node): boolean => /^default\b/.test(n.text.trim());

  // Java: switch_block of statement groups (falls through) or arrow rules (never).
  if (node.type === 'switch_expression') {
    const block = node.childForFieldName('body');
    const kids = named(block);
    const isGroup = (k: Node): boolean => k.type === 'switch_block_statement_group';
    const isRule = (k: Node): boolean => k.type === 'switch_rule';
    if (kids.length === 0 || !(kids.every(isGroup) || kids.every(isRule))) return null;
    const groups: SwitchGroup[] = [];
    for (const k of kids) {
      const labels = named(k).filter((c) => c.type === 'switch_label');
      const statements = named(k).filter((c) => c.type !== 'switch_label');
      if (labels.length === 0) return null;
      if (labels.some(defaultOf)) {
        if (labels.length > 1) return null; // `case 1: default:` - keep it simple
        groups.push({ node: k, labels: 'default', statements });
      } else {
        groups.push({ node: k, labels: labels.flatMap((l) => named(l)), statements });
      }
    }
    return {
      selector: node.childForFieldName('condition'),
      groups,
      fallthrough: kids.every(isRule) ? 'never' : 'c-style',
    };
  }

  // Go: cases directly under the switch; `fallthrough` must be asked for.
  if (node.type === 'expression_switch_statement') {
    const groups: SwitchGroup[] = [];
    for (const k of named(node)) {
      if (k.type === 'expression_case') {
        const value = k.childForFieldName('value');
        const labels = value?.type === 'expression_list' ? named(value) : value ? [value] : [];
        if (labels.length === 0) return null;
        groups.push({ node: k, labels, statements: named(k).filter((c) => !value || c.startIndex !== value.startIndex) });
      } else if (k.type === 'default_case') {
        groups.push({ node: k, labels: 'default', statements: named(k) });
      }
    }
    return { selector: node.childForFieldName('value'), groups, fallthrough: 'explicit' };
  }

  if (node.type !== 'switch_statement') return null;
  const block = node.childForFieldName('body');
  const selector = node.childForFieldName('condition') ?? node.childForFieldName('value');
  const kids = named(block);
  const groups: SwitchGroup[] = [];

  // A label inside the switch, or a case label that is not directly in its
  // body, is a way in that the selector does not control. Decline.
  const hasHiddenEntry = (n: Node, depthInBody: number, inNestedSwitch: boolean): boolean => {
    for (const c of named(n)) {
      if (c.type === 'labeled_statement') return true;
      if (!inNestedSwitch && depthInBody > 0 && (c.type === 'case_statement' || c.type === 'switch_case')) return true;
      // A nested switch's cases are its own; a label inside it is still a way in.
      if (hasHiddenEntry(c, depthInBody + 1, inNestedSwitch || SWITCH_NODES.has(c.type))) return true;
    }
    return false;
  };
  if (!block || hasHiddenEntry(block, 0, false)) return null;

  for (const k of kids) {
    if (k.type === 'switch_case' || k.type === 'case_statement' || k.type === 'switch_default' || k.type === 'default_statement') {
      const value = k.childForFieldName('value');
      // GNU's `case 1 ... 5:` is a RANGE, and the grammar reads it as `case 1`
      // followed by an error. A label that did not parse cleanly is not read.
      if (value && (value.hasError || /\.\.\./.test(k.text.split(':')[0] ?? ''))) return null;
      if (k.hasError) return null;
      const isDefault = k.type === 'switch_default' || k.type === 'default_statement' || (!value && defaultOf(k));
      const statements = named(k).filter((c) => !value || c.startIndex !== value.startIndex);
      if (isDefault) groups.push({ node: k, labels: 'default', statements });
      else if (value) groups.push({ node: k, labels: [value], statements });
      else return null;
    } else if (k.type !== 'comment') {
      return null; // a statement before the first case, or a shape we do not know
    }
  }
  return { selector, groups, fallthrough: 'c-style' };
}
