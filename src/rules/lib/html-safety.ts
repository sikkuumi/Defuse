/**
 * IS THIS EXPRESSION SAFE TO HAND TO AN HTML PARSER?
 * ==================================================
 *
 * WHY THIS FILE EXISTS
 *
 * The XSS rule used to fire on the SHAPE of the line alone:
 *
 *     element.innerHTML = <anything not a fixed string>
 *
 * and then print "No escaping or sanitiser call is visible at this line."
 *
 * Pointing the scanner at this project's own browser UI produced seven of
 * these. Every one was wrong, and one of them was wrong in a way that matters:
 *
 *     $('progressLabel').innerHTML = `<span class="err">${escapeHtml(msg)}</span>`
 *
 * The escaper is RIGHT THERE, in the same expression, four characters from the
 * value it protects. The finding said we could not see it. That is not a
 * conservative guess, it is a false statement about code we had already parsed,
 * and a tool whose entire pitch is "we never overclaim" cannot afford to make
 * it.
 *
 * WHAT THIS DOES
 *
 * It answers one question about one expression: can every value spliced into
 * this string be PROVEN incapable of carrying markup? A value qualifies when
 * it is
 *
 *   - a fixed literal (nobody injects into a constant),
 *   - a number, or an expression that can only produce one (`x.length`,
 *     `a - b`, `n.toFixed(2)`) - digits cannot open a tag,
 *   - the result of a known escaping function (`escapeHtml`, `encodeURIComponent`,
 *     `DOMPurify.sanitize`),
 *   - a local variable or local function whose every possible value is,
 *     recursively, one of the above.
 *
 * The last case is what makes it useful rather than cosmetic. Real UI code is
 * built out of small render helpers - `list.map(renderRow).join('')` - and a
 * check that stops at the first function call proves nothing about any of them.
 *
 * WHAT IT DELIBERATELY DOES NOT DO
 *
 * It PROVES SAFE or it says NOTHING. There is no "probably fine". Anything it
 * does not recognise - a bare property access, an imported function, a value
 * from another file - comes back unproven, and the finding still fires. That
 * asymmetry is the whole design: a wrong "safe" hides a real cross-site
 * scripting bug, while a wrong "unproven" only costs the reader a second look.
 *
 * It also does not decide whether the value is attacker-controlled. That is the
 * tracer's job, one pass later. This is the narrower question of whether the
 * value could carry markup at all, and it is worth asking first because a value
 * that provably cannot needs no trace.
 *
 * SCOPE: JavaScript and TypeScript only. Those are the languages whose HTML
 * sinks take an expression built in the same file. The Python, Java and Go
 * branches of the XSS rule are untouched and still report on shape alone -
 * that gap is stated in the rule's `support` notes rather than papered over.
 */

import type { Node } from 'web-tree-sitter';
import type { LanguageId } from '../../parse/languages.js';

/* ---------------------------------------------------------------------------
 * The escaper list.
 *
 * A name gets in here only if its ONE job is to make text safe for HTML. That
 * excludes `escape()` (deprecated URL escaping - leaves `<` alone), `String()`
 * (converts, does not clean) and `JSON.stringify` (its output can contain a
 * literal `</script>`, which closes the surrounding tag and ends the game).
 * ------------------------------------------------------------------------ */
const ESCAPER_NAMES: ReadonlySet<string> = new Set([
  'escapeHtml',
  'escapeHTML',
  'escapehtml',
  'htmlEscape',
  'html_escape',
  'escapeHtmlAttribute',
  'escapeAttribute',
  'encodeURIComponent',
  'encodeURI',
  'sanitize',
  'sanitizeHtml',
  'sanitizeHTML',
  'purify',
]);

/** Member-call escapers, matched on the property name of `X.sanitize(...)`. */
const ESCAPER_METHODS: ReadonlySet<string> = new Set(['sanitize', 'escape', 'clean']);

/** Objects whose `.escape`/`.sanitize` we trust. Prevents `router.escape()` counting. */
const ESCAPER_OBJECTS: ReadonlySet<string> = new Set([
  'DOMPurify',
  'dompurify',
  'sanitizeHtml',
  'xss',
  'he',
  'validator',
  'escapeHtml',
]);

/** Properties that can only ever hold a number. Digits cannot open a tag. */
const NUMERIC_PROPERTIES: ReadonlySet<string> = new Set(['length', 'size', 'byteLength']);

/** Methods whose return value is a number or a boolean, whatever the receiver. */
const NUMERIC_METHODS: ReadonlySet<string> = new Set([
  'toFixed',
  'indexOf',
  'lastIndexOf',
  'charCodeAt',
  'codePointAt',
  'includes',
  'startsWith',
  'endsWith',
  'has',
  'valueOf',
]);

/** Operators whose result is a number or a boolean regardless of the operands. */
const NUMERIC_OPERATORS: ReadonlySet<string> = new Set([
  '-',
  '*',
  '/',
  '%',
  '**',
  '<',
  '>',
  '<=',
  '>=',
  '==',
  '!=',
  '===',
  '!==',
  'instanceof',
  'in',
  '&',
  '|',
  '^',
  '<<',
  '>>',
  '>>>',
]);

/** Array methods that pass their safety straight through from the receiver. */
const PASSTHROUGH_METHODS: ReadonlySet<string> = new Set([
  'filter',
  'slice',
  'sort',
  'reverse',
  'flat',
  'concat',
  'toSorted',
  'toReversed',
]);

/** Node types that open a new function scope. We never resolve names across one. */
const FUNCTION_SCOPES: ReadonlySet<string> = new Set([
  'function_declaration',
  'function_expression',
  'function',
  'arrow_function',
  'method_definition',
  'generator_function',
  'generator_function_declaration',
]);

/** How far the recursion may go before giving up and reporting unproven. */
const MAX_DEPTH = 30;

/** How many nested calls we will follow with their arguments bound. */
const MAX_FRAMES = 6;

export interface HtmlSafety {
  /** True only when EVERY spliced-in value was proven incapable of carrying markup. */
  readonly proven: boolean;
  /** Source text of the parts we could not prove. Named in the finding. */
  readonly unproven: readonly string[];
  /** Escaping steps we actually saw run. Named in the finding when it still fires. */
  readonly escapers: readonly string[];
}

const NOT_APPLICABLE: HtmlSafety = { proven: false, unproven: [], escapers: [] };

/**
 * A binding is normally the expression a caller passed. `NUMERIC` is the one
 * exception: a name the LANGUAGE guarantees holds a number, with no expression
 * anywhere to point at. See `judgeIteratorCallback`.
 */
const NUMERIC = Symbol('numeric-by-language');
type Binding = Node | typeof NUMERIC;

export function supportsHtmlSafety(language: LanguageId): boolean {
  return language === 'javascript' || language === 'typescript';
}

/**
 * Judge one expression. `root` is the file's root node, used to look up
 * function declarations; pass `ctx.file.root`.
 */
export function analyzeHtmlSafety(node: Node, root: Node, language: LanguageId): HtmlSafety {
  if (!supportsHtmlSafety(language)) return NOT_APPLICABLE;

  const unproven: string[] = [];
  const escapers = new Set<string>();
  const seen = new Set<string>();

  /* ---------------------------------------------------------------------
   * ARGUMENT BINDING
   *
   * A render helper judged on its own is almost never provably safe:
   *
   *     function tile(count, label, note, className) {
   *       return `<div class="${className}"><b>${count}</b>${label}</div>`;
   *     }
   *
   * `className` is a parameter, so on its own it could be anything, and the
   * helper reads as unsafe at every call site. But the call sites say:
   *
   *     tile(flow, 'flow-verified', '...', 'tile-verified')
   *
   * - all four arguments are literals or numbers. The helper is safe HERE,
   * which is the only question being asked.
   *
   * So each call pushes a frame binding parameter names to the argument
   * EXPRESSIONS, and a parameter resolves to whatever the caller passed. This
   * is the same interprocedural move the taint tracer makes one pass later,
   * for the same reason: a function boundary is not an analysis boundary.
   *
   * The frame is popped while the argument itself is judged, so an argument
   * that happens to reuse a parameter's name resolves in the CALLER's scope,
   * where it belongs.
   * ------------------------------------------------------------------- */
  const frames: Array<Map<string, Binding>> = [];

  const collapse = (n: Node): string => (n.text ?? '').replace(/\s+/g, ' ').trim().slice(0, 60);

  /**
   * Returns true when `n` is proven safe. Records the reason for every
   * failure so the finding can point at the actual risky sub-expression
   * instead of the whole statement.
   */
  const judge = (n: Node | null, depth: number): boolean => {
    if (!n) return false;
    // Every `false` this function returns MUST leave a reason behind. A verdict
    // of "not proven" with nothing to point at produces a finding that says
    // "something here is unsafe" and names nothing - which is the vague,
    // unfalsifiable output this whole project exists to avoid.
    if (depth > MAX_DEPTH) {
      unproven.push(`${collapse(n)} (nested deeper than this analysis follows)`);
      return false;
    }
    // A name that refers to itself (a recursive render helper) must not spin.
    // The back-edge stops rather than re-judging: every sub-expression of the
    // function body is judged exactly once on the way in, so the second visit
    // could not discover anything the first did not. The key includes the frame
    // depth, because the same expression judged with different arguments bound
    // is a different question.
    const key = `${n.id}#${frames.length}`;
    if (seen.has(key)) return true;
    seen.add(key);

    switch (n.type) {
      /* ---- Fixed values ---- */
      case 'string':
      case 'number':
      case 'true':
      case 'false':
      case 'null':
      case 'undefined':
      case 'regex':
        return true;

      /* ---- A comment produces no value, so it cannot carry markup ---- */
      case 'comment':
        return true;

      /* ---- `a ${b} c` ---- */
      case 'template_string': {
        let ok = true;
        for (const child of n.namedChildren) {
          if (!child) continue;
          if (child.type !== 'template_substitution') continue;
          /*
           * A `${ }` hole can contain a comment BEFORE the expression, and this
           * used to take the substitution's first named child - which in that
           * case is the comment, not the code:
           *
           *     ${
           *       // A traced path is only as strong as its weakest hop.
           *       verified && finding.unmodelledHops?.length ? ... : ''
           *     }
           *
           * Scanning this project's own UI found it: the checker reported the
           * COMMENT as the thing it could not prove safe, and never looked at
           * the ternary underneath. Both directions of that bug are bad - here
           * it invented a false alarm, but a hole whose comment came first and
           * whose expression was genuinely dangerous would have been waved
           * through the moment `comment` counted as safe.
           *
           * So: drop comments, then judge EVERY remaining part rather than the
           * first one. A hole holds one expression, but "judge all of them" is
           * the reading that cannot silently skip anything.
           */
          const parts = child.namedChildren.filter(
            (c): c is Node => c !== null && c.type !== 'comment',
          );
          for (const part of parts) if (!judge(part, depth + 1)) ok = false;
        }
        return ok;
      }

      /* ---- a + b, a - b, a || b ---- */
      case 'binary_expression': {
        const operator = n.childForFieldName('operator')?.text ?? '';
        // `a - b` is a number whatever a and b are; no need to look inside.
        if (NUMERIC_OPERATORS.has(operator)) return true;
        const left = judge(n.childForFieldName('left'), depth + 1);
        const right = judge(n.childForFieldName('right'), depth + 1);
        return left && right;
      }

      case 'unary_expression':
        return true; // !x, -x, ~x, +x - all number or boolean

      case 'parenthesized_expression':
        return judge(n.namedChildren.find((c) => c !== null) ?? null, depth + 1);

      /* ---- cond ? a : b - the condition never reaches the page ---- */
      case 'ternary_expression': {
        const consequence = judge(n.childForFieldName('consequence'), depth + 1);
        const alternative = judge(n.childForFieldName('alternative'), depth + 1);
        return consequence && alternative;
      }

      case 'array': {
        let ok = true;
        for (const element of n.namedChildren) {
          if (!element) continue;
          if (!judge(element, depth + 1)) ok = false;
        }
        return ok;
      }

      case 'arrow_function':
      case 'function_expression':
      case 'function':
      case 'function_declaration': {
        // Reached as a VALUE (`rows.map(renderRow)`), so nobody told us what
        // the arguments will be. Push an empty frame so an enclosing call's
        // bindings cannot leak in and answer for a parameter they never saw.
        frames.push(new Map());
        const verdict = judgeFunctionResult(n, depth + 1);
        frames.pop();
        return verdict;
      }

      case 'member_expression': {
        const property = n.childForFieldName('property')?.text ?? '';
        if (NUMERIC_PROPERTIES.has(property)) return true;
        unproven.push(collapse(n));
        return false;
      }

      case 'call_expression':
        return judgeCall(n, depth);

      case 'identifier':
      case 'shorthand_property_identifier': {
        // A bound parameter resolves to what the caller actually passed.
        const frame = frames[frames.length - 1];
        const bound = frame?.get(n.text ?? '');
        if (bound === NUMERIC) return true;
        if (bound) {
          // Judge the argument in the CALLER's scope, not this one.
          const saved = frames.pop() as Map<string, Binding>;
          const verdict = judge(bound, depth + 1);
          frames.push(saved);
          return verdict;
        }

        const bindings = resolveBinding(n);
        if (bindings.length > 0) {
          let ok = true;
          for (const binding of bindings) if (!judge(binding, depth + 1)) ok = false;
          return ok;
        }

        /*
         * An escaper passed BY REFERENCE:
         *
         *     finding.unmodelledHops.map(escapeHtml).join(', ')
         *
         * This is the same promise as calling it, and it is one of the most
         * common safe idioms in real UI code. Without this branch the name
         * resolves to the function DECLARATION and we judge its body, which
         * ends at `String(x).replace(...)` - a `.replace()` call we cannot
         * prove anything about. The checker then reported the innards of its
         * own escaper as the unsafe part, which is a confusing way to be wrong.
         *
         * The `bindings.length === 0` test above is what keeps this honest, and
         * makes it STRICTER than the call form: a local `const sanitize = x =>
         * x` shadows the trusted name, resolves first, and gets judged on its
         * actual body instead of being waved through on its name.
         */
        if (ESCAPER_NAMES.has(n.text ?? '')) {
          escapers.add(`${n.text}()`);
          return true;
        }
        // A bare name can also be a function passed by reference -
        // `rows.map(renderRow)`. Without this the commonest shape in real UI
        // code resolves to nothing and every render helper reads as unproven.
        const fn = findFunctionNamed(n.text ?? '', root);
        if (fn) return judgeFunctionResult(fn, depth + 1);

        unproven.push(collapse(n));
        return false;
      }

      default:
        unproven.push(collapse(n));
        return false;
    }
  };

  /* ---- Calls ------------------------------------------------------------ */
  const judgeCall = (n: Node, depth: number): boolean => {
    const callee = n.childForFieldName('function');
    const args = n.childForFieldName('arguments');
    const argList = args ? args.namedChildren.filter((c): c is Node => c !== null) : [];

    if (callee && callee.type === 'identifier') {
      const name = callee.text ?? '';

      if (ESCAPER_NAMES.has(name)) {
        /*
         * Trusting a name is a CONVENTION, not a proof, and a file is free to
         * break it. `sanitize` is on the trusted list; a codebase that writes
         *
         *     const sanitize = (x) => x;
         *
         * has a function with the right name that cleans nothing, and taking
         * the name at face value silences the rule for the whole file.
         *
         * We do not try to decide whether an arbitrary local escaper is any
         * good - that is a research problem. We check the one case that needs
         * no judgement: a function that hands back its own argument untouched
         * escapes nothing, whatever it is called. Anything more involved keeps
         * the benefit of the doubt, which is what `limitations` already says.
         */
        const local = findFunctionNamed(name, root);
        if (local && isIdentityFunction(local)) {
          unproven.push(
            `${collapse(n)} (\`${name}\` is defined in this file and returns its argument unchanged)`,
          );
          return false;
        }
        escapers.add(`${name}()`);
        return true;
      }
      // Number(x) is a number. String(x) is NOT safe - it converts, it does
      // not clean - and neither is JSON.stringify, whose output can carry a
      // literal `</script>` that closes the tag it sits inside.
      if (name === 'Number' || name === 'parseInt' || name === 'parseFloat' || name === 'BigInt') {
        return true;
      }

      const fn = findFunctionNamed(name, root);
      if (fn) return judgeCallWithArguments(fn, argList, n, depth + 1);

      unproven.push(collapse(n));
      return false;
    }

    if (callee && callee.type === 'member_expression') {
      const object = callee.childForFieldName('object');
      const property = callee.childForFieldName('property')?.text ?? '';
      const objectName = object?.type === 'identifier' ? (object.text ?? '') : '';

      // DOMPurify.sanitize(x) and friends.
      if (ESCAPER_METHODS.has(property) && ESCAPER_OBJECTS.has(objectName)) {
        escapers.add(`${objectName}.${property}()`);
        return true;
      }
      if (ESCAPER_NAMES.has(property)) {
        escapers.add(`.${property}()`);
        return true;
      }
      if (NUMERIC_METHODS.has(property)) return true;
      if (objectName === 'Math') return true;

      // `parts.join('')` - safe when the thing being joined is safe.
      if (property === 'join') return judge(object, depth + 1);

      // `rows.map(renderRow)` - the array's safety is the CALLBACK's safety,
      // never the receiver's. This is the case that makes the whole analysis
      // worth having: UI code is render helpers all the way down.
      if (property === 'map' || property === 'flatMap') {
        const callback = argList[0];
        if (!callback) {
          unproven.push(collapse(n));
          return false;
        }
        return judgeIteratorCallback(callback, depth);
      }

      if (PASSTHROUGH_METHODS.has(property)) return judge(object, depth + 1);

      // `"x".repeat(n)`, `s.padStart(...)` on a literal receiver stay safe.
      if (
        (property === 'repeat' || property === 'padStart' || property === 'padEnd') &&
        object &&
        object.type === 'string'
      ) {
        return true;
      }

      unproven.push(collapse(n));
      return false;
    }

    unproven.push(collapse(n));
    return false;
  };

  /**
   * Does this function return one of its own parameters, unchanged?
   *
   * `(x) => x` and `function f(x) { return x; }` both qualify. A single
   * transformation anywhere - a `.replace()`, a template, a call - and the
   * answer is no, because then we genuinely cannot tell what it does and the
   * name is the only evidence available.
   */
  const isIdentityFunction = (fn: Node): boolean => {
    const params = new Set(
      parameterNames(fn)
        .map((p) => p.name)
        .filter((name) => name.length > 0),
    );
    if (params.size === 0) return false;

    const body = fn.childForFieldName('body');
    if (!body) return false;

    // Concise arrow body: `(x) => x`
    if (body.type !== 'statement_block') {
      return body.type === 'identifier' && params.has(body.text ?? '');
    }

    // Block body: every return must hand back a parameter, and there must be
    // at least one - a function that returns nothing is not an identity.
    let returns = 0;
    let allBareParameters = true;
    const collect = (n: Node, isRoot: boolean): void => {
      if (!isRoot && FUNCTION_SCOPES.has(n.type)) return;
      if (n.type === 'return_statement') {
        const value = n.namedChildren.find((c) => c !== null && c.type !== 'comment') ?? null;
        if (value) {
          returns++;
          if (value.type !== 'identifier' || !params.has(value.text ?? '')) {
            allBareParameters = false;
          }
        }
      }
      for (const child of n.namedChildren) if (child) collect(child, false);
    };
    collect(body, true);
    return returns > 0 && allBareParameters;
  };

  /**
   * Judge the callback of `rows.map((row, i) => ...)`.
   *
   * The first parameter is an element, and nobody here knows what is in the
   * array, so it stays unbound and reads as unproven. The SECOND parameter is
   * the index, and that one is not a guess: `Array.prototype.map` is specified
   * to pass an integer, and no caller can make it anything else. Digits cannot
   * open a tag, so the index is provably safe.
   *
   * This earns its place because loop counters are spliced into rendered markup
   * constantly - `<span class="ln">${i + 1}</span>` is in this project's own
   * code viewer - and without it every such line reads as unproven forever, for
   * a value that is arithmetic by construction.
   *
   * Only `map`/`flatMap` get this: they are the iterators whose RESULT becomes
   * markup. `forEach` returns undefined and never reaches the page.
   */
  const judgeIteratorCallback = (callback: Node, depth: number): boolean => {
    if (!FUNCTION_SCOPES.has(callback.type)) return judge(callback, depth + 1);
    const names = parameterNames(callback);
    const frame = new Map<string, Binding>();
    // names[1] is the index. names[0] (the element) and names[2] (the whole
    // array) are deliberately left unbound - we know nothing about either.
    const indexName = names[1]?.name;
    if (indexName) frame.set(indexName, NUMERIC);
    frames.push(frame);
    const verdict = judgeFunctionResult(callback, depth + 1);
    frames.pop();
    return verdict;
  };

  /** Judge `fn(...args)` with each parameter bound to the argument passed. */
  const judgeCallWithArguments = (
    fn: Node,
    argList: readonly Node[],
    callSite: Node,
    depth: number,
  ): boolean => {
    if (frames.length >= MAX_FRAMES) {
      unproven.push(`${collapse(callSite)} (call chain longer than this analysis follows)`);
      return false;
    }
    const names = parameterNames(fn);
    const frame = new Map<string, Binding>();
    names.forEach((param, index) => {
      if (!param.name) return;
      // The caller's argument wins; a missing argument falls back to the
      // parameter's own default (`className = ''`), which is just as knowable.
      const arg = argList[index] ?? param.fallback;
      if (arg) frame.set(param.name, arg);
    });
    frames.push(frame);
    const verdict = judgeFunctionResult(fn, depth);
    frames.pop();
    return verdict;
  };

  /**
   * Parameter names, in order. Destructuring and rest parameters are skipped
   * deliberately: we cannot bind them positionally, so the name stays
   * unresolved and the value reads as unproven, which is the safe direction.
   */
  const parameterNames = (fn: Node): Array<{ name: string; fallback: Node | null }> => {
    const params = fn.childForFieldName('parameters') ?? fn.childForFieldName('parameter');
    if (!params) return [];
    if (params.type === 'identifier') return [{ name: params.text ?? '', fallback: null }];

    const names: Array<{ name: string; fallback: Node | null }> = [];
    for (const child of params.namedChildren) {
      if (!child) continue;
      if (child.type === 'identifier') {
        names.push({ name: child.text ?? '', fallback: null });
      } else if (child.type === 'assignment_pattern') {
        // `className = ''` - a name AND a known value when the caller omits it.
        const left = child.childForFieldName('left');
        names.push({
          name: left?.type === 'identifier' ? (left.text ?? '') : '',
          fallback: child.childForFieldName('right'),
        });
      } else if (child.type === 'required_parameter' || child.type === 'optional_parameter') {
        // TypeScript wraps the name in a parameter node, sometimes with a default.
        const pattern = child.childForFieldName('pattern');
        names.push({
          name: pattern?.type === 'identifier' ? (pattern.text ?? '') : '',
          fallback: child.childForFieldName('value'),
        });
      } else {
        // Destructuring or a rest parameter: we cannot bind it positionally,
        // so the name stays unresolved and its uses read as unproven. Holding
        // the position matters - dropping it would shift every later argument.
        names.push({ name: '', fallback: null });
      }
    }
    return names;
  };

  /* ---- What can this function return? ----------------------------------- */
  const judgeFunctionResult = (fn: Node, depth: number): boolean => {
    if (depth > MAX_DEPTH) {
      unproven.push(`${collapse(fn)} (nested deeper than this analysis follows)`);
      return false;
    }
    const body = fn.childForFieldName('body');
    if (!body) {
      unproven.push(`${collapse(fn)} (no body to read)`);
      return false;
    }

    // Concise arrow body: `x => \`<b>${escapeHtml(x)}</b>\``
    if (body.type !== 'statement_block') return judge(body, depth + 1);

    const returns: Node[] = [];
    const collect = (n: Node, isRoot: boolean): void => {
      if (!isRoot && FUNCTION_SCOPES.has(n.type)) return; // a nested helper is its own problem
      if (n.type === 'return_statement') {
        const value = n.namedChildren.find((c) => c !== null) ?? null;
        if (value) returns.push(value);
        else return; // `return;` yields undefined - harmless
      }
      for (const child of n.namedChildren) if (child) collect(child, false);
    };
    collect(body, true);

    // A function with no return statement yields undefined, which prints as
    // "undefined" - ugly, but not markup.
    if (returns.length === 0) return true;

    let ok = true;
    for (const value of returns) if (!judge(value, depth + 1)) ok = false;
    return ok;
  };

  /* ---- Name resolution --------------------------------------------------
   * Two hard rules, both learned the expensive way on this project:
   *
   *   1. Never descend into a nested function scope when searching. An earlier
   *      helper did, walked into sibling functions, and matched a same-named
   *      variable that had nothing to do with the one being asked about.
   *   2. A name we cannot find is UNPROVEN, never safe. Function parameters,
   *      imports and globals all land here, which is correct - we have no idea
   *      what a caller passes in.
   * -------------------------------------------------------------------- */
  const resolveBinding = (identifier: Node): Node[] => {
    const name = identifier.text ?? '';
    if (!name) return [];

    // Walk outward through enclosing scopes, nearest first.
    let scope: Node | null = identifier.parent;
    while (scope) {
      if (FUNCTION_SCOPES.has(scope.type) || scope.type === 'program') {
        const found = bindingsIn(scope, name);
        if (found.length > 0) return found;
      }
      scope = scope.parent;
    }
    return [];
  };

  const bindingsIn = (scope: Node, name: string): Node[] => {
    const values: Node[] = [];
    const visit = (n: Node): void => {
      // Rule 1: stop at the boundary of any scope that is not the one we were
      // asked about. Sibling functions are a different world.
      if (n !== scope && FUNCTION_SCOPES.has(n.type)) return;

      if (n.type === 'variable_declarator') {
        const target = n.childForFieldName('name');
        if (target && target.type === 'identifier' && target.text === name) {
          const value = n.childForFieldName('value');
          // `let x;` with no initialiser tells us nothing.
          if (value) values.push(value);
          else values.push(n); // deliberately unresolvable -> judged unproven
        }
      }
      if (n.type === 'assignment_expression') {
        const target = n.childForFieldName('left');
        if (target && target.type === 'identifier' && target.text === name) {
          const value = n.childForFieldName('right');
          if (value) values.push(value);
        }
      }
      for (const child of n.namedChildren) if (child) visit(child);
    };
    visit(scope);
    return values;
  };

  const findFunctionNamed = (name: string, from: Node): Node | null => {
    let found: Node | null = null;
    const visit = (n: Node): void => {
      if (found) return;
      if (n.type === 'function_declaration') {
        if (n.childForFieldName('name')?.text === name) {
          found = n;
          return;
        }
      }
      if (n.type === 'variable_declarator') {
        const target = n.childForFieldName('name');
        const value = n.childForFieldName('value');
        if (
          target?.text === name &&
          value &&
          (value.type === 'arrow_function' ||
            value.type === 'function_expression' ||
            value.type === 'function')
        ) {
          found = value;
          return;
        }
      }
      for (const child of n.namedChildren) if (child) visit(child);
    };
    visit(from);
    return found;
  };

  const proven = judge(node, 0);
  return {
    proven: proven && unproven.length === 0,
    unproven: [...new Set(unproven)],
    escapers: [...escapers],
  };
}
