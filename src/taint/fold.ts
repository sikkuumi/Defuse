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

  const constantOfName = (rawName: string, body: Node, depth: number): Folded => {
    const name = bareName(rawName);
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

    let found: Folded;
    let assignments = 0;
    // `walkDepth` is how deep we are in the SYNTAX TREE looking for the
    // assignment; `depth` is how many names deep the resolution itself is.
    const visit = (node: Node, walkDepth: number): void => {
      if (walkDepth > 40 || assignments > 1) return;
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
      if (parts && bareName(text(parts.target)) === name) {
        assignments++;
        found = foldExpression(parts.value, body, depth + 1);
      }
      for (const child of node.namedChildren) if (child) visit(child, walkDepth + 1);
    };
    visit(body, 0);
    resolving.delete(cycleKey);

    /*
     * Cached even when the answer was cut short by the depth budget. A budget
     * that ran out always answers undefined, which means "cannot tell", which
     * keeps the flow - so the worst a stale one can do is leave a false
     * positive that was already there. Caching a NARROWER answer would be the
     * dangerous direction, and undefined is never narrower.
     */
    const answer = assignments === 1 ? found : undefined;
    perScope.set(name, answer);
    return answer;
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

  const foldExpression = (node: Node | null, body: Node, depth: number): Folded => {
    if (!node || depth > 12) return undefined;

    const binary = binaryParts(node);

    if (binary) {
      const { left, right, operator } = binary;
      if (!FOLDABLE_OPERATORS.has(operator)) return undefined;
      const a = foldExpression(left, body, depth + 1);
      const b = foldExpression(right, body, depth + 1);
      if (a === undefined || b === undefined) return undefined;
      if (typeof a === 'number' && typeof b === 'number') {
        switch (operator) {
          case '+': return a + b;
          case '-': return a - b;
          case '*': return a * b;
          case '/': return b === 0 ? undefined : Math.trunc(a / b);
          case '%': return b === 0 ? undefined : a % b;
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
      if (unary.operator === '-' && typeof value === 'number') return -value;
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
        return constantOfName(text(node), body, depth);
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

  return { foldExpression, conditionTruth, ternaryParts, deadBranchOf };
}
