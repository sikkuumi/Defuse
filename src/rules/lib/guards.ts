/**
 * VALIDATION GUARDS - cleanliness that lives in the control flow.
 * ==============================================================
 *
 * Every sanitiser this engine knew about until now was value-in / value-out:
 *
 *     $safe = esc_html($dirty);        // takes a dirty value, returns a clean one
 *
 * A GUARD is a different shape. It transforms nothing and returns a boolean,
 * and the fact it establishes is true only inside the branch it guards:
 *
 *     if (is_numeric($octet[0]) && is_numeric($octet[1])) {
 *         $target = $octet[0] . '.' . $octet[1];
 *         shell_exec('ping ' . $target);        // <- cannot hold a metacharacter
 *     }
 *
 * That is DVWA's `exec/impossible.php`, the author's deliberate FIX, and this
 * scanner reported it for weeks. It is the seventh time this project has
 * punished a fix and the only one still showing in the instrument panel: the
 * DVWA scorer's "fix respected" reading sat at 75% because of this one file.
 *
 * WHY THE BAR FOR A GUARD IS SO HIGH.
 *
 * A sanitiser rule that fires too often costs precision. A GUARD rule that
 * fires too often costs SILENCE, and silence is the failure this scanner
 * cannot detect in itself - a tool that has gone quiet looks exactly like a
 * tool that has been fixed. This project has over-corrected before: the
 * lowercase-word rejection that dropped the corpus from 48 findings to 32, and
 * the mathjs.eval regression that was caught only because dvna's flow count
 * fell from 3 to 2.
 *
 * So a predicate earns a place in VALIDATORS on exactly one condition: being
 * TRUE must prove the value holds no dangerous character. Numeric and
 * alphanumeric tests qualify - a value `is_numeric()` accepted cannot contain
 * a semicolon, a quote or an angle bracket, which makes it safe for a shell, a
 * query and a page alike.
 *
 * These do NOT qualify, and they are the ones that look reassuring:
 *
 *     strlen($x) < 100        a hundred characters of `; rm -rf /` fits fine
 *     $x !== ''               proves only that something is there
 *     isset($x)               proves only that it exists
 *     preg_match($re, $x)     depends entirely on $re, which we do not evaluate
 *
 * See safe/validated-guard.php for the shapes this recognises and
 * vulnerable/weak-guard.php for the fence around it.
 */
import type { Node } from 'web-tree-sitter';
import type { LanguageId } from '../../parse/languages.js';

/**
 * Predicates whose truth proves a value holds no shell, SQL or HTML
 * metacharacter. Deliberately short. Adding a name here silences findings, so
 * a candidate has to survive the question: "can a value this accepts contain
 * a quote, a semicolon, an angle bracket or a dot-dot-slash?"
 */
const VALIDATORS: Partial<Record<LanguageId, readonly string[]>> = {
  php: [
    'is_numeric', 'is_int', 'is_integer', 'is_long', 'is_float', 'is_double',
    'ctype_digit', 'ctype_alnum', 'ctype_alpha', 'ctype_xdigit',
  ],
  python: [
    // Method form: `page.isdigit()`. The receiver is the guarded value.
    'isdigit', 'isnumeric', 'isdecimal', 'isalnum', 'isalpha',
  ],
  javascript: ['isInteger', 'isFinite', 'isSafeInteger'],
  typescript: ['isInteger', 'isFinite', 'isSafeInteger'],
};

/** Statement types whose true-branch a guard's truth reaches. */
const BRANCH_TYPES = new Set(['if_statement']);

/*
 * THE TRUE-BRANCH IS NOT CALLED THE SAME THING IN EVERY GRAMMAR, and reading
 * only one name is why the first version of this file silently did nothing.
 * PHP's if_statement carries `body`; JavaScript and Python call it
 * `consequence`. The first draft asked for `consequence` everywhere, found
 * nothing on the one language this rule was written for, and reported zero
 * guards while every test still passed except the four it was meant to fix.
 *
 * The `else` clause is a separate node in each grammar, so it is never
 * returned here - which is what keeps a guard's fact out of the branch where
 * it is false.
 */
const trueBranch = (statement: Node): Node | null =>
  statement.childForFieldName('consequence') ?? statement.childForFieldName('body');

const lastSegment = (text: string): string => {
  const trimmed = text.trim();
  const dot = trimmed.lastIndexOf('.');
  return dot === -1 ? trimmed : trimmed.slice(dot + 1);
};

/** Is `node` inside `container`, by source position? */
const contains = (container: Node, node: Node): boolean =>
  container.startIndex <= node.startIndex && container.endIndex >= node.endIndex;

/**
 * True when this call sits under a `!`. The whole point of a guard is WHICH
 * branch you are standing in, so a negated test proves the opposite of safe
 * and must never count. `if (!is_numeric($h)) { shell_exec($h); }` is a real
 * command injection, and a rule matching on call text alone gets it backwards.
 */
const NEGATION_NODES = new Set([
  'unary_expression',      // JavaScript, TypeScript, Java, Go
  'unary_op_expression',   // PHP
  'not_operator',          // Python
]);

const isNegated = (call: Node, condition: Node): boolean => {
  let current: Node | null = call.parent;
  while (current && contains(condition, current)) {
    if (NEGATION_NODES.has(current.type)) {
      if (current.type === 'not_operator') return true;
      const op = current.childForFieldName('operator')?.text ?? '';
      // PHP's unary_op_expression has no `operator` field in every release, so
      // fall back to the leading character of the node's own text.
      const lead = op || (current.text ?? '').trim().charAt(0);
      if (lead.trim().startsWith('!')) return true;
    }
    current = current.parent;
  }
  return false;
};

/**
 * The expression texts proven safe by validator calls inside one condition.
 * `is_numeric($octet[0])` contributes `$octet[0]`; a Python `page.isdigit()`
 * contributes `page`.
 */
const guardedByCondition = (condition: Node, language: LanguageId): Set<string> => {
  const names = VALIDATORS[language];
  const guarded = new Set<string>();
  if (!names) return guarded;

  const walk = (node: Node | null): void => {
    if (!node) return;
    if (node.type.includes('call')) {
      const callee = node.childForFieldName('function');
      const method = lastSegment(callee?.text ?? '');
      if (names.includes(method) && !isNegated(node, condition)) {
        const args = node.childForFieldName('arguments');
        const first = args?.namedChildren.find((c): c is Node => c !== null);
        if (first?.text) {
          guarded.add(first.text.trim());
        } else if (callee?.text?.includes('.')) {
          // Method form - the receiver is the value being tested.
          const receiver = callee.text.slice(0, callee.text.lastIndexOf('.'));
          guarded.add(receiver.trim());
        }
      }
    }
    for (const child of node.namedChildren) walk(child ?? null);
  };
  walk(condition);
  return guarded;
};

/**
 * Every expression proven safe by a guard that REACHES this node - meaning the
 * node sits in the consequence of the `if`, not in its condition and not in its
 * else. Walks all the way out, so nested guards accumulate.
 */
export function reachingGuards(node: Node, language: LanguageId): Set<string> {
  const guarded = new Set<string>();
  let current: Node | null = node.parent;
  let child: Node = node;

  while (current) {
    if (BRANCH_TYPES.has(current.type)) {
      const consequence = trueBranch(current);
      // Only the true-branch. Being in the condition itself, or in the else,
      // means the guard's fact does not hold here.
      if (consequence && contains(consequence, child)) {
        const condition = current.childForFieldName('condition');
        if (condition) {
          for (const text of guardedByCondition(condition, language)) guarded.add(text);
        }
      }
    }
    child = current;
    current = current.parent;
  }
  return guarded;
}

/**
 * Are ALL the spliced parts of this expression proven safe by a reaching guard?
 *
 * Every part must be covered. That is deliberate and it is the lesson from the
 * Jenkins escaper bug, where a sanitiser covering ONE value in an expression
 * was allowed to vouch for a DIFFERENT value beside it. Here, one unguarded
 * part means the whole expression still reports:
 *
 *     if (is_numeric($port)) { shell_exec('nc ' . $host . ' ' . $port); }
 *                                                    ^^^^^ never checked
 *
 * One level of local indirection is followed, because the shape that matters
 * rebuilds the value inside the branch:
 *
 *     $target = $octet[0] . '.' . $octet[1];    <- assigned inside the branch
 *     shell_exec('ping ' . $target);            <- and used here
 *
 * `$target` is not itself guarded; it is ASSEMBLED from guarded parts. So a
 * name assigned within the guarded region counts as guarded when every dynamic
 * piece of its value does. One level only - past that we would be writing a
 * second taint engine with none of the first one's receipts.
 */
export function partsAreGuarded(
  node: Node,
  dynamicParts: readonly string[],
  language: LanguageId,
): boolean {
  if (dynamicParts.length === 0) return false;
  if (!VALIDATORS[language]) return false;

  const guarded = reachingGuards(node, language);
  if (guarded.size === 0) return false;

  for (const raw of dynamicParts) {
    const part = raw.trim();
    if (guarded.has(part)) continue;
    if (!resolvesToGuardedParts(node, part, guarded, language)) return false;
  }
  return true;
}

/**
 * One level of indirection: was `name` assigned, inside a region a guard
 * reaches, from an expression whose every non-literal piece is guarded?
 */
function resolvesToGuardedParts(
  node: Node,
  name: string,
  guarded: ReadonlySet<string>,
  language: LanguageId,
): boolean {
  // Find the guarded branch bodies we are standing inside.
  const bodies: Node[] = [];
  let current: Node | null = node.parent;
  let child: Node = node;
  while (current) {
    if (BRANCH_TYPES.has(current.type)) {
      const consequence = trueBranch(current);
      const condition = current.childForFieldName('condition');
      if (
        consequence &&
        contains(consequence, child) &&
        condition &&
        guardedByCondition(condition, language).size > 0
      ) {
        bodies.push(consequence);
      }
    }
    child = current;
    current = current.parent;
  }
  if (bodies.length === 0) return false;

  let sawBinding = false;
  let allGuarded = true;

  const walk = (n: Node | null): void => {
    if (!n) return;
    if (n.type === 'assignment_expression' || n.type === 'assignment') {
      const left = n.childForFieldName('left');
      const right = n.childForFieldName('right');
      if ((left?.text ?? '').trim() === name && right) {
        sawBinding = true;
        // Every identifier-ish leaf of the value must be guarded. Literals and
        // punctuation are fine - a dot between two checked octets is harmless.
        for (const piece of leafExpressions(right)) {
          if (!guarded.has(piece)) allGuarded = false;
        }
      }
    }
    for (const c of n.namedChildren) walk((c as Node | null) ?? null);
  };
  for (const body of bodies) walk(body);

  return sawBinding && allGuarded;
}

/**
 * The non-literal leaves of an expression - the pieces that could carry a
 * value. String literals and operators are skipped; anything else that names
 * or indexes something is returned as text for the guard set to match.
 */
function leafExpressions(node: Node): string[] {
  const out: string[] = [];
  const walk = (n: Node | null): void => {
    if (!n) return;
    if (n.type.includes('string') || n.type.includes('literal') || n.type === 'integer' || n.type === 'float') {
      return;
    }
    if (
      n.type === 'variable_name' ||
      n.type === 'identifier' ||
      n.type === 'subscript_expression' ||
      n.type === 'member_access_expression'
    ) {
      out.push((n.text ?? '').trim());
      return; // do not descend - `$octet[0]` is the unit the guard names
    }
    for (const c of n.namedChildren) walk((c as Node | null) ?? null);
  };
  walk(node);
  return out;
}

/**
 * The node-only entry point, for callers that have an expression but no
 * pre-computed list of its parts - specifically the TAINT TRACER.
 *
 * WHY THIS EXISTS AT ALL, which is a lesson this project has now learned four
 * separate times. Wiring the guard into the three signature rules made
 * safe/validated-guard.php clean and left DVWA's `exec/impossible.php` still
 * reported - because those two findings were FLOW-VERIFIED. The tracer reaches
 * a sink by its own route and never consults a signature rule, so a proof of
 * safety taught to one is invisible to the other.
 *
 * The same split caused the Go `digest.Write` false positive, the command
 * injection aliasing miss, and the WordPress escaper fix that appeared not to
 * work. A retraction has to be taught in BOTH places or it is only half done -
 * and the half that gets missed is the one that claims proof, which is the
 * worse half.
 */
export function expressionIsFullyGuarded(node: Node, language: LanguageId): boolean {
  if (!VALIDATORS[language]) return false;
  const parts = leafExpressions(node);
  return partsAreGuarded(node, parts, language);
}
