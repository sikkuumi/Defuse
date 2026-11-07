/**
 * VALIDATION GUARDS - cleanliness that lives in the control flow.
 * ==============================================================
 *
 * Every sanitiser this engine knew about until now was value-in / value-out:
 *
 *     $safe = esc_html($dirty);        // takes a dirty value, returns a clean one
 *
 * A GUARD is a different shape. It transforms nothing and returns a boolean,
 * and the fact it establishes is true only where the program can stand after
 * that boolean came out a particular way:
 *
 *     if (is_numeric($octet[0]) && is_numeric($octet[1])) {
 *         $target = $octet[0] . '.' . $octet[1];
 *         shell_exec('ping ' . $target);        // <- cannot hold a metacharacter
 *     }
 *
 * That is DVWA's `exec/impossible.php`, the author's deliberate FIX, and this
 * scanner reported it for weeks. It is the seventh time this project has
 * punished a fix.
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
 * So a check earns a place here on exactly one condition: being on the
 * passing side of it must prove what the value can contain. Three strengths:
 *
 *     digits  only digits (is_numeric, ctype_digit, preg_match('/^\d+$/'))
 *     word    only letters, digits and underscore (ctype_alnum, /^\w+$/)
 *     fixed   only values the programmer wrote down ($x === 'png',
 *             in_array($x, ['jpg', 'png'], true))
 *
 * and each one clears a different set of sinks - see guardClears(). A word is
 * not enough for a SQL query unless it sits inside quotes (`WHERE id = id` is
 * true for every row), so `word` hands SQL to the same quote check that
 * escaping uses.
 *
 * These do NOT count, and they are the ones that look reassuring:
 *
 *     strlen($x) < 100        a hundred characters of `; rm -rf /` fits fine
 *     $x !== ''               proves only that something is there
 *     isset($x)               proves only that it exists
 *     preg_match('/\d+/', $x) not anchored: "1; rm -rf /" contains a digit
 *     preg_match('/^\d+$/m')  multi-line: "1\n; rm -rf /" has a line of digits
 *     preg_match(...) !== 0   preg_match returns FALSE on an error, and
 *                             false !== 0 - the error would pass as a match
 *
 * WHERE A FACT HOLDS (guardFactsAt):
 *
 *     if (CHECK) { here }                     the true branch
 *     if (!CHECK) { ... } else { here }       the else of a negated check
 *     if (!CHECK) { exit; }  here             after a branch that always leaves
 *     CHECK ? here : not-here                 the matching arm of a ternary
 *
 * and only while the checked value is not written again: a write to it
 * anywhere in that region - including the condition - drops the fact, because
 * `if (is_numeric($x)) { $x = $_GET['y']; run($x); }` is a real injection. The
 * walk also stops at a function boundary: a closure defined inside the branch
 * may run long after the value changed.
 *
 * NOT covered, on purpose or not yet - each one only means a finding stays:
 *   Java (no checks recognised at all yet); Python's `abort()` and other calls
 *   that never return; compiled regex objects (`re.compile(...).fullmatch`,
 *   `const re = /.../; re.test(x)`); `switch` on the value; a check whose
 *   result was stored in a variable first; a closure or by-reference
 *   parameter that rewrites the value from inside a called function.
 *
 * See safe/validated-guard.php and safe/allow-list-guards.* for the shapes this
 * recognises, and vulnerable/weak-guard.php and vulnerable/allow-list-fence.*
 * for the fence around them.
 */
import type { Node, Tree } from 'web-tree-sitter';
import type { LanguageId } from '../../parse/languages.js';
import type { SinkKind } from '../../taint/types.js';

export type GuardStrength = 'digits' | 'word' | 'fixed' | 'quoted-literal';

export interface GuardFact {
  readonly strength: GuardStrength;
  /** For `fixed`: the values the check lets through. */
  readonly values?: readonly string[];
  /** For `fixed`: the check compared a lower- or upper-cased copy. */
  readonly caseFolded?: boolean;
  /** A regex `$` in PHP or Python also lets one line break through after the value. */
  readonly newlineTail?: boolean;
  /** The check itself, for the path a reader sees. */
  readonly check: Node;
}

type Facts = Map<string, GuardFact>;

interface Outcome {
  readonly whenTrue: Facts;
  readonly whenFalse: Facts;
}

const GUARD_LANGUAGES: ReadonlySet<LanguageId> = new Set<LanguageId>(['php', 'python', 'javascript', 'typescript']);

/** Does this language have any checks this module recognises? */
export const guardsApply = (language: LanguageId): boolean => GUARD_LANGUAGES.has(language);

/**
 * Predicates whose truth proves what the value can contain. Deliberately
 * short. Adding a name here silences findings, so a candidate has to survive
 * the question: "can a value this accepts contain a quote, a semicolon, an
 * angle bracket or a dot-dot-slash?"
 *
 * is_numeric accepts "1e5", "-1" and " 1" - no metacharacter in any of them.
 * ctype_xdigit accepts "dead" and "beef", which are words, not digits.
 */
const VALIDATORS: Partial<Record<LanguageId, Readonly<Record<string, GuardStrength>>>> = {
  php: {
    is_numeric: 'digits', is_int: 'digits', is_integer: 'digits', is_long: 'digits',
    is_float: 'digits', is_double: 'digits', ctype_digit: 'digits',
    ctype_alnum: 'word', ctype_alpha: 'word', ctype_xdigit: 'word',
  },
  python: {
    // Method form: `page.isdigit()`. The receiver is the checked value.
    isdigit: 'digits', isnumeric: 'digits', isdecimal: 'digits',
    isalnum: 'word', isalpha: 'word',
  },
  javascript: { isInteger: 'digits', isFinite: 'digits', isSafeInteger: 'digits' },
  typescript: { isInteger: 'digits', isFinite: 'digits', isSafeInteger: 'digits' },
};

/** Calls that hand back the value with its letters' case changed - and nothing else. */
const CASE_FOLDS = new Set(['strtolower', 'strtoupper', 'mb_strtolower', 'mb_strtoupper', 'toLowerCase', 'toUpperCase', 'lower', 'upper']);

const SAFE_KINDS: Record<GuardStrength, { readonly kinds: readonly SinkKind[]; readonly insideQuotesOnly: readonly SinkKind[] }> = {
  // No quote, semicolon, angle bracket, dot-dot-slash or `--`. Not a URL host,
  // though: "2130706433" is 127.0.0.1 to most URL parsers.
  digits: { kinds: ['sql', 'command', 'xss', 'deserialization', 'code', 'format'], insideQuotesOnly: [] },
  // A bare word is a column name in SQL (`WHERE id = id`) and a name in code,
  // so SQL counts only inside quotes and code not at all.
  word: { kinds: ['sql', 'command', 'xss', 'format'], insideQuotesOnly: ['sql'] },
  // The attacker only chooses which of the programmer's own values arrives.
  fixed: {
    kinds: ['sql', 'command', 'xss', 'deserialization', 'code', 'ssrf', 'format', 'overflow'],
    insideQuotesOnly: [],
  },
  // One Python string literal with no quote of its kind inside: eval/exec can
  // only build a str from it. Says nothing for SQL, a shell or a page.
  'quoted-literal': { kinds: ['code'], insideQuotesOnly: [] },
};

/** Which sinks a fact makes safe, and which of those only when the value lands inside quotes. */
export const guardClears = (fact: GuardFact): { readonly kinds: readonly SinkKind[]; readonly insideQuotesOnly: readonly SinkKind[] } => {
  const base = SAFE_KINDS[fact.strength];
  // `/^(localhost|internal)$/` also passes "localhost\n": fine in a query or a
  // page, not something to vouch for inside a URL.
  if (fact.newlineTail) return { kinds: base.kinds.filter((k) => k !== 'ssrf' && k !== 'overflow'), insideQuotesOnly: base.insideQuotesOnly };
  return base;
};

/** One sentence for the path: what the check proved. */
export function describeFact(fact: GuardFact): string {
  const line = fact.check.startPosition.row + 1;
  const snippet = (fact.check.text ?? '').replace(/\s+/g, ' ').trim();
  const shown = snippet.length > 70 ? `${snippet.slice(0, 67)}...` : snippet;
  const lets =
    fact.strength === 'quoted-literal'
      ? 'only one quoted string literal can pass, so evaluating it only builds a string'
      : fact.strength === 'digits'
      ? 'only digits can pass'
      : fact.strength === 'word'
        ? 'only letters, digits and underscores can pass'
        : `only ${fact.values && fact.values.length > 0 ? fact.values.slice(0, 5).map((v) => `'${v}'`).join(', ') : 'fixed values'}` +
          `${fact.values && fact.values.length > 5 ? ' (and others)' : ''} can pass` +
          `${fact.caseFolded ? ', in any letter case' : ''}`;
  const tail = fact.newlineTail ? ' (and one line break after it, which `$` allows)' : '';
  return `checked by \`${shown}\` on line ${line}: ${lets}${tail}`;
}

/* ------------------------------------------------------------------------ */
/* Text                                                                      */
/* ------------------------------------------------------------------------ */

/**
 * The same expression written two ways must compare equal. DVWA writes
 * `$_REQUEST[ 'ip' ]` with spaces and reads it back the same way, but a check
 * written `$_GET["id"]` and a read written `$_GET['id']` are one value too.
 */
export function normalizeExpression(raw: string): string {
  let out = '';
  let quote: string | null = null;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i]!;
    if (quote) {
      out += c === '"' ? "'" : c;
      if (c === '\\') {
        out += raw[i + 1] ?? '';
        i++;
      } else if (c === quote) {
        quote = null;
      }
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      out += "'";
      continue;
    }
    if (/\s/.test(c)) continue;
    out += c;
  }
  return out;
}

const firstNamed = (node: Node | null | undefined): Node | null =>
  node?.namedChildren.find((c): c is Node => c !== null) ?? null;

const namedKids = (node: Node | null | undefined): Node[] =>
  node ? node.namedChildren.filter((c): c is Node => c !== null) : [];

const contains = (container: Node, node: Node): boolean =>
  container.startIndex <= node.startIndex && container.endIndex >= node.endIndex;

const lastSegment = (text: string): string => {
  const trimmed = text.trim();
  const cut = Math.max(trimmed.lastIndexOf('.'), trimmed.lastIndexOf('->'), trimmed.lastIndexOf('::'));
  if (cut === -1) return trimmed;
  return trimmed.slice(cut + (trimmed.startsWith('->', cut) || trimmed.startsWith('::', cut) ? 2 : 1));
};

/** The arguments of a call, unwrapped from PHP's `argument` nodes. */
function callArgs(call: Node): Node[] {
  const list = call.childForFieldName('arguments') ?? namedKids(call).find((c) => c.type === 'argument_list' || c.type === 'arguments') ?? null;
  return namedKids(list)
    .filter((a) => a.type !== 'comment')
    .map((a) => (a.type === 'argument' ? firstNamed(a) ?? a : a));
}

const CALL_TYPES = new Set(['function_call_expression', 'member_call_expression', 'scoped_call_expression', 'call_expression', 'call']);

/** `strtolower($x)` -> `$x`; anything else -> null. */
function caseFoldedArgument(node: Node): Node | null {
  if (!CALL_TYPES.has(node.type)) return null;
  const callee = node.childForFieldName('function') ?? node.childForFieldName('name');
  const name = lastSegment(callee?.text ?? '');
  if (!CASE_FOLDS.has(name) && !CASE_FOLDS.has(name.toLowerCase())) return null;
  const args = callArgs(node);
  if (args.length === 1) return args[0] ?? null;
  // Method form: `ext.toLowerCase()`, `ext.lower()`.
  if (args.length === 0 && callee && (callee.type === 'member_expression' || callee.type === 'attribute')) {
    return callee.childForFieldName('object');
  }
  return null;
}

/* ------------------------------------------------------------------------ */
/* Literals                                                                  */
/* ------------------------------------------------------------------------ */

interface Literal {
  readonly kind: 'string' | 'number' | 'bool' | 'null';
  readonly value: string;
}

/**
 * The value of a literal, or null when it is not one we can read exactly.
 * Interpolation, escapes we do not decode and heredocs all answer null - and
 * null only ever means a check is NOT counted.
 */
function literalOf(node: Node | null | undefined, language: LanguageId): Literal | null {
  if (!node) return null;
  const raw = node.text ?? '';
  if (node.type === 'parenthesized_expression') return literalOf(firstNamed(node), language);
  if (node.type === 'integer' || node.type === 'number' || node.type === 'float') return { kind: 'number', value: raw };
  if (node.type === 'boolean' || node.type === 'true' || node.type === 'false') return { kind: 'bool', value: raw.toLowerCase() };
  if (node.type === 'null' || node.type === 'none') return { kind: 'null', value: '' };

  if (language === 'php') {
    if (node.type === 'string' && raw.startsWith("'") && raw.endsWith("'")) {
      return { kind: 'string', value: raw.slice(1, -1).replace(/\\([\\'])/g, '$1') };
    }
    if (node.type === 'encapsed_string' && raw.startsWith('"') && raw.endsWith('"')) {
      if (namedKids(node).some((c) => c.type !== 'string_content' && c.type !== 'string_value' && c.type !== 'escape_sequence')) return null;
      const body = raw.slice(1, -1);
      if (/\$[A-Za-z_{]/.test(body)) return null;
      if (/\\(?:[nrtvef0-7]|x[0-9A-Fa-f]|u\{)/.test(body)) return null;
      return { kind: 'string', value: body.replace(/\\([\\$"])/g, '$1') };
    }
    return null;
  }

  if (language === 'javascript' || language === 'typescript') {
    if (node.type === 'string' || node.type === 'template_string') {
      if (namedKids(node).some((c) => c.type !== 'string_fragment')) return null;
      return { kind: 'string', value: raw.slice(1, -1) };
    }
    return null;
  }

  if (language === 'python' && node.type === 'string') {
    const kids = namedKids(node);
    if (kids.some((c) => c.type === 'interpolation')) return null;
    const start = kids.find((c) => c.type === 'string_start')?.text ?? '';
    const prefix = start.replace(/['"]+$/, '').toLowerCase();
    if (prefix.includes('f')) return null;
    const content = kids.filter((c) => c.type === 'string_content').map((c) => c.text ?? '').join('');
    if (prefix.includes('r')) return { kind: 'string', value: content };
    // Escapes Python decodes are refused; ones it leaves alone (`\d`) are kept.
    if (/\\[\\'"abfnrtv0-7xNuU\n]/.test(content.replace(/\\\\/g, ''))) return null;
    return { kind: 'string', value: content.replace(/\\\\/g, '\\') };
  }
  return null;
}

/** PHP's idea of a numeric string - the ones `==` compares as numbers. */
const PHP_NUMERIC_STRING = /^\s*[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?\s*$/;

/* ------------------------------------------------------------------------ */
/* Regular expressions                                                       */
/* ------------------------------------------------------------------------ */

const precedingBackslashes = (s: string, at: number): number => {
  let n = 0;
  for (let i = at - 1; i >= 0 && s[i] === '\\'; i--) n++;
  return n;
};

const sameRangeGroup = (lo: string, hi: string): boolean =>
  (/[0-9]/.test(lo) && /[0-9]/.test(hi)) || (/[a-z]/.test(lo) && /[a-z]/.test(hi)) || (/[A-Z]/.test(lo) && /[A-Z]/.test(hi));

/**
 * What a whole-value regular expression lets through: 'digits', 'word',
 * 'fixed' (a list of literal words, `/^(asc|desc)$/`), or null when anything
 * else could pass - and null is the answer for everything this does not
 * understand.
 *
 * The body may only be digits, letters, underscores, `\d`, `\w`, classes of
 * those, groups, alternation INSIDE a group, and quantifiers. Top-level `|`
 * is refused because it splits the anchors: `/^1|2$/` is "starts with 1" OR
 * "ends with 2", and "1; rm -rf /" starts with 1.
 *
 * `$` lets one trailing newline through in PHP and Python (not in
 * JavaScript, and not with PHP's D flag). A lone newline at the very end
 * cannot open a quote or a tag, and is accepted - but it is recorded, so a
 * fixed list is not vouched for inside a URL (see guardClears).
 */
export function regexAllowList(
  source: string,
  options: {
    readonly flags?: string;
    readonly implicitStart?: boolean;
    readonly implicitEnd?: boolean;
    readonly language: LanguageId;
  },
): { readonly strength: GuardStrength; readonly values?: readonly string[]; readonly caseFolded?: boolean; readonly newlineTail?: boolean } | null {
  const flags = options.flags ?? '';
  // Multi-line makes ^ and $ match at every line; extended mode changes what
  // whitespace and # mean. Either way the anchors no longer pin the value.
  if (/[mx]/.test(flags)) return null;
  const php = options.language === 'php';
  let body = source;
  if (body.startsWith('^')) body = body.slice(1);
  else if (php && body.startsWith('\\A')) body = body.slice(2);
  else if (!options.implicitStart && !(php && flags.includes('A'))) return null;

  const endsWith = (token: string): boolean =>
    body.endsWith(token) && precedingBackslashes(body, body.length - token.length) % 2 === 0;
  const javascript = options.language === 'javascript' || options.language === 'typescript';
  let newlineTail = false;
  if (endsWith('$')) {
    body = body.slice(0, -1);
    newlineTail = !javascript && !(php && flags.includes('D'));
  } else if (!javascript && endsWith('\\Z')) {
    // PCRE's and Python's \Z both allow the same one line break as `$`.
    body = body.slice(0, -2);
    newlineTail = true;
  } else if (!javascript && endsWith('\\z')) {
    body = body.slice(0, -2);
  } else if (!options.implicitEnd) return null;
  const tail = newlineTail ? { newlineTail: true } : {};

  // A list of literal words: the value is one of them.
  const list = /^\((?:\?:)?([A-Za-z0-9_]+(?:\|[A-Za-z0-9_]+)*)\)$/.exec(body) ?? /^([A-Za-z0-9_]+)$/.exec(body);
  if (list) {
    const values = list[1]!.split('|');
    return { strength: 'fixed', values, ...(flags.includes('i') ? { caseFolded: true } : {}), ...tail };
  }

  let letters = false;
  let depth = 0;
  let i = 0;
  while (i < body.length) {
    const c = body[i]!;
    if (c === '\\') {
      const e = body[i + 1];
      if (e === 'd') { i += 2; continue; }
      if (e === 'w') { letters = true; i += 2; continue; }
      return null;
    }
    if (c === '[') {
      let j = i + 1;
      if (body[j] === '^' || body[j] === ']') return null;
      let any = false;
      while (j < body.length && body[j] !== ']') {
        const k = body[j]!;
        if (k === '[' && php && body[j + 1] === ':') {
          const posix = /^\[:(digit|alnum|alpha|upper|lower|word|xdigit):\]/.exec(body.slice(j));
          if (!posix) return null;
          if (posix[1] !== 'digit') letters = true;
          j += posix[0].length;
          any = true;
          continue;
        }
        if (k === '\\') {
          const e = body[j + 1];
          if (e === 'd') { j += 2; any = true; continue; }
          if (e === 'w') { letters = true; j += 2; any = true; continue; }
          return null;
        }
        if (!/[A-Za-z0-9_]/.test(k)) return null;
        if (body[j + 1] === '-' && body[j + 2] !== undefined && body[j + 2] !== ']') {
          const hi = body[j + 2]!;
          if (!sameRangeGroup(k, hi) || k > hi) return null;
          if (!/[0-9]/.test(k)) letters = true;
          j += 3;
          any = true;
          continue;
        }
        if (!/[0-9]/.test(k)) letters = true;
        j++;
        any = true;
      }
      if (body[j] !== ']' || !any) return null;
      i = j + 1;
      continue;
    }
    if (c === '(') {
      if (body[i + 1] === '?') {
        if (body[i + 2] !== ':') return null; // lookarounds, inline flags, named groups
        i += 3;
      } else {
        i++;
      }
      depth++;
      continue;
    }
    if (c === ')') {
      if (depth === 0) return null;
      depth--;
      i++;
      continue;
    }
    if (c === '|') {
      if (depth === 0) return null;
      i++;
      continue;
    }
    if (c === '+' || c === '*' || c === '?') { i++; continue; }
    if (c === '{') {
      const q = /^\{\d+(,\d*)?\}/.exec(body.slice(i));
      if (!q) return null;
      i += q[0].length;
      continue;
    }
    if (/[0-9]/.test(c)) { i++; continue; }
    if (/[A-Za-z_]/.test(c)) { letters = true; i++; continue; }
    return null;
  }
  if (depth !== 0) return null;
  return { strength: letters ? 'word' : 'digits', ...tail };
}

/** `/^\d+$/i` written as a PHP string: delimiters, then flags. */
function phpPattern(literal: string): { source: string; flags: string } | null {
  const open = literal[0];
  if (!open || /[A-Za-z0-9\\\s]/.test(open)) return null;
  const close = ({ '(': ')', '[': ']', '{': '}', '<': '>' } as Record<string, string>)[open] ?? open;
  const end = literal.lastIndexOf(close);
  if (end <= 0) return null;
  const flags = literal.slice(end + 1);
  if (!/^[A-Za-z]*$/.test(flags)) return null;
  return { source: literal.slice(1, end), flags };
}

/* ------------------------------------------------------------------------ */
/* Conditions                                                                */
/* ------------------------------------------------------------------------ */

const EMPTY: Outcome = { whenTrue: new Map(), whenFalse: new Map() };
const RANK: Record<GuardStrength, number> = { 'quoted-literal': 0, word: 1, digits: 2, fixed: 3 };

const classOfValues = (values: readonly string[]): GuardStrength | null =>
  values.every((v) => /^[0-9]*$/.test(v)) ? 'digits' : values.every((v) => /^[A-Za-z0-9_]*$/.test(v)) ? 'word' : null;

/** Both facts hold - keep the stronger. */
function stronger(a: GuardFact, b: GuardFact): GuardFact {
  return RANK[b.strength] > RANK[a.strength] ? b : a;
}

/** One of the two holds - keep only what both promise. */
function weaker(a: GuardFact, b: GuardFact, at: Node): GuardFact | null {
  if (a.strength === 'fixed' && b.strength === 'fixed') {
    return {
      strength: 'fixed',
      values: [...new Set([...(a.values ?? []), ...(b.values ?? [])])],
      ...(a.caseFolded || b.caseFolded ? { caseFolded: true } : {}),
      ...(a.newlineTail || b.newlineTail ? { newlineTail: true } : {}),
      check: at,
    };
  }
  // Not a character class: "word OR quoted literal" promises nothing either does.
  if (a.strength === 'quoted-literal' || b.strength === 'quoted-literal') {
    return a.strength === b.strength ? { strength: a.strength, check: at } : null;
  }
  const asCharset = (f: GuardFact): GuardStrength | null => (f.strength === 'fixed' ? classOfValues(f.values ?? ['\u0000']) : f.strength);
  const x = asCharset(a);
  const y = asCharset(b);
  if (!x || !y) return null;
  return { strength: RANK[x] <= RANK[y] ? x : y, ...(a.newlineTail || b.newlineTail ? { newlineTail: true } : {}), check: at };
}

function joinStrong(a: Facts, b: Facts): Facts {
  const out: Facts = new Map(a);
  for (const [k, f] of b) out.set(k, out.has(k) ? stronger(out.get(k)!, f) : f);
  return out;
}

function meetWeak(a: Facts, b: Facts, at: Node): Facts {
  const out: Facts = new Map();
  for (const [k, f] of a) {
    const g = b.get(k);
    if (!g) continue;
    const w = weaker(f, g, at);
    if (w) out.set(k, w);
  }
  return out;
}

const facts1 = (subject: Node | null, fact: Omit<GuardFact, 'check'>, check: Node): Facts => {
  const out: Facts = new Map();
  if (subject?.text) out.set(normalizeExpression(subject.text), { ...fact, check } as GuardFact);
  return out;
};

const operatorOf = (node: Node): string => {
  const field = node.childForFieldName('operator')?.text;
  if (field) return field.trim();
  // Python's comparison operators are anonymous children: `in`, `not in`, `is not`.
  return node.children
    .filter((c): c is Node => c !== null && !c.isNamed)
    .map((c) => c.text)
    .join(' ')
    .trim();
};

/** A check written as a call: validators, regex matches, list membership. */
function callFacts(call: Node, language: LanguageId): Facts {
  const callee = call.childForFieldName('function') ?? call.childForFieldName('name');
  const calleeText = callee?.text ?? '';
  // PHP lets a builtin be called fully qualified: `\preg_match(...)`.
  const name = lastSegment(calleeText).replace(/^\\+/, '');
  const args = callArgs(call);
  const empty: Facts = new Map();

  // Validators: is_numeric($x), ctype_digit($x), Number.isInteger(x), page.isdigit()
  const validators = VALIDATORS[language] ?? {};
  const lookup = language === 'php' ? name.toLowerCase() : name;
  if (Object.prototype.hasOwnProperty.call(validators, lookup)) {
    const strength = validators[lookup]!;
    if (args.length >= 1) return facts1(args[0] ?? null, { strength }, call);
    if (callee && (callee.type === 'attribute' || callee.type === 'member_expression')) {
      return facts1(callee.childForFieldName('object'), { strength }, call);
    }
    return empty;
  }

  if (language === 'php') {
    const lower = name.toLowerCase();
    if (lower === 'preg_match' && args.length >= 2 && args.length <= 4) {
      const pattern = literalOf(args[0], language);
      const parsed = pattern?.kind === 'string' ? phpPattern(pattern.value) : null;
      const allowed = parsed ? regexAllowList(parsed.source, { flags: parsed.flags, language }) : null;
      return allowed ? facts1(args[1] ?? null, allowed, call) : empty;
    }
    if (lower === 'in_array' && (args.length === 2 || args.length === 3)) {
      const strict = args.length === 3 && (args[2]?.text ?? '').toLowerCase() === 'true';
      const values = arrayLiteralValues(args[1] ?? null, language, strict);
      if (!values) return empty;
      return membershipFacts(args[0] ?? null, values, call);
    }
    return empty;
  }

  if (language === 'javascript' || language === 'typescript') {
    if (!callee || callee.type !== 'member_expression') return empty;
    const object = callee.childForFieldName('object');
    const property = callee.childForFieldName('property')?.text ?? '';
    // /^\d+$/.test(x)
    if (property === 'test' && object?.type === 'regex' && args.length === 1) {
      const source = object.childForFieldName('pattern')?.text ?? '';
      const flags = object.childForFieldName('flags')?.text ?? '';
      const allowed = regexAllowList(source, { flags, language });
      return allowed ? facts1(args[0] ?? null, allowed, call) : empty;
    }
    // x.match(/^\d+$/)
    if (property === 'match' && args.length === 1 && args[0]?.type === 'regex') {
      const source = args[0].childForFieldName('pattern')?.text ?? '';
      const flags = args[0].childForFieldName('flags')?.text ?? '';
      const allowed = regexAllowList(source, { flags, language });
      return allowed ? facts1(object, allowed, call) : empty;
    }
    // ['jpg', 'png'].includes(x) - includes() is strict equality.
    if (property === 'includes' && object?.type === 'array' && args.length === 1) {
      const values = arrayLiteralValues(object, language, true);
      return values ? membershipFacts(args[0] ?? null, values, call) : empty;
    }
    return empty;
  }

  if (language === 'python') {
    // re.fullmatch(r'\d+', x) / re.match(r'\d+$', x)
    if ((calleeText === 're.fullmatch' || calleeText === 're.match') && (args.length === 2 || args.length === 3)) {
      if (args.length === 3 && !/^re\.(I|IGNORECASE|A|ASCII|U|UNICODE)$/.test((args[2]?.text ?? '').trim())) return empty;
      const pattern = literalOf(args[0], language);
      if (pattern?.kind !== 'string') return empty;
      const allowed = regexAllowList(pattern.value, {
        language,
        implicitStart: true,
        implicitEnd: calleeText === 're.fullmatch',
        // Python spells case-insensitive as an argument, not a suffix.
        ...(args.length === 3 && /^re\.(I|IGNORECASE)$/.test((args[2]?.text ?? '').trim()) ? { flags: 'i' } : {}),
      });
      return allowed ? facts1(args[1] ?? null, allowed, call) : empty;
    }
    return empty;
  }
  return empty;
}

/** The values of an array literal of strings - or null if any element is not one. */
function arrayLiteralValues(node: Node | null, language: LanguageId, strict: boolean): string[] | null {
  if (!node) return null;
  const ok = new Set(['array_creation_expression', 'array', 'list', 'tuple', 'set']);
  if (!ok.has(node.type)) return null;
  const values: string[] = [];
  for (const element of namedKids(node)) {
    if (element.type === 'comment') continue;
    // PHP wraps each element; a `key => value` pair is refused.
    const inner = element.type === 'array_element_initializer' ? (namedKids(element).length === 1 ? firstNamed(element) : null) : element;
    const lit = literalOf(inner, language);
    if (!lit) return null;
    if (lit.kind === 'string') {
      // Loose comparison turns "1e0" == "1" true; only exact strings are safe there.
      if (!strict && language === 'php' && PHP_NUMERIC_STRING.test(lit.value)) return null;
      values.push(lit.value);
      continue;
    }
    // A number compared loosely is PHP 7's `"abc" == 0`. Strictly, a request
    // string never equals one, so the branch is dead - harmless to count.
    if (strict && lit.kind === 'number') {
      values.push(lit.value);
      continue;
    }
    return null;
  }
  return values.length > 0 ? values : null;
}

function membershipFacts(subject: Node | null, values: readonly string[], check: Node): Facts {
  if (!subject) return new Map();
  const folded = caseFoldedArgument(subject);
  if (folded) return facts1(folded, { strength: 'fixed', values, caseFolded: true }, check);
  return facts1(subject, { strength: 'fixed', values }, check);
}

/**
 * Comparisons. Two families:
 *
 *   CHECK == 1, CHECK > 0, CHECK != 0 ...   the result of a check, compared
 *   $x === 'png', 'png' == $x, $x != 'a'   the value against a literal
 *
 * The first family is where preg_match bites: it returns 1, 0, or FALSE on an
 * error (bad UTF-8 under /u, a backtrack limit). `!== 0` and `=== false`
 * treat that error as a pass, so they are not counted at all.
 */
function comparisonOutcome(node: Node, language: LanguageId, depth: number): Outcome {
  const operator = operatorOf(node);
  const left = node.childForFieldName('left') ?? namedKids(node)[0] ?? null;
  const right = node.childForFieldName('right') ?? namedKids(node)[1] ?? null;
  if (!left || !right || namedKids(node).length > 2) return EMPTY;

  const leftLit = literalOf(left, language);
  const rightLit = literalOf(right, language);

  // Python: `m is not None` / `m is None`
  if (language === 'python' && (operator === 'is not' || operator === 'is') && rightLit?.kind === 'null') {
    const inner = outcomeOf(left, language, depth + 1);
    return operator === 'is not' ? inner : { whenTrue: inner.whenFalse, whenFalse: inner.whenTrue };
  }

  // The result of a check, compared to a constant.
  const lit = rightLit ?? leftLit;
  const other = rightLit ? left : right;
  if (lit && (lit.kind === 'number' || lit.kind === 'bool')) {
    const v = lit.value;
    const isOne = v === '1' || v === 'true';
    const isZero = v === '0' || v === 'false';
    const flipped = !rightLit; // literal on the left: `0 < x` reads the other way
    const op = flipped ? ({ '>': '<', '<': '>', '>=': '<=', '<=': '>=' } as Record<string, string>)[operator] ?? operator : operator;
    const positive =
      ((op === '==' || op === '===') && isOne) ||
      ((op === '!=' || op === '<>') && isZero) ||
      (op === '>' && v === '0') ||
      (op === '>=' && v === '1');
    const negative =
      (op === '==' && isZero) ||
      ((op === '!=' || op === '<>' || op === '!==') && isOne) ||
      (op === '<' && v === '1');
    if (positive || negative) {
      const inner = outcomeOf(other, language, depth + 1);
      if (inner.whenTrue.size > 0 || inner.whenFalse.size > 0) {
        return positive ? inner : { whenTrue: inner.whenFalse, whenFalse: inner.whenTrue };
      }
    }
  }

  // Membership: `x in ('a', 'b')`, `x not in [...]`
  if (language === 'python' && (operator === 'in' || operator === 'not in')) {
    const values = arrayLiteralValues(right, language, true);
    if (!values) return EMPTY;
    const facts = membershipFacts(left, values, node);
    return operator === 'in' ? { whenTrue: facts, whenFalse: new Map() } : { whenTrue: new Map(), whenFalse: facts };
  }

  // The value against a literal.
  const equal = operator === '===' || operator === '==';
  const notEqual = operator === '!==' || operator === '!=' || operator === '<>';
  if (!equal && !notEqual) return EMPTY;
  if (!lit || lit.kind === 'null' || lit.kind === 'bool') return EMPTY;
  const strict = operator === '===' || operator === '!==' || language === 'python';
  if (!strict) {
    // Loose equality is exact only against a non-numeric string.
    if (lit.kind !== 'string') return EMPTY;
    if (language === 'php' && PHP_NUMERIC_STRING.test(lit.value)) return EMPTY;
    if ((language === 'javascript' || language === 'typescript') && (lit.value === '' || !Number.isNaN(Number(lit.value)))) return EMPTY;
  }
  if (literalOf(other, language)) return EMPTY;
  const facts = membershipFacts(other, [lit.value], node);
  return equal ? { whenTrue: facts, whenFalse: new Map() } : { whenTrue: new Map(), whenFalse: facts };
}

/** `'` or `"` written as a one-character Python literal, in any of its spellings. */
const QUOTE_LITERALS: Readonly<Record<string, string>> = { [`"'"`]: "'", [`'\\''`]: "'", [`'"'`]: '"', [`"\\""`]: '"' };

/**
 * `s.startswith(Q) and s.endswith(Q) and Q not in s[1:-1]`, or its negation
 * `not s.startswith(Q) or not s.endswith(Q) or Q in s[1:-1]` (true side leaves).
 *
 * Where it holds, s is exactly one Q-quoted literal with no Q inside, so
 * eval/exec can only produce a str (or a SyntaxError). BenchmarkPython fences
 * eval and exec with it; the engine proved 7 of those safe cases "vulnerable".
 *
 * Recognised WHOLE or not at all - each part alone proves nothing - and on one
 * subject with one quote character.
 */
function quotedLiteralFence(node: Node): Outcome | null {
  const operator = operatorOf(node).toLowerCase();
  if (operator !== 'and' && operator !== 'or') return null;
  const operands: Node[] = [];
  const flatten = (n: Node | null): void => {
    if (!n) return;
    if (n.type === 'parenthesized_expression') return flatten(firstNamed(n));
    if (n.type === 'boolean_operator' && operatorOf(n).toLowerCase() === operator) {
      flatten(n.childForFieldName('left'));
      flatten(n.childForFieldName('right'));
    } else operands.push(n);
  };
  flatten(node);
  // `and`: every operand true on the true side. `or`: every operand false on the false side.
  const need = operator === 'and';
  const seen = new Map<string, Set<string>>(); // `${subject}|${quote}` -> parts
  for (let operand of operands) {
    let truth = need;
    while (operand.type === 'not_operator' || operand.type === 'parenthesized_expression') {
      if (operand.type === 'not_operator') truth = !truth;
      const inner = operand.childForFieldName('argument') ?? firstNamed(operand);
      if (!inner) break;
      operand = inner;
    }
    let part: string | null = null;
    let subject = '';
    let quote: string | undefined;
    if (operand.type === 'call' && truth) {
      const callee = operand.childForFieldName('function');
      const method = callee?.type === 'attribute' ? callee.childForFieldName('attribute')?.text : undefined;
      const args = callArgs(operand);
      quote = args.length === 1 ? QUOTE_LITERALS[args[0]?.text ?? ''] : undefined;
      if ((method === 'startswith' || method === 'endswith') && quote) {
        part = method;
        subject = normalizeExpression(callee?.childForFieldName('object')?.text ?? '');
      }
    } else if (operand.type === 'comparison_operator') {
      const op = operatorOf(operand);
      const [left, right] = namedKids(operand);
      quote = QUOTE_LITERALS[left?.text ?? ''];
      // `Q in s[1:-1]` must come out false; `Q not in s[1:-1]` true.
      if (quote && right?.type === 'subscript' && ((op === 'in' && !truth) || (op === 'not in' && truth))) {
        if (normalizeExpression(right.text.slice(right.childForFieldName('value')?.text.length ?? 0)) === '[1:-1]') {
          part = 'inner';
          subject = normalizeExpression(right.childForFieldName('value')?.text ?? '');
        }
      }
    }
    if (!part || !subject || !quote) continue;
    const key = `${subject}|${quote}`;
    if (!seen.has(key)) seen.set(key, new Set());
    seen.get(key)!.add(part);
  }
  for (const [key, parts] of seen) {
    if (parts.size !== 3) continue;
    const facts: Facts = new Map([[key.slice(0, key.lastIndexOf('|')), { strength: 'quoted-literal', check: node }]]);
    return need ? { whenTrue: facts, whenFalse: new Map() } : { whenTrue: new Map(), whenFalse: facts };
  }
  return null;
}

const outcomeCache = new WeakMap<Tree, Map<number, Outcome>>();

/** What is known about values when this condition came out true, and when false. */
function outcomeOf(node: Node | null, language: LanguageId, depth = 0): Outcome {
  if (!node || depth > 40) return EMPTY;
  let perTree = outcomeCache.get(node.tree);
  if (!perTree) {
    perTree = new Map();
    outcomeCache.set(node.tree, perTree);
  }
  const cached = perTree.get(node.id);
  if (cached) return cached;
  const result = computeOutcome(node, language, depth);
  perTree.set(node.id, result);
  return result;
}

function computeOutcome(node: Node, language: LanguageId, depth: number): Outcome {
  switch (node.type) {
    case 'parenthesized_expression':
      return outcomeOf(firstNamed(node), language, depth + 1);
    case 'unary_op_expression': // PHP
    case 'unary_expression': {  // JS
      const operator = node.childForFieldName('operator')?.text ?? (node.text ?? '').trim().charAt(0);
      if (operator.trim() !== '!') return EMPTY;
      const inner = outcomeOf(node.childForFieldName('argument') ?? firstNamed(node), language, depth + 1);
      return { whenTrue: inner.whenFalse, whenFalse: inner.whenTrue };
    }
    case 'not_operator': { // Python
      const inner = outcomeOf(node.childForFieldName('argument') ?? firstNamed(node), language, depth + 1);
      return { whenTrue: inner.whenFalse, whenFalse: inner.whenTrue };
    }
    case 'binary_expression':
    case 'boolean_operator':
    case 'comparison_operator': {
      const fence = language === 'python' ? quotedLiteralFence(node) : null;
      if (fence) return fence;
      const operator = operatorOf(node).toLowerCase();
      if (operator === '&&' || operator === 'and') {
        const a = outcomeOf(node.childForFieldName('left'), language, depth + 1);
        const b = outcomeOf(node.childForFieldName('right'), language, depth + 1);
        return { whenTrue: joinStrong(a.whenTrue, b.whenTrue), whenFalse: meetWeak(a.whenFalse, b.whenFalse, node) };
      }
      if (operator === '||' || operator === 'or') {
        const a = outcomeOf(node.childForFieldName('left'), language, depth + 1);
        const b = outcomeOf(node.childForFieldName('right'), language, depth + 1);
        return { whenTrue: meetWeak(a.whenTrue, b.whenTrue, node), whenFalse: joinStrong(a.whenFalse, b.whenFalse) };
      }
      return comparisonOutcome(node, language, depth);
    }
    default:
      if (CALL_TYPES.has(node.type)) return { whenTrue: callFacts(node, language), whenFalse: new Map() };
      return EMPTY;
  }
}

/* ------------------------------------------------------------------------ */
/* Where a fact holds, and whether the value is written while it does         */
/* ------------------------------------------------------------------------ */

const FUNCTION_TYPES = new Set([
  'function_definition', 'method_declaration', 'anonymous_function_creation_expression', 'anonymous_function',
  'arrow_function', 'function_declaration', 'function_expression', 'method_definition',
  'generator_function_declaration', 'generator_function', 'lambda',
]);
const IF_TYPES = new Set(['if_statement']);
const ALTERNATIVE_TYPES = new Set(['else_if_clause', 'else_clause', 'elif_clause']);
const TERNARY_TYPES = new Set(['conditional_expression', 'ternary_expression']);
const BLOCK_TYPES = new Set(['compound_statement', 'statement_block', 'block', 'program', 'module']);
const EXIT_TYPES = new Set(['exit_statement', 'return_statement', 'throw_statement', 'raise_statement', 'break_statement', 'continue_statement']);

const WRITE_TYPES = new Set([
  'assignment_expression', 'augmented_assignment_expression', 'reference_assignment_expression',
  'variable_declarator', 'assignment', 'augmented_assignment', 'named_expression', 'update_expression',
]);

interface Writes {
  readonly targets: readonly string[];
  /** extract(), parse_str() with one argument, `$$name = ...`: any variable may change. */
  readonly anything: boolean;
}

const writesCache = new WeakMap<Tree, Map<number, Writes>>();

function writesIn(region: Node): Writes {
  let perTree = writesCache.get(region.tree);
  if (!perTree) {
    perTree = new Map();
    writesCache.set(region.tree, perTree);
  }
  const cached = perTree.get(region.id);
  if (cached) return cached;
  const targets: string[] = [];
  let anything = false;
  const visit = (n: Node): void => {
    if (WRITE_TYPES.has(n.type)) {
      const target = n.childForFieldName('left') ?? n.childForFieldName('name') ?? n.childForFieldName('argument') ?? firstNamed(n);
      if (target?.text) {
        if (target.type === 'dynamic_variable_name' || target.text.startsWith('$$')) anything = true;
        targets.push(normalizeExpression(target.text));
      }
    }
    if (n.type === 'foreach_statement') {
      // Everything bound by `as $k => $v`, which sits between the iterable and the body.
      const kids = namedKids(n);
      for (const k of kids.slice(1)) {
        if (k.type === 'compound_statement' || k.type === 'colon_block') continue;
        targets.push(normalizeExpression(k.text ?? ''));
      }
    }
    if (n.type === 'as_pattern') {
      // Python `with open(p) as f`, `except E as e`: the name after `as`.
      const alias = namedKids(n).pop();
      if (alias?.text) targets.push(normalizeExpression(alias.text));
    }
    if (n.type === 'for_in_statement' || n.type === 'for_statement') {
      const left = n.childForFieldName('left');
      if (left?.text) targets.push(normalizeExpression(left.text));
    }
    if (n.type === 'global_declaration' || n.type === 'static_variable_declaration' || n.type === 'global_statement' || n.type === 'nonlocal_statement') {
      targets.push(normalizeExpression(n.text ?? ''));
    }
    if (n.type === 'function_call_expression') {
      const name = (n.childForFieldName('function')?.text ?? '').toLowerCase();
      const args = callArgs(n);
      if (name === 'extract' || (name === 'parse_str' && args.length < 2)) anything = true;
      // Out-parameters PHP writes through a reference.
      const outIndex: Record<string, number> = { parse_str: 1, preg_match: 2, preg_match_all: 2, settype: 0, sscanf: 2 };
      const at = outIndex[name];
      if (at !== undefined) for (const a of args.slice(at)) targets.push(normalizeExpression(a.text ?? ''));
    }
    for (const c of namedKids(n)) visit(c);
  };
  visit(region);
  const result: Writes = { targets, anything };
  perTree.set(region.id, result);
  return result;
}

const isIdentChar = (c: string | undefined): boolean => c !== undefined && /[\w$]/.test(c);

/** Does a write to `target` change the value written `text`? */
function touches(target: string, text: string): boolean {
  if (target === text) return true;
  for (const sep of ['[', '->', '.']) {
    if (text.startsWith(target + sep) || target.startsWith(text + sep)) return true;
  }
  // `[$a, $b] = ...`, `list($a) = ...`, `global $a;`, `obj.x = ...` - a whole
  // token inside the target counts. Over-cautious by design.
  let from = 0;
  while (true) {
    const at = target.indexOf(text, from);
    if (at === -1) return false;
    if (!isIdentChar(target[at - 1]) || text.startsWith('$')) {
      if (!isIdentChar(target[at + text.length])) return true;
    }
    from = at + 1;
  }
}

function writtenIn(regions: readonly Node[], text: string): boolean {
  for (const region of regions) {
    const w = writesIn(region);
    if (w.anything) return true;
    if (w.targets.some((t) => touches(t, text))) return true;
  }
  return false;
}

/** The then-branch: PHP calls it `body`, JavaScript and Python `consequence`. */
const thenBranch = (statement: Node): Node | null =>
  statement.childForFieldName('consequence') ?? statement.childForFieldName('body');

/** Does this branch always leave - its last statement an exit, return, throw, break or continue? */
function alwaysLeaves(branch: Node | null): boolean {
  if (!branch) return false;
  const last = BLOCK_TYPES.has(branch.type) || branch.type === 'colon_block' ? namedKids(branch).filter((k) => k.type !== 'comment').pop() ?? null : branch;
  if (!last) return false;
  if (EXIT_TYPES.has(last.type)) return true;
  // PHP: `die(...)`, `exit(...)` and `throw` parse inside an expression statement.
  const inner = last.type === 'expression_statement' ? firstNamed(last) : null;
  if (inner?.type === 'throw_expression') return true;
  if (inner?.type === 'exit_statement') return true;
  if (inner?.type === 'function_call_expression') {
    const name = (inner.childForFieldName('function')?.text ?? '').toLowerCase();
    if (name === 'die' || name === 'exit') return true;
  }
  return false;
}

function add(into: Facts, facts: Facts, regions: readonly Node[]): void {
  for (const [text, fact] of facts) {
    if (writtenIn(regions, text)) continue;
    const had = into.get(text);
    into.set(text, had ? stronger(had, fact) : fact);
  }
}

/**
 * Every value a check proves something about, at this node. Keys are
 * normalised expression texts (see normalizeExpression).
 */
export function guardFactsAt(node: Node, language: LanguageId): ReadonlyMap<string, GuardFact> {
  const facts: Facts = new Map();
  if (!GUARD_LANGUAGES.has(language)) return facts;
  let child: Node = node;
  let current: Node | null = node.parent;
  while (current) {
    if (FUNCTION_TYPES.has(current.type)) break;

    if (IF_TYPES.has(current.type)) {
      const condition = current.childForFieldName('condition');
      const then = thenBranch(current);
      if (condition) {
        const outcome = outcomeOf(condition, language);
        if (then && then.id === child.id) {
          add(facts, outcome.whenTrue, [current]);
        } else {
          const alternatives = namedKids(current).filter((k) => ALTERNATIVE_TYPES.has(k.type));
          if (alternatives.some((a) => a.id === child.id)) {
            add(facts, outcome.whenFalse, [current]);
            for (const alt of alternatives) {
              const altCondition = alt.childForFieldName('condition');
              if (alt.id === child.id) {
                const altBody = thenBranch(alt);
                if (altCondition && altBody && contains(altBody, node)) {
                  add(facts, outcomeOf(altCondition, language).whenTrue, [current]);
                }
                break;
              }
              if (altCondition) add(facts, outcomeOf(altCondition, language).whenFalse, [current]);
            }
          }
        }
      }
    }

    if (TERNARY_TYPES.has(current.type)) {
      const condition = current.childForFieldName('condition');
      const yes = current.childForFieldName('consequence') ?? current.childForFieldName('body');
      const no = current.childForFieldName('alternative');
      if (condition) {
        const outcome = outcomeOf(condition, language);
        if (yes && yes.id === child.id) add(facts, outcome.whenTrue, [current]);
        else if (no && no.id === child.id) add(facts, outcome.whenFalse, [current]);
      }
    }

    // An earlier `if (!CHECK) { exit; }` in the same block.
    if (BLOCK_TYPES.has(current.type)) {
      const siblings = namedKids(current);
      const index = siblings.findIndex((s) => s.id === child.id);
      for (let i = 0; i < index; i++) {
        const s = siblings[i]!;
        if (!IF_TYPES.has(s.type)) continue;
        const condition = s.childForFieldName('condition');
        if (!condition || !alwaysLeaves(thenBranch(s))) continue;
        add(facts, outcomeOf(condition, language).whenFalse, siblings.slice(i));
      }
    }

    child = current;
    current = current.parent;
  }
  return facts;
}

/* ------------------------------------------------------------------------ */
/* The signature rules' entry point                                          */
/* ------------------------------------------------------------------------ */

/** A fact a signature rule may use for this sink: word needs quotes for SQL, and a text rule does not know them. */
const usableFor = (fact: GuardFact, kind: SinkKind): boolean => {
  const clears = SAFE_KINDS[fact.strength];
  return clears.kinds.includes(kind) && !clears.insideQuotesOnly.includes(kind);
};

/**
 * Are ALL the spliced parts of this expression proven safe by a check?
 *
 * Every part must be covered. That is deliberate and it is the lesson from the
 * Jenkins escaper bug, where a sanitiser covering ONE value in an expression
 * was allowed to vouch for a DIFFERENT value beside it. Here, one unchecked
 * part means the whole expression still reports:
 *
 *     if (is_numeric($port)) { shell_exec('nc ' . $host . ' ' . $port); }
 *                                                    ^^^^^ never checked
 *
 * One level of local indirection is followed, because the shape that matters
 * rebuilds the value inside the branch:
 *
 *     $target = $octet[0] . '.' . $octet[1];    <- every piece checked here
 *     shell_exec('ping ' . $target);            <- and used here
 *
 * A name counts when its value here certainly comes from one assignment: the
 * last plain `name = ...` before this point, sitting directly in a block that
 * also holds this point, with no other write to the name from that assignment
 * to the end of the statement this point is in (so a loop cannot bring a
 * different value round). And every piece of that one value was checked where
 * it was assigned. DVWA writes `$target` twice - once from the request, once
 * rebuilt from checked octets - so "assigned once in the function" was too
 * strict, and "assigned somewhere in the branch" (the first version) never
 * asked whether a later write replaced it.
 */
export function partsAreGuarded(
  node: Node,
  dynamicParts: readonly string[],
  language: LanguageId,
  kind: SinkKind,
): boolean {
  if (dynamicParts.length === 0) return false;
  if (!GUARD_LANGUAGES.has(language)) return false;
  const facts = guardFactsAt(node, language);
  for (const raw of dynamicParts) {
    const part = normalizeExpression(raw);
    const fact = facts.get(part);
    if (fact && usableFor(fact, kind)) continue;
    if (!definedFromCheckedParts(node, part, language, kind)) return false;
  }
  return true;
}

function definedFromCheckedParts(node: Node, name: string, language: LanguageId, kind: SinkKind): boolean {
  if (!/^\$?[A-Za-z_][\w]*$/.test(name)) return false;
  let scope: Node | null = node.parent;
  while (scope && !FUNCTION_TYPES.has(scope.type) && scope.parent) scope = scope.parent;
  if (!scope) return false;

  // Every write to the name in the function, in source order.
  const writes: Node[] = [];
  const visit = (n: Node): void => {
    if (WRITE_TYPES.has(n.type)) {
      const target = n.childForFieldName('left') ?? n.childForFieldName('name') ?? n.childForFieldName('argument');
      if (target?.text && touches(normalizeExpression(target.text), name)) writes.push(n);
    }
    for (const c of namedKids(n)) visit(c);
  };
  visit(scope);
  const before = writes.filter((w) => w.endIndex <= node.startIndex);
  const definition = before[before.length - 1];
  if (!definition) return false;
  const target = definition.childForFieldName('left') ?? definition.childForFieldName('name');
  const value = definition.childForFieldName('right') ?? definition.childForFieldName('value');
  const plain = definition.type === 'assignment_expression' || definition.type === 'assignment' || definition.type === 'variable_declarator';
  if (!plain || !value || !target || normalizeExpression(target.text ?? '') !== name) return false;

  // The assignment's statement must sit directly in a block that holds this point.
  let statement: Node = definition;
  while (statement.parent && !BLOCK_TYPES.has(statement.parent.type)) statement = statement.parent;
  const block = statement.parent;
  if (!block || !contains(block, node) || statement.endIndex > node.startIndex) return false;
  let pointStatement: Node = node;
  while (pointStatement.parent && pointStatement.parent.id !== block.id) pointStatement = pointStatement.parent;
  if (pointStatement.parent?.id !== block.id) return false;

  // Nothing else writes it - by assignment, foreach, global, out-parameter or
  // extract() - between the assignment and the end of this point's statement.
  if (writes.some((w) => w.id !== definition.id && w.startIndex > definition.startIndex && w.startIndex < pointStatement.endIndex)) return false;
  const between = namedKids(block).filter((s) => s.startIndex >= statement.endIndex && s.startIndex <= pointStatement.startIndex);
  for (const s of between) {
    const w = writesIn(s);
    if (w.anything || w.targets.some((t) => touches(t, name))) return false;
  }

  const pieces = leafExpressions(value);
  if (pieces.length === 0) return false;
  const factsThere = guardFactsAt(value, language);
  return pieces.every((piece) => {
    const fact = factsThere.get(normalizeExpression(piece));
    return fact !== undefined && usableFor(fact, kind);
  });
}

/**
 * The pieces of an expression that could carry a value. String literal TEXT
 * is skipped, but what is interpolated INTO a string is not - the first
 * version of this skipped every node with "string" in its type, so
 * `"... '$b'"` had no pieces at all and a check on a different value vouched
 * for it. A call is one opaque piece: what it returns is not something a
 * check on its arguments describes.
 */
function leafExpressions(node: Node): string[] {
  const out: string[] = [];
  const walk = (n: Node | null): void => {
    if (!n) return;
    if (n.type === 'integer' || n.type === 'float' || n.type === 'number' || n.type === 'boolean') return;
    if (n.type === 'string_content' || n.type === 'string_value' || n.type === 'string_fragment' || n.type === 'escape_sequence') return;
    if (CALL_TYPES.has(n.type)) {
      out.push(n.text ?? '');
      return;
    }
    if (
      n.type === 'variable_name' ||
      n.type === 'identifier' ||
      n.type === 'subscript_expression' ||
      n.type === 'member_access_expression' ||
      n.type === 'member_expression' ||
      n.type === 'subscript' ||
      n.type === 'attribute'
    ) {
      out.push((n.text ?? '').trim());
      return; // do not descend - `$octet[0]` is the unit a check names
    }
    for (const c of namedKids(n)) walk(c);
  };
  walk(node);
  return out;
}
