/**
 * WHERE WAS THIS VARIABLE BUILT?
 * ==============================
 *
 * A signature rule reads the argument of a dangerous call and asks how its text
 * was assembled. That question has an obvious blind spot, and until this file
 * existed the command-injection rule sat squarely in it:
 *
 *     os.system("ls " + name)     <- the argument IS the build. Reported.
 *
 *     cmd = "ls " + name
 *     os.system(cmd)              <- the argument is a NAME. Silent.
 *
 * Same code, same risk, one line break apart - in every language. In C it was
 * worse than a blind spot: C has no `+` for strings, so a command is ALWAYS
 * formatted into a buffer first and run afterwards, and the signature pass saw
 * `system(buf)` every single time.
 *
 * WHAT THIS DOES, AND ON PURPOSE WHAT IT DOES NOT.
 *
 * Given a bare name at a call site, it looks back through the SAME function for
 * the writes that reach the call, in straight-line code:
 *
 *   a RESET replaces the value      cmd = ...   char cmd[] = ...   sprintf(cmd, ...)
 *   an EXTEND appends to it         cmd += ...  strcat(cmd, ...)   cmd.append(...)
 *
 * The value at the call is the LAST reset plus every extend after it. That is
 * what makes `cmd = "ls " + name; cmd = "ls -l"; system(cmd)` quiet: the build
 * that spliced `name` in was overwritten before the call ran.
 *
 * It gives up - returns null, which leaves the rule exactly as quiet as it was
 * before - whenever the answer would depend on which way the program went:
 *
 *   - any write to the name sits under an if, a loop, a switch or a try;
 *   - there is no reset in this function at all (a parameter, a global);
 *   - the write is a shape this file has not been taught.
 *
 * Giving up is the safe direction for a SIGNATURE rule in the narrow sense that
 * it cannot add a false finding. It is not free: every one of those is a guess
 * the rule could have made and did not. The coverage notes say so, rather than
 * letting "implemented" imply the conditional case is covered too.
 *
 * It never evaluates anything. It describes how the text was put together,
 * which is all a signature rule is entitled to know.
 */

import type { Node } from 'web-tree-sitter';
import type { LanguageId } from '../../parse/languages.js';
import { analyzeStringExpression, type StringExpression } from './strings.js';

export interface LocalBuild {
  readonly expression: StringExpression;
  /** 1-based line of the write the value at the call starts from. */
  readonly line: number;
}

/** Where a function's own writes stop. A nested function is a different scope. */
const FUNCTION_NODES = new Set([
  'function_declaration', 'function_expression', 'arrow_function', 'method_definition',
  'function_definition', 'lambda', 'lambda_expression',
  'method_declaration', 'constructor_declaration',
  'func_literal', 'anonymous_function_creation_expression',
]);

/*
 * Control flow, matched on the node-type NAME across all eight grammars, because
 * eight grammars spell it eight ways (if_statement, elif_clause,
 * expression_switch_statement, enhanced_for_statement, for_range_loop,
 * switch_block_statement_group, catch_clause, except_clause...). A type this
 * pattern wrongly calls conditional only makes the helper give up - it cannot
 * make it report something it would not otherwise have reported.
 */
const CONTROL_FLOW =
  /(^|_)(if|else|elif|switch|case|for|foreach|while|do|try|catch|except|finally|match|conditional|ternary)(_|$)/;

/* C's output-parameter writers. The destination is always argument 0. */
const C_FORMAT_WRITERS: Record<string, number> = {
  sprintf: 1, vsprintf: 1, snprintf: 2, vsnprintf: 2, // value: index of the format string
};
const C_COPY_RESETS = new Set(['strcpy', 'strncpy', 'strlcpy']);
const C_APPENDS = new Set(['strcat', 'strncat', 'strlcat']);

/* C++ std::string members that replace or extend the receiver. */
const CPP_MEMBER_RESETS = new Set(['assign']);
const CPP_MEMBER_APPENDS = new Set(['append']);

/*
 * `.c_str()` and `.data()` do nothing to the text; they hand a std::string over
 * in the shape a C API wants. std::system() takes a `const char*`, so EVERY C++
 * shell call ends in one of these, and to the signature pass a method call was
 * an opaque value - which is why even the one-line form was silent:
 *
 *     std::system(("ls " + name).c_str());
 */
const TRANSPARENT_METHODS = new Set(['c_str', 'data']);

type Write =
  | { kind: 'reset'; node: Node; piece: StringExpression }
  | { kind: 'extend'; node: Node; piece: StringExpression };

const lineOf = (node: Node): number => node.startPosition.row + 1;

const same = (a: Node | null, b: Node | null): boolean =>
  a !== null && b !== null && a.startIndex === b.startIndex && a.endIndex === b.endIndex;

/** The bare name a declarator or assignment target binds: `cmd`, `buf[256]`, `*p`, `$cmd`. */
function boundName(target: Node | null): string | null {
  let current: Node | null = target;
  for (let depth = 0; current && depth < 6; depth++) {
    if (current.type === 'identifier' || current.type === 'variable_name') {
      return (current.text ?? '').replace(/^\$/, '');
    }
    // array_declarator, pointer_declarator, reference_declarator, expression_list
    current = current.childForFieldName('declarator') ?? current.namedChildren[0] ?? null;
  }
  return null;
}

/** Strip parentheses and `.c_str()` / `.data()` - wrappers that do not change the text. */
function unwrap(node: Node): Node {
  let current = node;
  for (let depth = 0; depth < 6; depth++) {
    if (current.type === 'parenthesized_expression' && current.namedChildren.length === 1) {
      current = current.namedChildren[0] ?? current;
      continue;
    }
    if (current.type === 'call_expression') {
      const fn = current.childForFieldName('function');
      const args = current.childForFieldName('arguments');
      const field = fn?.childForFieldName('field')?.text ?? '';
      const receiver = fn?.childForFieldName('argument') ?? null;
      if (fn?.type === 'field_expression' && TRANSPARENT_METHODS.has(field) && receiver &&
          (args?.namedChildren.length ?? 0) === 0) {
        current = receiver;
        continue;
      }
    }
    break;
  }
  return current;
}

/*
 * THE FORMAT STRING IS A TYPE DECLARATION.
 *
 * `%d` can only ever emit digits and a sign, so it cannot carry a semicolon, a
 * pipe or a backtick however hostile the integer is. `%s` and `%c` splice text.
 * So `snprintf(buf, n, "kill -9 %d", pid)` is not a built command in any sense
 * that matters to a shell, and `snprintf(buf, n, "ls %s", name)` is.
 *
 * A format string that is not itself a literal is the worst case of all - the
 * caller controls the shape of the command - and is reported as dynamic.
 */
const SPECIFIER = /%[-+ #0]*(\*|\d+)?(?:\.(\*|\d+))?(?:hh|h|ll|l|j|z|t|L)?([diouxXeEfFgGaAcspn%])/g;

function formatPiece(call: Node, language: LanguageId, formatIndex: number, isVa: boolean): StringExpression {
  const args = (call.childForFieldName('arguments')?.namedChildren ?? []).filter((c): c is Node => c !== null);
  const format = args[formatIndex];
  if (!format) return { isDynamic: false, mechanism: 'literal', literalText: '', dynamicParts: [] };

  const fmt = analyzeStringExpression(format, language);
  if (fmt.isDynamic) {
    return { isDynamic: true, mechanism: 'format-call', literalText: '', dynamicParts: [format.text ?? ''] };
  }

  const dynamicParts: string[] = [];
  let argCursor = formatIndex + 1;
  for (const match of fmt.literalText.matchAll(SPECIFIER)) {
    const [, width, precision, conversion] = match;
    if (conversion === '%') continue;
    if (width === '*') argCursor++;
    if (precision === '*') argCursor++;
    const value = args[argCursor++];
    if (conversion !== 's' && conversion !== 'c') continue; // numeric: cannot splice text
    if (isVa) {
      dynamicParts.push('va_list');
      continue;
    }
    if (!value) continue;
    const piece = analyzeStringExpression(value, language);
    if (piece.isDynamic) dynamicParts.push((value.text ?? '').trim().slice(0, 60));
  }

  return {
    isDynamic: dynamicParts.length > 0,
    mechanism: dynamicParts.length > 0 ? 'format-call' : 'literal',
    literalText: fmt.literalText.replace(SPECIFIER, ''),
    dynamicParts,
  };
}

/** Classify one node as a write to `name`, or null if it is not one. */
function writeTo(node: Node, name: string, language: LanguageId): Write | null {
  const piece = (value: Node | null): StringExpression | null =>
    value ? analyzeStringExpression(unwrap(value), language) : null;

  // Declarations with an initialiser: JS/TS/Java variable_declarator, C/C++ init_declarator, Go var_spec.
  if (node.type === 'variable_declarator' || node.type === 'init_declarator' || node.type === 'var_spec') {
    const target = node.childForFieldName('name') ?? node.childForFieldName('declarator');
    const value = node.childForFieldName('value');
    if (boundName(target) !== name || !value) return null;
    const p = piece(value);
    return p ? { kind: 'reset', node, piece: p } : null;
  }

  // Assignment, plain or compound. The operator decides reset versus extend.
  if (
    node.type === 'assignment' || node.type === 'assignment_expression' ||
    node.type === 'augmented_assignment' || node.type === 'augmented_assignment_expression' ||
    node.type === 'assignment_statement' || node.type === 'short_var_declaration'
  ) {
    const target = node.childForFieldName('left');
    const value = node.childForFieldName('right');
    if (!target || !value) return null;
    if ((target.text ?? '').trim().replace(/^\$/, '') !== name) return null;
    const operator = (node.childForFieldName('operator')?.text ?? '=').trim();
    const p = piece(value);
    if (!p) return null;
    if (operator === '=' || operator === ':=') return { kind: 'reset', node, piece: p };
    if (operator === '+=' || operator === '.=') return { kind: 'extend', node, piece: p };
    return null; // some other compound operator: not a string build this knows
  }

  if (node.type !== 'call_expression') return null;
  const fn = node.childForFieldName('function');
  const args = (node.childForFieldName('arguments')?.namedChildren ?? []).filter((c): c is Node => c !== null);

  // C++ members on the string itself: cmd.append(x), cmd.assign(x).
  if (fn?.type === 'field_expression') {
    const receiver = fn.childForFieldName('argument');
    const member = fn.childForFieldName('field')?.text ?? '';
    if ((receiver?.text ?? '').trim() !== name) return null;
    const p = piece(args[0] ?? null);
    if (!p) return null;
    if (CPP_MEMBER_APPENDS.has(member)) return { kind: 'extend', node, piece: p };
    if (CPP_MEMBER_RESETS.has(member)) return { kind: 'reset', node, piece: p };
    return null;
  }

  // C's output-parameter idiom: the buffer is argument 0.
  if (language !== 'c' && language !== 'cpp') return null;
  const callee = (fn?.text ?? '').split('::').pop() ?? '';
  if ((args[0]?.text ?? '').trim() !== name) return null;
  if (callee in C_FORMAT_WRITERS) {
    return {
      kind: 'reset',
      node,
      piece: formatPiece(node, language, C_FORMAT_WRITERS[callee] ?? 1, callee.startsWith('v')),
    };
  }
  const p = piece(args[1] ?? null);
  if (!p) return null;
  if (C_COPY_RESETS.has(callee)) return { kind: 'reset', node, piece: p };
  if (C_APPENDS.has(callee)) return { kind: 'extend', node, piece: p };
  return null;
}

/** Is `node` inside a branch, loop or try between itself and the function body? */
function underControlFlow(node: Node, body: Node): boolean {
  let current: Node | null = node.parent;
  while (current && !same(current, body)) {
    if (CONTROL_FLOW.test(current.type)) return true;
    current = current.parent;
  }
  return false;
}

/**
 * Follow the argument of a dangerous call back to how its text was built.
 * Returns null when there is nothing to follow, or when following it would
 * need to know which way the program went.
 */
export function followLocalBuild(arg: Node, language: LanguageId): LocalBuild | null {
  const target = unwrap(arg);

  // Unwrapping alone can expose an inline build: std::system(("ls " + x).c_str()).
  if (!same(target, arg) && target.type !== 'identifier') {
    return { expression: analyzeStringExpression(target, language), line: lineOf(target) };
  }
  if (target.type !== 'identifier' && target.type !== 'variable_name') return null;
  const name = (target.text ?? '').replace(/^\$/, '');

  let body: Node | null = arg.parent;
  while (body && !FUNCTION_NODES.has(body.type)) body = body.parent;
  if (!body) return null;

  const writes: Write[] = [];
  let unsafe = false;
  const visit = (node: Node): void => {
    if (unsafe || node.startIndex >= arg.startIndex) return;
    if (!same(node, body) && FUNCTION_NODES.has(node.type)) return; // a nested function
    const write = writeTo(node, name, language);
    if (write) {
      if (underControlFlow(node, body!)) unsafe = true;
      else writes.push(write);
      return;
    }
    for (const child of node.namedChildren) if (child) visit(child);
  };
  visit(body);
  if (unsafe) return null;

  let start = -1;
  for (let i = writes.length - 1; i >= 0; i--) {
    if (writes[i]?.kind === 'reset') {
      start = i;
      break;
    }
  }
  if (start < 0) return null; // a parameter or a global: nothing here says how it was built

  const pieces = writes.slice(start).map((w) => w.piece);
  const first = writes[start]!;
  if (pieces.length === 1) return { expression: pieces[0]!, line: lineOf(first.node) };

  const dynamicParts = pieces.flatMap((p) => [...p.dynamicParts]);
  const literalText = pieces.map((p) => p.literalText).join('');
  const mechanism: StringExpression['mechanism'] = pieces.some((p) => p.mechanism === 'interpolation')
    ? 'interpolation'
    : pieces.some((p) => p.mechanism === 'format-call')
      ? 'format-call'
      : dynamicParts.length > 0
        ? 'concatenation'
        : 'literal';
  return {
    expression: { isDynamic: mechanism !== 'literal', mechanism, literalText, dynamicParts },
    line: lineOf(first.node),
  };
}
