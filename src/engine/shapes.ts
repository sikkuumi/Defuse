/**
 * THE SHAPE LAYER
 * ===============
 *
 * This is the translator between "five different languages" and "one set of
 * rules". It uses tree-sitter's QUERY LANGUAGE, which is worth understanding
 * because it is the only unfamiliar syntax in this project.
 *
 * A tree-sitter query is a pattern written as nested parentheses that describes
 * a shape of tree, with @names marking the parts you want back:
 *
 *     (call_expression
 *       function: (member_expression
 *         object: (_) @receiver
 *         property: (property_identifier) @method)
 *       arguments: (arguments) @args) @call
 *
 * Read it as: "find a call_expression; its `function` child must be a
 * member_expression (that's the `a.b` shape); give me whatever is on the left
 * of the dot as @receiver, the name after the dot as @method, the argument list
 * as @args, and the whole call as @call."
 *
 * `(_)` means "any node". Field names before the colon (`function:`,
 * `object:`) are the ROLE labels you saw in the AST dump. Matching on roles
 * instead of child positions is what makes these patterns stable.
 *
 * Every language below gets its own query because the grammars use different
 * node names for the same idea - JavaScript says `call_expression`, Python says
 * `call`, Java says `method_invocation`. The OUTPUT is identical for all five,
 * and that output is what rules see.
 *
 * ADDING A LANGUAGE LATER means adding two query strings to this file. No rule
 * changes.
 */

import { Query, type Node, type QueryMatch } from 'web-tree-sitter';
import type { Assignment, CallSite, Shape } from '../rules/contract.js';
import type { LanguageId } from '../parse/languages.js';
import { getLanguage, type ParsedFile } from '../parse/parser.js';

/* ---------------------------------------------------------------------------
 * CALL SITES: "something is being called with arguments"
 * ------------------------------------------------------------------------ */

/** Shared by C and C++, because C++ is a superset of these two shapes. */
const C_CALL_QUERY = `
  (call_expression
    function: (identifier) @method
    arguments: (argument_list) @args) @call
  (call_expression
    function: (field_expression argument: (_) @receiver field: (field_identifier) @method)
    arguments: (argument_list) @args) @call
`;

const CALL_QUERIES: Record<LanguageId, string> = {
  javascript: `
    (call_expression
      function: (member_expression object: (_) @receiver property: (property_identifier) @method)
      arguments: (arguments) @args) @call
    (call_expression
      function: (identifier) @method
      arguments: (arguments) @args) @call
    (new_expression
      constructor: (_) @method
      arguments: (arguments) @args) @call
  `,
  // TypeScript's grammar is JavaScript's grammar plus types, so the call shapes
  // are byte-for-byte identical. Kept as a separate entry rather than an alias
  // so that a future TS-only pattern has an obvious home.
  typescript: `
    (call_expression
      function: (member_expression object: (_) @receiver property: (property_identifier) @method)
      arguments: (arguments) @args) @call
    (call_expression
      function: (identifier) @method
      arguments: (arguments) @args) @call
    (new_expression
      constructor: (_) @method
      arguments: (arguments) @args) @call
  `,
  python: `
    (call
      function: (attribute object: (_) @receiver attribute: (identifier) @method)
      arguments: (argument_list) @args) @call
    (call
      function: (identifier) @method
      arguments: (argument_list) @args) @call
  `,
  java: `
    (method_invocation
      object: (_) @receiver
      name: (identifier) @method
      arguments: (argument_list) @args) @call
    (method_invocation
      name: (identifier) @method
      arguments: (argument_list) @args) @call
    (object_creation_expression
      type: (_) @method
      arguments: (argument_list) @args) @call
  `,
  go: `
    (call_expression
      function: (selector_expression operand: (_) @receiver field: (field_identifier) @method)
      arguments: (argument_list) @args) @call
    (call_expression
      function: (identifier) @method
      arguments: (argument_list) @args) @call
  `,
  // PHP has three call shapes: a bare function, a method on an object, and a
  // static method on a class. `echo` is deliberately NOT here - it is a
  // statement, not a call, and the XSS rule handles it separately.
  php: `
    (function_call_expression
      function: (name) @method
      arguments: (arguments) @args) @call
    (member_call_expression
      object: (_) @receiver
      name: (name) @method
      arguments: (arguments) @args) @call
    (scoped_call_expression
      scope: (_) @receiver
      name: (name) @method
      arguments: (arguments) @args) @call
    (object_creation_expression
      (name) @method
      (arguments) @args) @call
  `,

  /*
   * C. Two shapes only, because C has two: a bare call, and a call through a
   * struct member. Every node type and field name below was read off the real
   * grammar with a query probe rather than assumed - the same discipline the
   * PHP entry learned the hard way, when `if_statement` turned out to use
   * `body` where every other grammar uses `consequence`.
   */
  c: C_CALL_QUERY,

  /*
   * C++ is C plus namespaces. `std::system(cmd)` parses as a
   * qualified_identifier, NOT an identifier, so a query that only matched the
   * C shapes would miss it - and reaching system() through <cstdlib> is the
   * stylistically CORRECT way to do it in C++, which means the well-written
   * code would be the code that slipped through.
   */
  cpp: `
    ${C_CALL_QUERY}
    (call_expression
      function: (qualified_identifier name: (identifier) @method)
      arguments: (argument_list) @args) @call
  `,
};

/* ---------------------------------------------------------------------------
 * ASSIGNMENTS: "a name is being bound to a value"
 *
 * Deliberately broad: it covers `x = v`, `const x = v`, object/dict entries
 * `{ key: v }`, and keyword arguments `f(key=v)`. Hardcoded credentials hide in
 * all of those, and so does `element.innerHTML = ...`.
 * ------------------------------------------------------------------------ */

const JS_ASSIGN_QUERY = `
  (assignment_expression left: (_) @target right: (_) @value) @assign
  (variable_declarator name: (_) @target value: (_) @value) @assign
  (pair key: (_) @target value: (_) @value) @assign
  (augmented_assignment_expression left: (_) @target right: (_) @value) @assign
`;

const C_ASSIGN_QUERY = `
  (assignment_expression left: (_) @target right: (_) @value) @assign
  (init_declarator declarator: (_) @target value: (_) @value) @assign
`;

const ASSIGNMENT_QUERIES: Record<LanguageId, string> = {
  php: `
    (assignment_expression left: (_) @target right: (_) @value) @assign
    (property_element (variable_name) @target (_) @value) @assign
    (echo_statement "echo" @target (_) @value) @assign
  `,
  javascript: JS_ASSIGN_QUERY,
  typescript: `
    ${JS_ASSIGN_QUERY}
    (public_field_definition name: (_) @target value: (_) @value) @assign
  `,
  python: `
    (assignment left: (_) @target right: (_) @value) @assign
    (pair key: (_) @target value: (_) @value) @assign
    (keyword_argument name: (identifier) @target value: (_) @value) @assign
  `,
  java: `
    (variable_declarator name: (identifier) @target value: (_) @value) @assign
    (assignment_expression left: (_) @target right: (_) @value) @assign
  `,
  go: `
    (short_var_declaration left: (expression_list) @target right: (expression_list) @value) @assign
    (assignment_statement left: (expression_list) @target right: (expression_list) @value) @assign
    (var_spec name: (identifier) @target value: (expression_list) @value) @assign
    (const_spec name: (identifier) @target value: (expression_list) @value) @assign
    (keyed_element (literal_element (identifier) @target) (literal_element (_) @value)) @assign
  `,

  /*
   * C and C++ share these. `init_declarator` is the declaration-with-value
   * form (`char *p = getenv(...)`), and its @target captures the DECLARATOR
   * rather than a bare name - so `*name = getenv("USER")` yields a target of
   * `*name`, pointer star included. The tracer strips it; see POINTER_PREFIX
   * in taint/tracer.ts. Recorded here because it is the kind of detail that
   * silently halves a language's coverage if nobody notices it.
   */
  c: C_ASSIGN_QUERY,
  cpp: C_ASSIGN_QUERY,
};

/* ------------------------------------------------------------------------ */

/** Compiled queries are expensive to build and cheap to reuse. Cache per grammar. */
const queryCache = new Map<string, Query>();

async function compile(grammar: string, key: string, source: string): Promise<Query> {
  const cacheKey = `${grammar}:${key}`;
  const cached = queryCache.get(cacheKey);
  if (cached) return cached;
  const language = await getLanguage(grammar);
  const query = new Query(language, source);
  queryCache.set(cacheKey, query);
  return query;
}

function collapse(text: string | null | undefined): string {
  return (text ?? '').replace(/\s+/g, ' ').trim();
}

/** Pull one capture out of a match. Returns null when the capture is optional. */
function captured(match: QueryMatch, name: string): Node | null {
  for (const capture of match.captures) {
    if (capture.name === name) return capture.node;
  }
  return null;
}

/**
 * Argument lists contain punctuation as well as expressions. `namedChildren`
 * gives us only the meaningful ones - see the "named vs anonymous" note in
 * astDump.ts.
 */
function argumentNodes(argsNode: Node | null): Node[] {
  if (!argsNode) return [];
  return argsNode.namedChildren
    .filter((n): n is Node => n !== null)
    // PHP wraps every argument in an `argument` node, so the expression a rule
    // wants to examine sits one level down. Without this unwrap every PHP
    // argument reads as the node type `argument` and no content check matches.
    .map((n) => (n.type === 'argument' ? (n.namedChildren.find((c) => c !== null) ?? n) : n));
}

/**
 * Go writes `a, b := f(), g()` - both sides are lists. When the lists line up
 * we pair them; when they don't (a multi-return call) we bind every name to the
 * single value node, which is honest enough for signature matching and is
 * flagged as a known imprecision in the Go coverage notes.
 */
function goPairs(target: Node, value: Node): Array<{ t: Node; v: Node }> {
  const targets = target.type === 'expression_list' ? target.namedChildren : [target];
  const values = value.type === 'expression_list' ? value.namedChildren : [value];
  const pairs: Array<{ t: Node; v: Node }> = [];
  for (let i = 0; i < targets.length; i++) {
    const t = targets[i];
    if (!t) continue;
    const v = values.length === targets.length ? values[i] : values[0];
    if (v) pairs.push({ t, v });
  }
  return pairs;
}

/** Last dotted segment: "config.db.password" -> "password". */
function lastSegment(text: string): string {
  const cleaned = text.replace(/\[["']?|["']?\]/g, '.').replace(/\.+$/, '');
  const parts = cleaned.split('.');
  return (parts[parts.length - 1] ?? cleaned).trim();
}

/**
 * Lower one parsed file into the flat list of shapes rules will see.
 * Order is source order, which makes reports read top-to-bottom like the file.
 */
export async function extractShapes(file: ParsedFile, language: LanguageId): Promise<Shape[]> {
  const shapes: Shape[] = [];
  const seen = new Set<number>();

  const callQuery = await compile(file.grammar, 'calls', CALL_QUERIES[language]);
  for (const match of callQuery.matches(file.root)) {
    const call = captured(match, 'call');
    const method = captured(match, 'method');
    if (!call || !method) continue;
    // Java's two method_invocation patterns overlap (object is optional), so the
    // same node can match twice. Dedupe by node id.
    if (seen.has(call.id)) continue;
    seen.add(call.id);

    const receiver = captured(match, 'receiver');
    const receiverText = collapse(receiver?.text);
    const calleeName = collapse(method.text);
    // Java's `method_invocation` has no `function` field - the receiver and the
    // name are separate children - so we rebuild "receiver.name" by hand there.
    const functionNode = call.childForFieldName('function') ?? call.childForFieldName('constructor');
    const site: CallSite = {
      kind: 'call',
      node: call,
      calleeName,
      receiverText,
      calleeText: collapse(
        functionNode?.text ?? (receiverText ? `${receiverText}.${calleeName}` : calleeName),
      ),
      args: argumentNodes(captured(match, 'args')),
    };
    shapes.push(site);
  }

  const assignQuery = await compile(file.grammar, 'assignments', ASSIGNMENT_QUERIES[language]);
  for (const match of assignQuery.matches(file.root)) {
    const node = captured(match, 'assign');
    const target = captured(match, 'target');
    const value = captured(match, 'value');
    if (!node || !target || !value) continue;
    if (seen.has(node.id)) continue;
    seen.add(node.id);

    const pairs = language === 'go' ? goPairs(target, value) : [{ t: target, v: value }];
    for (const pair of pairs) {
      const targetText = collapse(pair.t.text);
      shapes.push({
        kind: 'assignment',
        node,
        targetText,
        targetName: lastSegment(targetText).replace(/^["']|["']$/g, ''),
        value: pair.v,
      } satisfies Assignment);
    }
  }

  shapes.sort((a, b) => a.node.startIndex - b.node.startIndex);
  return shapes;
}

/** Exposed so a self-check can compile every query against every grammar. */
export const SHAPE_QUERY_SOURCES = {
  calls: CALL_QUERIES,
  assignments: ASSIGNMENT_QUERIES,
} as const;
