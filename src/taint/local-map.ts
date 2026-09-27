/**
 * WHAT A LOCAL MAP GIVES BACK UNDER A KEY - WHEN THAT IS A FACT.
 *
 * The tracer taints a collection whole: one dirty `put` and every `get` comes
 * back dirty, marked as a guess about which element was read. That is the
 * right default, because in general a map's contents are not on the page -
 * it can be passed to a helper, filled by a framework, iterated, merged.
 *
 * keyed-container.java refuses to match keys for exactly that reason, on a
 * request's attributes: filters and frameworks the scan never sees can write
 * under the same name, so matching the key would be a guess.
 *
 * This module answers the narrow case where it is NOT a guess, and declines
 * everything else. Java only, and only when every write the map can ever
 * receive is visible right here:
 *
 *   - declared in this block as `new HashMap<...>()` or `new LinkedHashMap<...>()`
 *     with no arguments (a copy constructor would bring in contents unseen);
 *   - every mention of it is `map.put("literal", value);` as its OWN statement
 *     directly in that block - never under an if, a loop or a try, so each put
 *     certainly runs - or a read (`get`, `containsKey`, `size`, `isEmpty`);
 *   - it is never passed, returned, assigned, iterated, captured by anything
 *     that writes to it, or touched by any other method;
 *   - the read is not inside a lambda or an inner class, which could run after
 *     puts that come later in the text;
 *   - some put under that key comes before the read. The last one is the value.
 *
 * Keys are compared as literal text, and only literals with no escapes: two
 * Java string literals are equal() exactly when their characters match, and a
 * HashMap uses equals(). A TreeMap with a comparator does not, which is one of
 * the reasons only the two hash maps are accepted.
 */

import type { Node } from 'web-tree-sitter';
import type { LanguageId } from '../parse/languages.js';

export interface MapRead {
  readonly mapName: string;
  readonly key: string;
  /** The `map.put(key, value)` call whose value this read returns. */
  readonly put: Node;
  /** The value expression of that put. */
  readonly value: Node;
}

const MAP_TYPE = /^(?:java\.util\.)?(?:HashMap|LinkedHashMap)\s*(?:<[^>]*>)?$/;
const PLAIN_KEY = /^"([^"\\]*)"$/;
const READ_ONLY = new Set(['get', 'containsKey', 'containsValue', 'size', 'isEmpty']);
const FUNCTION_BOUNDARY = /^(?:method_declaration|constructor_declaration|lambda_expression|class_body)$/;

const named = (n: Node | null | undefined): Node[] =>
  (n?.namedChildren ?? []).filter((c): c is Node => c !== null);

const sameSpan = (a: Node | null | undefined, b: Node | null | undefined): boolean =>
  !!a && !!b && a.startIndex === b.startIndex && a.endIndex === b.endIndex;

/** The literal key of a one-argument call, or null. */
function literalKey(args: Node[], index: number): string | null {
  const arg = args[index];
  if (!arg || arg.type !== 'string_literal') return null;
  const match = PLAIN_KEY.exec(arg.text);
  return match?.[1] ?? null;
}

/** The block that declares `name` as a fresh collection of `type`, walking up from `from` without leaving the function. */
function declaringBlock(from: Node, name: string, type: RegExp = MAP_TYPE): { block: Node; declaration: Node } | null {
  let current: Node | null = from.parent;
  while (current) {
    if (FUNCTION_BOUNDARY.test(current.type)) return null;
    if (current.type === 'block' || current.type === 'constructor_body') {
      for (const statement of named(current)) {
        if (statement.type !== 'local_variable_declaration') continue;
        const declarators = named(statement).filter((c) => c.type === 'variable_declarator');
        const mine = declarators.find((d) => d.childForFieldName('name')?.text === name);
        if (!mine) continue;
        if (declarators.length !== 1) return null;
        const value = mine.childForFieldName('value');
        if (value?.type !== 'object_creation_expression') return null;
        if (!type.test((value.childForFieldName('type')?.text ?? '').replace(/\s+/g, ''))) return null;
        if (named(value.childForFieldName('arguments')).length !== 0) return null;
        if (value.childForFieldName('body') ?? named(value).some((c) => c.type === 'class_body')) return null;
        return { block: current, declaration: statement };
      }
    }
    current = current.parent;
  }
  return null;
}

/** The method or constructor a node sits in - the whole region any mention of the map could hide in. */
function outermostFunction(from: Node): Node | null {
  let current: Node | null = from.parent;
  let found: Node | null = null;
  while (current) {
    if (current.type === 'method_declaration' || current.type === 'constructor_declaration') found = current;
    if (current.type === 'class_body' && found) break;
    current = current.parent;
  }
  return found;
}

/**
 * The put a `map.get("key")` certainly returns, or null whenever that is not a
 * fact. Null always means "use the old whole-collection answer", never "clean".
 */
export function resolveMapRead(call: Node, language: LanguageId): MapRead | null {
  if (language !== 'java' || call.type !== 'method_invocation') return null;
  if (call.childForFieldName('name')?.text !== 'get') return null;
  const receiver = call.childForFieldName('object');
  if (receiver?.type !== 'identifier') return null;
  const mapName = receiver.text;
  const key = literalKey(named(call.childForFieldName('arguments')), 0);
  if (key === null || named(call.childForFieldName('arguments')).length !== 1) return null;

  const home = declaringBlock(call, mapName);
  if (!home) return null;
  if (home.declaration.endIndex > call.startIndex) return null;
  const fn = outermostFunction(call);
  if (!fn) return null;

  // Every mention of the name, anywhere in the method - lambdas and inner
  // classes included, since that is exactly where an unseen write would hide.
  const puts: Array<{ put: Node; key: string; value: Node }> = [];
  let escapes = false;
  let walked = 0;
  const visit = (n: Node): void => {
    if (escapes) return;
    if (++walked > 20000) {
      escapes = true;
      return;
    }
    if (n.type === 'identifier' && n.text === mapName) {
      const parent = n.parent;
      if (parent?.type === 'variable_declarator' && sameSpan(parent.childForFieldName('name'), n)) {
        if (!sameSpan(parent.parent, home.declaration)) escapes = true; // a second variable of that name
        return;
      }
      if (parent?.type !== 'method_invocation' || !sameSpan(parent.childForFieldName('object'), n)) {
        escapes = true; // passed, returned, assigned, captured, iterated
        return;
      }
      const method = parent.childForFieldName('name')?.text ?? '';
      if (READ_ONLY.has(method)) return;
      if (method !== 'put') {
        escapes = true;
        return;
      }
      const args = named(parent.childForFieldName('arguments'));
      const putKey = literalKey(args, 0);
      const statement = parent.parent;
      const certain =
        statement?.type === 'expression_statement' && sameSpan(statement.parent, home.block);
      if (putKey === null || args.length !== 2 || !certain || !args[1]) {
        escapes = true;
        return;
      }
      puts.push({ put: parent, key: putKey, value: args[1] });
      return;
    }
    for (const child of named(n)) visit(child);
  };
  visit(fn);
  if (escapes) return null;

  const before = puts.filter((p) => p.key === key && p.put.endIndex <= call.startIndex);
  const last = before[before.length - 1];
  return last ? { mapName, key, put: last.put, value: last.value } : null;
}

/** Assignment-like writes to `name` strictly between two source offsets - any, in any form. */
export function writtenBetween(fn: Node, name: string, from: number, to: number): boolean {
  let found = false;
  const word = new RegExp(`(^|[^\\w$])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w$])`);
  const visit = (n: Node): void => {
    if (found || n.endIndex <= from || n.startIndex >= to) return;
    if (n.type === 'assignment_expression' || n.type === 'update_expression') {
      const target = n.childForFieldName('left') ?? n;
      if (word.test(target.text)) found = true;
    } else if (n.type === 'variable_declarator' && n.childForFieldName('name')?.text === name) {
      found = true;
    }
    for (const child of named(n)) visit(child);
  };
  visit(fn);
  return found;
}

/** The method or constructor containing a node, for callers that need to scan it. */
export function enclosingMethod(from: Node): Node | null {
  return outermostFunction(from);
}

/*
 * A value the map holds BY REFERENCE can change after the put without any
 * write to the name the tracer watches: `StringBuilder sb; map.put("k", sb);
 * alias.append(dirty)` - or an array element, or a list. Reading such a name
 * at the `get` would describe the tracer's idea of it, which misses aliases.
 * So a put value is read at the get only when its declared type is one whose
 * values cannot change: String, the primitives and their boxes.
 */
const IMMUTABLE_TYPES = /^(?:(?:java\.lang\.)?(?:String|Integer|Long|Short|Byte|Character|Boolean|Double|Float)|int|long|short|byte|char|boolean|double|float)$/;

/** Whether `name`, as declared in `fn`, holds a value that can never change in place. */
export function declaredImmutable(fn: Node, name: string): boolean {
  let verdict: boolean | null = null;
  const visit = (n: Node): void => {
    if (verdict === false) return;
    if (n.type === 'formal_parameter' && n.childForFieldName('name')?.text === name) {
      const ok = IMMUTABLE_TYPES.test((n.childForFieldName('type')?.text ?? '').replace(/\s+/g, ''));
      verdict = verdict === null ? ok : verdict && ok;
    } else if (n.type === 'local_variable_declaration') {
      for (const d of named(n)) {
        if (d.type === 'variable_declarator' && d.childForFieldName('name')?.text === name) {
          const ok = IMMUTABLE_TYPES.test((n.childForFieldName('type')?.text ?? '').replace(/\s+/g, ''));
          verdict = verdict === null ? ok : verdict && ok;
        }
      }
    }
    for (const child of named(n)) visit(child);
  };
  visit(fn);
  return verdict === true;
}

/*
 * THE SAME PROOF FOR A LIST, WHERE THE KEY IS A POSITION.
 *
 *     List<String> valuesList = new ArrayList<String>();
 *     valuesList.add("safe");
 *     valuesList.add(param);
 *     valuesList.add("moresafe");
 *     valuesList.remove(0);
 *     bar = valuesList.get(1);            // "moresafe"
 *
 * 323 BenchmarkJava cases are this list. Positions move - `remove(0)` shifts
 * everything after it down one - so the list is REPLAYED: every operation that
 * certainly runs before the read, in order, on a model of the list. The same
 * conditions as the map, and a few of a list's own:
 *
 *   - a local `new ArrayList<>()` or `new LinkedList<>()`, no arguments;
 *   - its only writes are `list.add(value);` (append) and `list.remove(n);`
 *     with an integer literal, each its own statement directly in the declaring
 *     block. `remove("x")` removes by VALUE and `add(i, v)` inserts - neither is
 *     modelled, and either one ends the proof;
 *   - reads are `get`, `size`, `isEmpty`, `contains`, `indexOf`, `lastIndexOf`;
 *   - the read's index is an integer literal, and every position the replay
 *     touches exists. An index out of range throws at runtime, and a proof that
 *     has to assume which exception happens is not one.
 */
const LIST_TYPE = /^(?:java\.util\.)?(?:ArrayList|LinkedList)\s*(?:<[^>]*>)?$/;
const LIST_READ_ONLY = new Set(['get', 'size', 'isEmpty', 'contains', 'indexOf', 'lastIndexOf']);

/** An integer literal's value, or null. */
function intLiteral(n: Node | undefined): number | null {
  if (!n || n.type !== 'decimal_integer_literal' || !/^\d+$/.test(n.text)) return null;
  const value = Number(n.text);
  return Number.isSafeInteger(value) ? value : null;
}

export interface ListRead {
  readonly listName: string;
  readonly index: number;
  /** The `list.add(value)` call whose value this read returns. */
  readonly add: Node;
  readonly value: Node;
}

/** The element a `list.get(n)` certainly returns, or null whenever that is not a fact. */
export function resolveListRead(call: Node, language: LanguageId): ListRead | null {
  if (language !== 'java' || call.type !== 'method_invocation') return null;
  if (call.childForFieldName('name')?.text !== 'get') return null;
  const receiver = call.childForFieldName('object');
  if (receiver?.type !== 'identifier') return null;
  const listName = receiver.text;
  const readArgs = named(call.childForFieldName('arguments'));
  const index = readArgs.length === 1 ? intLiteral(readArgs[0]) : null;
  if (index === null) return null;

  const home = declaringBlock(call, listName, LIST_TYPE);
  if (!home) return null;
  if (home.declaration.endIndex > call.startIndex) return null;
  const fn = outermostFunction(call);
  if (!fn) return null;

  type Op = { kind: 'add'; node: Node; value: Node } | { kind: 'remove'; node: Node; at: number };
  const ops: Op[] = [];
  let escapes = false;
  let walked = 0;
  const visit = (n: Node): void => {
    if (escapes) return;
    if (++walked > 20000) {
      escapes = true;
      return;
    }
    if (n.type === 'identifier' && n.text === listName) {
      const parent = n.parent;
      if (parent?.type === 'variable_declarator' && sameSpan(parent.childForFieldName('name'), n)) {
        if (!sameSpan(parent.parent, home.declaration)) escapes = true;
        return;
      }
      if (parent?.type !== 'method_invocation' || !sameSpan(parent.childForFieldName('object'), n)) {
        escapes = true;
        return;
      }
      const method = parent.childForFieldName('name')?.text ?? '';
      if (LIST_READ_ONLY.has(method)) return;
      const args = named(parent.childForFieldName('arguments'));
      const statement = parent.parent;
      const certain =
        statement?.type === 'expression_statement' && sameSpan(statement.parent, home.block);
      if (!certain) {
        escapes = true;
        return;
      }
      if (method === 'add' && args.length === 1 && args[0]) {
        ops.push({ kind: 'add', node: parent, value: args[0] });
        return;
      }
      const at = method === 'remove' && args.length === 1 ? intLiteral(args[0]) : null;
      if (at !== null) {
        ops.push({ kind: 'remove', node: parent, at });
        return;
      }
      escapes = true;
      return;
    }
    for (const child of named(n)) visit(child);
  };
  visit(fn);
  if (escapes) return null;

  const model: Array<{ node: Node; value: Node }> = [];
  for (const op of ops.sort((a, b) => a.node.startIndex - b.node.startIndex)) {
    if (op.node.endIndex > call.startIndex) break;
    if (op.kind === 'add') {
      model.push({ node: op.node, value: op.value });
    } else {
      if (op.at >= model.length) return null;
      model.splice(op.at, 1);
    }
  }
  const element = model[index];
  return element ? { listName, index, add: element.node, value: element.value } : null;
}

/** A read from a local map or list, resolved to the write that supplies it. */
export interface ContainerRead {
  readonly container: string;
  /** How the read picks its element, for a sentence: `"keyA"` or `index 1`. */
  readonly selector: string;
  /** The put or add whose value this read returns. */
  readonly write: Node;
  readonly value: Node;
}

/** Try the map proof, then the list proof. Null means "use the whole-collection answer". */
export function resolveContainerRead(call: Node, language: LanguageId): ContainerRead | null {
  const map = resolveMapRead(call, language);
  if (map) return { container: map.mapName, selector: `"${map.key}"`, write: map.put, value: map.value };
  const list = resolveListRead(call, language);
  if (list) return { container: list.listName, selector: `index ${list.index}`, write: list.add, value: list.value };
  return null;
}
