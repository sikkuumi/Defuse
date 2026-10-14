/**
 * JAVA NAMES, AS JAVA RESOLVES THEM - THE PARTS THE CONSTANT PROOF NEEDS.
 * =====================================================================
 *
 * The constant proof (rules/lib/strings.ts) withdraws a finding when it can
 * show every value spliced into a query or command is fixed. That makes every
 * mistake about WHICH declaration a name refers to a deleted finding, not a
 * noisy one. An agent was set to break it, and in Java alone it found 32 ways
 * (tests/probes/): a class hidden by a pattern variable, a static import, an
 * enum constant or an inherited member type; an inherited overload; a local
 * that is out of scope where the value is read; `final` written only in a
 * comment; a `\u000a` that javac reads as a newline.
 *
 * This module does not resolve names. It answers narrower questions whose
 * "no" is always safe - "is this name used ANY way but as a qualifier?", "does
 * any class between here and there inherit from something?" - so a doubt ends
 * the proof and leaves the finding standing.
 */

import type { Node } from 'web-tree-sitter';

/** A modifier keyword on a declaration - the token itself, never a word in an annotation or comment. */
export function hasModifier(declaration: Node, keyword: string): boolean {
  const modifiers = declaration.namedChildren.find((c): c is Node => c?.type === 'modifiers');
  return !!modifiers && modifiers.children.some((c) => c?.type === keyword);
}

/** Declarations whose body is a class body: they can declare and inherit members. */
const CLASS_LIKE = new Set([
  'class_declaration', 'interface_declaration', 'enum_declaration', 'record_declaration',
  'annotation_type_declaration',
]);

/** A class-like node, including `new T() { ... }` - an anonymous subclass of T. */
export function isClassLike(n: Node): boolean {
  return (
    CLASS_LIKE.has(n.type) ||
    (n.type === 'object_creation_expression' && n.namedChildren.some((c) => c?.type === 'class_body'))
  );
}

/** Class-like nodes strictly enclosing `n`, innermost first, stopping before `stop` if given. */
export function enclosingClassLikes(n: Node, stop?: Node): Node[] {
  const out: Node[] = [];
  for (let at = n.parent; at; at = at.parent) {
    if (stop && at.startIndex === stop.startIndex && at.endIndex === stop.endIndex) break;
    if (isClassLike(at)) out.push(at);
  }
  return out;
}

/**
 * The types a class-like inherits from, as written: `extends B`, `implements
 * I, J`, an interface's `extends`, and the T of an anonymous `new T() {}`.
 * Generic arguments are dropped; a qualified name keeps its dots.
 */
export function supertypesOf(classLike: Node): string[] {
  const names: string[] = [];
  const add = (t: Node | null | undefined): void => {
    if (!t) return;
    const text = (t.text ?? '').replace(/<[\s\S]*$/, '').replace(/\s+/g, '');
    if (text) names.push(text);
  };
  if (classLike.type === 'object_creation_expression') {
    add(classLike.childForFieldName('type'));
    return names;
  }
  for (const child of classLike.namedChildren) {
    if (!child) continue;
    if (child.type === 'superclass' || child.type === 'super_interfaces' || child.type === 'extends_interfaces') {
      const visit = (n: Node): void => {
        if (n.type === 'type_identifier' || n.type === 'scoped_type_identifier' || n.type === 'generic_type') {
          add(n);
          return;
        }
        for (const c of n.namedChildren) if (c) visit(c);
      };
      visit(child);
    }
  }
  return names;
}

/**
 * Is every appearance of `name` in this file - outside its package and import
 * lines - a QUALIFIER, as `name` is in `name.m()`, `name.f` or `@name.A`?
 *
 * A variable, parameter, field, pattern variable, lambda parameter, enum
 * constant, label or type DECLARED with that name is some other kind of
 * appearance, and any one of them could be what `name.m()` means here (JLS
 * 6.4.2: a variable obscures a type, and a type a package). Reading the
 * negative is what keeps this short: there are a dozen ways to declare a name
 * in Java and only these few ways to use one as a qualifier.
 */
export function usedOnlyAsQualifier(root: Node, name: string): boolean {
  return cached(qualifierCache, root, name, () => walkQualifierUses(root, name));
}

/*
 * Both whole-file questions are asked once per name per proof, and a scan
 * asks thousands - so the answer is kept per tree and name. A tree is never
 * edited, so it never goes stale.
 */
const qualifierCache = new WeakMap<object, Map<string, boolean>>();
const bindingCache = new WeakMap<object, Map<string, boolean>>();
function cached(cache: WeakMap<object, Map<string, boolean>>, root: Node, name: string, compute: () => boolean): boolean {
  const key = root.tree as object;
  let perTree = cache.get(key);
  if (!perTree) {
    perTree = new Map();
    cache.set(key, perTree);
  }
  let answer = perTree.get(name);
  if (answer === undefined) {
    answer = compute();
    perTree.set(name, answer);
  }
  return answer;
}

function walkQualifierUses(root: Node, name: string): boolean {
  const same = (a: Node | null, b: Node): boolean =>
    !!a && a.startIndex === b.startIndex && a.endIndex === b.endIndex;
  let ok = true;
  const visit = (n: Node): void => {
    if (!ok) return;
    if (n.type === 'package_declaration' || n.type === 'import_declaration') return;
    if (n.type === 'identifier' && n.text === name) {
      const p = n.parent;
      const qualifier =
        !!p &&
        (((p.type === 'method_invocation' || p.type === 'field_access') && same(p.childForFieldName('object'), n)) ||
          (p.type === 'scoped_identifier' && same(p.childForFieldName('scope'), n)) ||
          (p.type === 'field_access' && same(p.childForFieldName('field'), n)) ||
          (p.type === 'method_invocation' && same(p.childForFieldName('name'), n)));
      if (!qualifier) ok = false;
      return;
    }
    for (const child of n.namedChildren) if (child) visit(child);
  };
  visit(root);
  return ok;
}

/**
 * Does the file bind `name` in a way the constant proof's write survey does
 * not collect - a lambda parameter, a pattern variable (`instanceof T name`,
 * `case T name ->`, a record pattern), a try-with-resources variable, a
 * record component, or an enum constant? Any one of them can shadow the
 * declaration the proof found (tests/probes/p15, p16, j01, j02).
 */
export function boundElsewhere(root: Node, name: string): boolean {
  return cached(bindingCache, root, name, () => walkBindings(root, name));
}

function walkBindings(root: Node, name: string): boolean {
  let found = false;
  const word = new RegExp(`(^|[^\\w$])${name.replace(/\$/g, '\\$')}(?![\\w$])`);
  const visit = (n: Node): void => {
    if (found) return;
    if (n.type === 'lambda_expression') {
      const params = n.childForFieldName('parameters');
      if (params && word.test(params.text ?? '')) found = true;
    } else if (n.type === 'instanceof_expression') {
      if (n.childForFieldName('name')?.text === name) found = true;
    } else if (n.type === 'type_pattern' || n.type === 'record_pattern_component') {
      if (n.namedChildren.some((c) => c?.type === 'identifier' && c.text === name)) found = true;
    } else if (n.type === 'resource' || n.type === 'enum_constant') {
      if (n.childForFieldName('name')?.text === name) found = true;
    } else if (n.type === 'record_declaration') {
      const components = n.childForFieldName('parameters')?.namedChildren ?? [];
      if (components.some((c) => c?.childForFieldName('name')?.text === name)) found = true;
    }
    if (!found) for (const child of n.namedChildren) if (child) visit(child);
  };
  visit(root);
  return found;
}

/**
 * Where a Java declaration of a variable is visible: a local from its own
 * declaration to the end of the block that holds it (a `for` header's local,
 * the whole `for`); a field or interface constant, its whole class body.
 * Null for anything else - the caller treats that as "cannot place it".
 */
export function declarationScope(declarator: Node): { region: Node; from: number } | null {
  const holder = declarator.parent;
  if (!holder) return null;
  if (holder.type === 'local_variable_declaration') {
    const region = holder.parent;
    if (!region) return null;
    return { region, from: declarator.endIndex };
  }
  if (holder.type === 'field_declaration' || holder.type === 'constant_declaration') {
    const body = holder.parent;
    if (!body) return null;
    return { region: body, from: body.startIndex };
  }
  return null;
}
