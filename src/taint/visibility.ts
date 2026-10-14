/**
 * WHERE A DECLARATION CAN BE SEEN, AND WHAT THE PARSER CANNOT SEE.
 * ===============================================================
 *
 * The constant proof (rules/lib/strings.ts) collects every declaration of a
 * name in the scopes around a read. A collected declaration is only the one the
 * read means if the read is INSIDE where that declaration is visible - and
 * every language here scopes more tightly than "somewhere in this function".
 * The second break-it round (tests/probes/g05, s02, s03, s05, s06) was a
 * literal declared in a block, a `for` header, a class static block or a
 * namespace, standing in for the import or package variable the read really
 * meant.
 *
 * Every answer here may be NARROWER than the language's real rule - then the
 * proof gives up and the finding stays - but never wider.
 */

import type { Node } from 'web-tree-sitter';
import type { LanguageId } from '../parse/languages.js';
import { declarationScope } from './java-scope.js';

/** From this offset to the end of `region`, the declaration is the one a read of its name means. */
export interface Visibility {
  readonly region: Node;
  readonly from: number;
}

const JS_FUNCTIONS = new Set([
  'function_declaration', 'function_expression', 'arrow_function', 'method_definition',
  'generator_function_declaration', 'generator_function', 'class_static_block', 'program',
]);

export function declarationVisibility(declarator: Node, language: LanguageId): Visibility | null {
  if (language === 'java') return declarationScope(declarator);

  if (language === 'javascript' || language === 'typescript') {
    const declaration = declarator.parent;
    if (!declaration) return null;
    let holder = declaration.parent;
    while (holder?.type === 'export_statement') holder = holder.parent;
    if (!holder) return null;
    // `let` and `const`: the enclosing block (a `for` header's: the loop),
    // from the declaration on - before it is the temporal dead zone.
    if (declaration.type === 'lexical_declaration') return { region: holder, from: declarator.endIndex };
    // `var` is hoisted to the top of its function.
    if (declaration.type === 'variable_declaration') {
      let fn: Node | null = holder;
      while (fn && !JS_FUNCTIONS.has(fn.type)) fn = fn.parent;
      return fn ? { region: fn, from: fn.startIndex } : null;
    }
    return null;
  }

  if (language === 'go') {
    if (declarator.type === 'short_var_declaration') {
      // `x := v` is visible to the end of its block; in an `if`, `for` or
      // `switch` header, to the end of that statement.
      let holder = declarator.parent;
      if (holder?.type === 'for_clause') holder = holder.parent;
      return holder ? { region: holder, from: declarator.endIndex } : null;
    }
    if (declarator.type === 'var_spec') {
      let declaration = declarator.parent;
      if (declaration?.type === 'var_spec_list') declaration = declaration.parent;
      const holder = declaration?.parent;
      if (!holder) return null;
      // A package-level `var` is visible in the whole package, in any order.
      if (holder.type === 'source_file') return { region: holder, from: holder.startIndex };
      return { region: holder, from: declarator.endIndex };
    }
    return null;
  }

  return null;
}

/*
 * TEXT THE COMPILER READS AND THE PARSER DOES NOT.
 *
 * A lone carriage return ends a `//` comment for javac, for JavaScript
 * engines and for Python's tokenizer; U+2028 and U+2029 end one in
 * JavaScript; `\u000a` is a newline to javac before it parses anything.
 * Tree-sitter reads all of them as more comment - so `// note<CR> x = f();`
 * hides a real write (tests/probes/j15, s10, p31, p32). A file holding any of
 * them is a file the constant proof does not try to read.
 */
const hidden = new WeakMap<object, boolean>();
export function hidesCodeFromParser(n: Node, language: LanguageId): boolean {
  const key = n.tree as object;
  let found = hidden.get(key);
  if (found === undefined) {
    const text = n.tree.rootNode.text ?? '';
    found =
      /\r(?!\n)/.test(text) ||
      ((language === 'javascript' || language === 'typescript') && new RegExp("[\\u2028\\u2029]").test(text)) ||
      (language === 'java' && /\\u+[0-9a-fA-F]{4}/.test(text));
    hidden.set(key, found);
  }
  return found;
}
