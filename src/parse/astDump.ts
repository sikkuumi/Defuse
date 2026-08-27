/**
 * A human-readable printer for syntax trees.
 *
 * This exists purely so you can SEE what the parser sees. Run:
 *     npm run ast -- somefile.js
 * and compare the output to the source. Once the shape of the tree stops
 * looking mysterious, writing detection rules becomes ordinary programming.
 *
 * Two concepts show up in the output:
 *
 *   NAMED vs ANONYMOUS nodes. `db.query(x)` contains the parentheses and the
 *   dot as nodes too, but they carry no meaning of their own - tree-sitter calls
 *   those "anonymous". By default we hide them, because rules almost never care.
 *
 *   FIELDS. Some children have a role, not just a position. In
 *   `binary_expression`, the children are labelled `left`, `operator`, `right`.
 *   Fields are how a rule says "the thing being called" instead of "child #0",
 *   which is what makes rules survive grammar updates.
 */

import type { Node } from 'web-tree-sitter';

export interface AstDumpOptions {
  /** Show punctuation/keyword nodes too. Default false. */
  readonly includeAnonymous?: boolean;
  /** Stop after this depth. Default 12. */
  readonly maxDepth?: number;
  /** Stop after this many lines, so a huge file doesn't flood the terminal. */
  readonly maxLines?: number;
  /** Show the source text of leaf nodes. Default true. */
  readonly showText?: boolean;
}

export function dumpAst(root: Node, options: AstDumpOptions = {}): string {
  const includeAnonymous = options.includeAnonymous ?? false;
  const maxDepth = options.maxDepth ?? 12;
  const maxLines = options.maxLines ?? 400;
  const showText = options.showText ?? true;

  const lines: string[] = [];

  const walk = (node: Node, depth: number, fieldName: string | null, prefix: string, isLast: boolean): void => {
    if (lines.length >= maxLines) return;

    const connector = depth === 0 ? '' : isLast ? '└─ ' : '├─ ';
    const label = fieldName ? `${fieldName}: ${node.type}` : node.type;
    const position = `[${node.startPosition.row + 1}:${node.startPosition.column + 1}]`;

    // Show source text only for leaves - printing it for a whole function is noise.
    let text = '';
    if (showText && node.namedChildCount === 0) {
      const raw = (node.text ?? '').replace(/\s+/g, ' ').trim();
      if (raw.length > 0) text = `  "${raw.length > 48 ? `${raw.slice(0, 47)}…` : raw}"`;
    }

    lines.push(`${prefix}${connector}${label} ${position}${text}`);

    if (depth >= maxDepth) {
      if (node.namedChildCount > 0) {
        lines.push(`${prefix}${isLast ? '   ' : '│  '}└─ … (${node.namedChildCount} more, depth limit)`);
      }
      return;
    }

    const children: Array<{ node: Node; field: string | null }> = [];
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (!child) continue;
      if (!includeAnonymous && !child.isNamed) continue;
      children.push({ node: child, field: node.fieldNameForChild(i) });
    }

    const childPrefix = depth === 0 ? '' : prefix + (isLast ? '   ' : '│  ');
    children.forEach((child, index) => {
      walk(child.node, depth + 1, child.field, childPrefix, index === children.length - 1);
    });
  };

  walk(root, 0, null, '', true);

  if (lines.length >= maxLines) {
    lines.push(`… output truncated at ${maxLines} lines (use --max-lines to raise)`);
  }
  return lines.join('\n');
}
