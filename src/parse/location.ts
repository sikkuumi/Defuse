/**
 * Turning a tree-sitter node into a human-readable, reproducible location.
 *
 * Tree-sitter counts rows and columns from 0. Editors, terminals and humans
 * count from 1. Every off-by-one bug in a scanner's output lives right here, so
 * the conversion happens in exactly ONE place: this file.
 */

import type { Node } from 'web-tree-sitter';
import type { CodeLocation } from '../core/finding.js';

const MAX_SNIPPET = 160;

/** Walk up the tree collecting node types: "program > call_expression > ...". */
export function astPath(node: Node, maxDepth = 5): string {
  const parts: string[] = [];
  let current: Node | null = node;
  while (current && parts.length < maxDepth) {
    parts.unshift(current.type);
    current = current.parent;
  }
  return parts.join(' > ');
}

/**
 * Build the location record that goes into a finding.
 * `file` is passed in because a node does not know which file it came from -
 * tree-sitter only ever sees a string of text.
 */
export function nodeLocation(node: Node, file: string): CodeLocation {
  const raw = node.text ?? '';
  const collapsed = raw.replace(/\s+/g, ' ').trim();
  return {
    file,
    startLine: node.startPosition.row + 1,
    startColumn: node.startPosition.column + 1,
    endLine: node.endPosition.row + 1,
    endColumn: node.endPosition.column + 1,
    astNodeType: node.type,
    astNodePath: astPath(node),
    snippet:
      collapsed.length > MAX_SNIPPET ? `${collapsed.slice(0, MAX_SNIPPET - 1)}…` : collapsed,
  };
}
