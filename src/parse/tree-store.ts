/**
 * THE TREE STORE  (how a scan stops running out of memory)
 * ========================================================
 *
 * THE PROBLEM, STATED HONESTLY.
 *
 * A tree-sitter syntax tree does not live in JavaScript memory. It lives in a
 * WebAssembly heap that the garbage collector cannot see into, so a tree is
 * never collected, however dead it looks - the only thing that frees one is an
 * explicit call to tree.delete().
 *
 * Until this module existed, nothing in this project called delete(). Every file
 * parsed stayed parsed until the process exited. Measured on Django:
 *
 *     248 files   0.9 MB source   173 MB peak
 *     992 files   6.9 MB source   525 MB peak      ~59x per marginal byte
 *
 * which puts the hard ceiling at roughly 44 MB of source on an 8 GB machine.
 * Most serious repositories are bigger than that. The scan does not slow down
 * at the ceiling; it is killed by the operating system, which is a worse
 * failure than a slow answer because it produces no answer at all.
 *
 * THE EXPLANATION THAT WAS IN THE CODE, AND WHY IT WAS WRONG.
 *
 * A comment above the parse loop said the trees had to be held because
 * cross-file tracing must be able to resolve into any file at any time, and
 * that this was why `--no-cross-file` existed. Plausible, and false. Measured:
 *
 *     cross-file ON     528.8 MB
 *     cross-file OFF    535.8 MB
 *
 * Turning the feature off freed nothing, because the trees were never freed in
 * either mode. The stated cause was a rationalisation of an accident. It is
 * recorded here because a wrong explanation is more expensive than no
 * explanation: it stops anybody looking.
 *
 * WHAT THIS MODULE DOES.
 *
 * It owns every tree in the scan and holds as many as a stated budget allows,
 * evicting the least recently used one when the budget is exceeded. A file
 * whose tree was evicted is simply parsed again when something needs it. So:
 *
 *   - a project that fits in the budget behaves exactly as before, parses each
 *     file exactly once, and runs at exactly the old speed;
 *   - a project that does not fit gets slower instead of getting killed.
 *
 * Time is a renewable resource and a dead process is not.
 *
 * PINNING - THE PART THAT WOULD BE A CRASH IF IT WERE WRONG.
 *
 * Evicting a tree frees the WebAssembly memory that every Node object from it
 * points into. A Node whose tree has been deleted is not an error; it is a
 * dangling pointer into a heap that now holds something else, and reading it
 * yields silent nonsense. So a tree is pinned for as long as anything might
 * still hold a node from it, and eviction skips pinned entries entirely, even
 * when that means going over budget. Going over budget is visible in the stats
 * and is the right answer: correctness first, then memory, then speed.
 */

import type { Node, Tree } from 'web-tree-sitter';
import { parseSourceSync } from './parser.js';

/**
 * How many bytes of WebAssembly heap one byte of source costs once parsed.
 *
 * MEASURED, not guessed: 6.9 MB of Django source produced a 525 MB peak against
 * a ~120 MB floor (Node plus seven loaded grammars), which is about 59x. Sixty
 * is used because the number varies by language and an underestimate is the
 * dangerous direction - it would let the store believe it is inside a budget it
 * has already blown.
 *
 * The estimate only decides WHEN to evict. Nothing is ever wrong because this
 * number is off; the scan just holds slightly more or less than intended.
 */
export const TREE_BYTES_PER_SOURCE_BYTE = 60;

/**
 * Default budget: roughly a gigabyte of trees, which is about 17 MB of source
 * held at once. Chosen so that every project this tool has been run against so
 * far fits entirely and therefore parses each file exactly once - the redesign
 * should cost nothing on the sizes people actually scan, and only start trading
 * time for memory past the point where the old code died.
 */
export const DEFAULT_TREE_BUDGET_BYTES = 1024 * 1024 * 1024;

export interface TreeStoreStats {
  readonly budgetBytes: number;
  /** Files whose tree is resident right now. */
  readonly filesResident: number;
  /** The most tree memory this scan ever estimated it was holding. */
  readonly peakEstimatedBytes: number;
  /** Parses performed in total, including the first one of each file. */
  readonly parses: number;
  /** Parses that happened only because an earlier tree had been evicted. */
  readonly reparses: number;
  readonly evictions: number;
  /**
   * True when the budget was exceeded and something had to be evicted - i.e.
   * the project did not fit. Reported, because it is the difference between
   * "this scan was slow" and "this scan was slow FOR A REASON".
   */
  readonly spilled: boolean;
  /**
   * Times the budget was blown because every resident tree was pinned. Not an
   * error, but the one way this design can still use unbounded memory, so it is
   * counted rather than assumed away.
   */
  readonly overBudgetWhileAllPinned: number;
}

interface Entry {
  readonly path: string;
  readonly source: string;
  readonly grammar: string;
  readonly estimatedBytes: number;
  tree: Tree | null;
  pins: number;
  lastUsed: number;
}

export interface TreeStore {
  /** Declare a file and hand over the tree the first pass already produced. */
  admit(path: string, source: string, grammar: string, tree: Tree): void;
  /** The tree for a known file, parsing it again if it was evicted. */
  get(path: string): Tree;
  /** Hold this file's tree until releaseAll(). Nested pins are counted. */
  pin(path: string): void;
  /** Drop every pin. Call only where no Node from any file is still held. */
  releaseAll(): void;
  /** Free everything. The store is unusable afterwards. */
  disposeAll(): void;
  stats(): TreeStoreStats;
}

/**
 * Find the node at an exact byte range in a freshly parsed tree.
 *
 * This is the hinge of the whole design. The index records a function body as
 * two byte offsets instead of a Node, because a Node keeps its tree alive and
 * the point is to let trees go. When the tracer finally wants that body, the
 * file is parsed again and the node is looked up here.
 *
 * Two things make it safe. The parse is deterministic - same bytes, same
 * grammar, same tree - so the node is certainly there. And the result is
 * CHECKED: the range and the node type must both match what was recorded, or
 * this returns null and the caller declines to resolve. Tracing into a node we
 * merely believe is the right one would manufacture exactly the kind of
 * confident, wrong proof this project exists to avoid.
 *
 * The walk upward is needed because descendantForIndex returns the SMALLEST
 * node covering a range, and a node can share its exact extent with its parent
 * (a block that is its own statement, an expression that is its own body). The
 * recorded type disambiguates them.
 */
export function nodeAtRange(
  root: Node,
  startIndex: number,
  endIndex: number,
  type: string,
): Node | null {
  let node: Node | null = root.descendantForIndex(startIndex, endIndex);
  let hops = 0;
  while (node && hops < 64) {
    if (node.startIndex === startIndex && node.endIndex === endIndex && node.type === type) {
      return node;
    }
    node = node.parent;
    hops++;
  }
  return null;
}

export function createTreeStore(budgetBytes = DEFAULT_TREE_BUDGET_BYTES): TreeStore {
  const entries = new Map<string, Entry>();
  let heldBytes = 0;
  let peakEstimatedBytes = 0;
  let clock = 0;
  let parses = 0;
  let reparses = 0;
  let evictions = 0;
  let spilled = false;
  let overBudgetWhileAllPinned = 0;

  const touch = (entry: Entry): void => {
    entry.lastUsed = ++clock;
  };

  const drop = (entry: Entry): void => {
    if (!entry.tree) return;
    entry.tree.delete();
    entry.tree = null;
    heldBytes -= entry.estimatedBytes;
    evictions++;
    spilled = true;
  };

  /** Evict least-recently-used unpinned trees until we are inside the budget. */
  const makeRoom = (): void => {
    if (heldBytes <= budgetBytes) return;

    const candidates = [...entries.values()]
      .filter((e) => e.tree !== null && e.pins === 0)
      .sort((a, b) => a.lastUsed - b.lastUsed);

    for (const candidate of candidates) {
      if (heldBytes <= budgetBytes) return;
      drop(candidate);
    }

    // Everything still resident is pinned. We go over budget rather than free
    // a tree somebody is holding a node from. Counted, never hidden.
    if (heldBytes > budgetBytes) overBudgetWhileAllPinned++;
  };

  const note = (): void => {
    if (heldBytes > peakEstimatedBytes) peakEstimatedBytes = heldBytes;
  };

  return {
    admit(path, source, grammar, tree) {
      const existing = entries.get(path);
      if (existing) {
        // Re-admitting the same path would leak the tree already held for it.
        if (existing.tree && existing.tree !== tree) existing.tree.delete();
        else if (existing.tree === null) heldBytes += existing.estimatedBytes;
        existing.tree = tree;
        touch(existing);
        note();
        makeRoom();
        return;
      }

      const entry: Entry = {
        path,
        source,
        grammar,
        estimatedBytes: source.length * TREE_BYTES_PER_SOURCE_BYTE,
        tree,
        pins: 0,
        lastUsed: ++clock,
      };
      entries.set(path, entry);
      heldBytes += entry.estimatedBytes;
      parses++;
      note();
      makeRoom();
    },

    get(path) {
      const entry = entries.get(path);
      if (!entry) {
        throw new Error(
          `No file registered at ${path}. Every file must be admitted during the ` +
            'first pass; asking for one that was not is a bug, not a missing file.',
        );
      }
      if (entry.tree) {
        touch(entry);
        return entry.tree;
      }
      entry.tree = parseSourceSync(entry.source, entry.grammar);
      heldBytes += entry.estimatedBytes;
      parses++;
      reparses++;
      touch(entry);
      note();
      makeRoom();
      return entry.tree;
    },

    pin(path) {
      const entry = entries.get(path);
      if (entry) entry.pins++;
    },

    releaseAll() {
      for (const entry of entries.values()) entry.pins = 0;
      makeRoom();
    },

    disposeAll() {
      for (const entry of entries.values()) {
        if (entry.tree) entry.tree.delete();
        entry.tree = null;
      }
      heldBytes = 0;
      entries.clear();
    },

    stats: () => ({
      budgetBytes,
      filesResident: [...entries.values()].filter((e) => e.tree !== null).length,
      peakEstimatedBytes,
      parses,
      reparses,
      evictions,
      spilled,
      overBudgetWhileAllPinned,
    }),
  };
}
