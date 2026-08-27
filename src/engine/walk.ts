/**
 * FILE DISCOVERY
 *
 * Turning "scan this path" into "here is the list of files". Boring code, but
 * two decisions in it matter:
 *
 * 1. We skip dependency and build directories. Scanning node_modules finds
 *    thousands of "vulnerabilities" in other people's code that you cannot fix
 *    and did not write. Dependency risk is a real and separate problem
 *    (Software Composition Analysis) and it deserves its own tool, not noise
 *    inside this one.
 *
 * 2. We record the extensions we skipped. That list feeds the coverage report,
 *    so a scan of a repo that is 70% Ruby says "we did not look at 412 .rb
 *    files" instead of quietly reporting "no issues found".
 */

import { readdir, stat } from 'node:fs/promises';
import path from 'node:path';

const IGNORED_DIRECTORIES = new Set([
  '.git', '.hg', '.svn',
  'node_modules', 'bower_components', 'jspm_packages',
  'dist', 'build', 'out', 'target', 'bin', 'obj',
  'vendor', 'third_party',
  '.venv', 'venv', 'env', '__pycache__', '.tox', 'site-packages', '.mypy_cache',
  '.next', '.nuxt', '.svelte-kit', '.turbo', '.parcel-cache',
  'coverage', '.nyc_output', '.gradle', '.m2',
  '.idea', '.vscode', '.cache', '.pytest_cache',
]);

/** 2 MB. Anything larger is almost always generated, minified or a data blob. */
const MAX_FILE_BYTES = 2 * 1024 * 1024;

export interface WalkResult {
  readonly files: readonly string[];
  /** Extension -> how many files with it we passed over. Feeds the coverage report. */
  readonly skippedByExtension: ReadonlyMap<string, number>;
  readonly oversizedFiles: readonly string[];
  /** How many files --exclude removed. Printed, never silent. */
  readonly excludedCount: number;
  /**
   * Directories --exclude pruned. Counted separately because we stop walking
   * them, so we honestly do not know how many files were inside. Saying
   * "0 files excluded" after skipping a whole tree would be its own small lie.
   */
  readonly excludedDirectories: readonly string[];
}

export interface WalkOptions {
  /** Extensions we are able to parse. Everything else is counted and skipped. */
  readonly scannable: readonly string[];
  readonly maxBytes?: number;
  /** Glob-ish patterns from --exclude. */
  readonly exclude?: readonly string[];
}

/**
 * Turn a glob into a regular expression.
 *
 * Supported, deliberately a small subset:
 *   **   any number of path segments
 *   *    anything except a path separator
 *   ?    one character
 * A pattern with no wildcards and no separator (e.g. `vendor`) matches any path
 * SEGMENT with that name, which is what people mean by `--exclude=vendor`.
 *
 * Everything is matched against the path with forward slashes, so the same
 * pattern works on Windows and Unix.
 */
export function globToRegExp(pattern: string): RegExp {
  const cleaned = pattern.trim().replace(/\\/g, '/').replace(/\/+$/, '');
  const bare = !/[*?/]/.test(cleaned);

  const escaped = cleaned
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]')
    .replace(/\u0000/g, '.*');

  // `vendor` -> matches the segment anywhere in the path.
  if (bare) return new RegExp(`(^|/)${escaped}(/|$)`);
  // `src/**/test.js` or `*.spec.ts` -> match anywhere the shape fits.
  return new RegExp(`(^|/)${escaped}$|^${escaped}$`);
}

export async function collectFiles(target: string, options: WalkOptions): Promise<WalkResult> {
  const scannable = new Set(options.scannable.map((e) => e.toLowerCase()));
  const maxBytes = options.maxBytes ?? MAX_FILE_BYTES;
  const excludePatterns = (options.exclude ?? []).map(globToRegExp);
  let excludedCount = 0;
  const excludedDirectories: string[] = [];

  /** Matched against the path relative to the scan target, slashes normalised. */
  const isExcluded = (fullPath: string): boolean => {
    if (excludePatterns.length === 0) return false;
    const relative = path.relative(target, fullPath).split(path.sep).join('/');
    return excludePatterns.some((pattern) => pattern.test(relative));
  };

  const files: string[] = [];
  const skipped = new Map<string, number>();
  const oversized: string[] = [];

  const info = await stat(target);
  if (info.isFile()) {
    // An explicitly named file is always scanned - if the user pointed at it,
    // they meant it, even if it is huge or in node_modules.
    files.push(target);
    return {
      files,
      skippedByExtension: skipped,
      oversizedFiles: oversized,
      excludedCount,
      excludedDirectories,
    };
  }

  const queue: string[] = [target];
  while (queue.length > 0) {
    const dir = queue.pop();
    if (!dir) break;

    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue; // unreadable directory - permissions, broken symlink, race
    }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(entry.name)) continue;
        if (entry.name.startsWith('.') && entry.name !== '.') continue;
        // Pruning an excluded directory here saves walking its whole subtree.
        if (isExcluded(full)) {
          excludedDirectories.push(path.relative(target, full).split(path.sep).join('/'));
          continue;
        }
        queue.push(full);
        continue;
      }
      if (!entry.isFile()) continue;

      if (isExcluded(full)) {
        excludedCount++;
        continue;
      }

      const ext = path.extname(entry.name).toLowerCase();
      if (!scannable.has(ext)) {
        if (ext) skipped.set(ext, (skipped.get(ext) ?? 0) + 1);
        continue;
      }

      try {
        const fileInfo = await stat(full);
        if (fileInfo.size > maxBytes) {
          oversized.push(full);
          continue;
        }
      } catch {
        continue;
      }

      files.push(full);
    }
  }

  files.sort();
  excludedDirectories.sort();
  return {
    files,
    skippedByExtension: skipped,
    oversizedFiles: oversized,
    excludedCount,
    excludedDirectories,
  };
}
