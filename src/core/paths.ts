/**
 * PATH HELPERS WITH NO PLATFORM ATTACHED
 *
 * `node:path` was the last thing standing between the analysis code and a
 * browser. The import graph needs to join and normalise paths, and Node's
 * version of that pulls in a runtime the browser does not have.
 *
 * These are the four operations the resolver actually uses, written in plain
 * JavaScript over forward slashes. Windows paths are normalised on the way in,
 * so `C:\\src\\db.ts` and `C:/src/db.ts` compare equal - which matters, because
 * a path that fails to match is an import edge silently not resolved.
 */

/** Backslashes to forward slashes. Everything else here assumes this ran. */
export function toPosix(filePath: string): string {
  return filePath.replace(/\\/g, '/');
}

/** Collapse `.` and `..` segments. Keeps a leading `/` or a `C:` drive. */
export function normalizePath(filePath: string): string {
  const posix = toPosix(filePath);
  const absolute = posix.startsWith('/');
  const parts: string[] = [];

  for (const segment of posix.split('/')) {
    if (!segment || segment === '.') continue;
    if (segment === '..') {
      const last = parts[parts.length - 1];
      if (parts.length > 0 && last !== '..') parts.pop();
      else if (!absolute) parts.push('..');
      continue;
    }
    parts.push(segment);
  }
  return (absolute ? '/' : '') + parts.join('/');
}

export function dirnameOf(filePath: string): string {
  const posix = toPosix(filePath);
  const cut = posix.lastIndexOf('/');
  if (cut < 0) return '';
  return cut === 0 ? '/' : posix.slice(0, cut);
}

export function basenameOf(filePath: string): string {
  const posix = toPosix(filePath);
  return posix.slice(posix.lastIndexOf('/') + 1);
}

export function joinPath(...parts: readonly string[]): string {
  return normalizePath(parts.filter(Boolean).join('/'));
}

/** Resolve a relative specifier against a directory. */
export function resolveFrom(directory: string, relative: string): string {
  const posix = toPosix(relative);
  if (posix.startsWith('/')) return normalizePath(posix);
  return normalizePath(`${toPosix(directory)}/${posix}`);
}
