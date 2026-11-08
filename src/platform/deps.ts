/**
 * THE DEPENDENCY CHECK: DO THE LIBRARIES THIS PROJECT PINS HAVE KNOWN ADVISORIES?
 * ==============================================================================
 *
 * Every other check reads the code a project wrote. Most of what a project
 * runs, it did not write: it is in the lockfile. This reads the versions a
 * lockfile pins and asks OSV (osv.dev, the open advisory database behind
 * OSV-Scanner) which of them have published advisories.
 *
 * WHY IT IS A SEPARATE COMMAND. It is the one check that talks to the network.
 * `defuse scan` promises nothing leaves the machine, and keeps that promise;
 * `defuse deps` sends package names and versions - never code - to api.osv.dev,
 * and says so before it does.
 *
 * WHAT IT CAN AND CANNOT CLAIM. A pinned version that matches an advisory says
 * the vulnerable code is installed. It says nothing about whether this project
 * ever calls it. Signature-grade by nature, and every result says so.
 *
 * Lockfiles it recognises but cannot read yet are listed by name, and lines it
 * could not read are counted with the reason - never silently skipped.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { signatureFinding, type Severity, type SignatureFinding } from '../core/finding.js';
import { DEPENDENCY_RULE, type DependencyReport } from './dependency-rule.js';
import { globToRegExp } from '../engine/walk.js';

export { DEPENDENCY_RULE, type DependencyReport };



export type Ecosystem = 'npm' | 'PyPI' | 'Packagist' | 'Go';

export interface Pinned {
  readonly name: string;
  readonly version: string;
  readonly ecosystem: Ecosystem;
  /** The lockfile it was read from, as found. */
  readonly file: string;
}

export interface LockfileRead {
  readonly file: string;
  readonly packages: readonly Pinned[];
  /** What was in the file but not checked, each with the reason. */
  readonly skipped: readonly string[];
}

export interface Advisory {
  readonly id: string;
  readonly summary: string;
  readonly aliases: readonly string[];
  /** OSV's own rating where the source gives one (critical/high/medium/low), else "unrated". */
  readonly severity: string;
  /** Versions the advisory says fix it, for this package. Empty when none is published. */
  readonly fixed: readonly string[];
}

export interface DependencyHit {
  readonly pkg: Pinned;
  readonly advisories: readonly Advisory[];
}

type Reader = (text: string, file: string) => { packages: Pinned[]; skipped: string[] };

/** A version that is a release, not a path, URL or branch. */
const RELEASE = /^v?\d/;

const READERS: Record<string, Reader> = {
  'package-lock.json': (text, file) => {
    const lock = JSON.parse(text) as {
      packages?: Record<string, { name?: string; version?: string; link?: boolean }>;
      dependencies?: Record<string, NpmV1Dep>;
    };
    const found: Array<[string, string]> = [];
    if (lock.packages) {
      for (const [key, p] of Object.entries(lock.packages)) {
        if (key === '' || p.link || !p.version) continue; // the project itself, or a workspace link
        found.push([p.name ?? key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length), p.version]);
      }
    } else {
      const walk = (deps: Record<string, NpmV1Dep> | undefined): void => {
        for (const [name, d] of Object.entries(deps ?? {})) {
          if (d.version) found.push([name, d.version]);
          walk(d.dependencies);
        }
      };
      walk(lock.dependencies);
    }
    return split(found, 'npm', file);
  },

  'composer.lock': (text, file) => {
    const lock = JSON.parse(text) as Record<string, Array<{ name: string; version: string }> | undefined>;
    const all = [...(lock['packages'] ?? []), ...(lock['packages-dev'] ?? [])];
    return split(all.map((p) => [p.name, p.version]), 'Packagist', file);
  },

  'requirements.txt': (text, file) => {
    const packages: Pinned[] = [];
    const skipped: string[] = [];
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.replace(/\s+#.*$/, '').trim();
      if (!line || line.startsWith('#')) continue;
      if (line.startsWith('-')) {
        skipped.push(`${line} - an option line (-r, -e, --index-url...), not followed`);
        continue;
      }
      const m = /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([^\s;,]+)$/.exec(line.split(';')[0]!.trim());
      if (m) packages.push({ name: m[1]!, version: m[2]!, ecosystem: 'PyPI', file });
      else skipped.push(`${line} - not pinned with ==, so the installed version is unknown`);
    }
    return { packages, skipped };
  },

  'go.mod': (text, file) => {
    const found: Array<[string, string]> = [];
    let inRequire = false;
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.replace(/\/\/.*$/, '').trim();
      if (/^require\s*\($/.test(line)) inRequire = true;
      else if (inRequire && line === ')') inRequire = false;
      else {
        const m = (inRequire ? /^(\S+)\s+(\S+)$/ : /^require\s+(\S+)\s+(\S+)$/).exec(line);
        if (m) found.push([m[1]!, m[2]!]);
      }
    }
    const result = split(found, 'Go', file);
    if (/^replace\b/m.test(text)) {
      result.skipped.push('replace directives - not applied, so a replaced module is checked at its required version');
    }
    return result;
  },
};

interface NpmV1Dep {
  version?: string;
  dependencies?: Record<string, NpmV1Dep>;
}

function split(found: ReadonlyArray<readonly [string, string]>, ecosystem: Ecosystem, file: string) {
  const packages: Pinned[] = [];
  const skipped: string[] = [];
  for (const [name, version] of found) {
    if (RELEASE.test(version)) packages.push({ name, version, ecosystem, file });
    else skipped.push(`${name} ${version} - not a release version (a path, URL or branch)`);
  }
  return { packages, skipped };
}

/** Recognised by name, not read yet. Listed in the output, never ignored in silence. */
export const UNREAD_LOCKFILES: ReadonlySet<string> = new Set([
  'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json', 'Pipfile.lock', 'poetry.lock', 'uv.lock',
  'Cargo.lock', 'Gemfile.lock', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'gradle.lockfile',
  'packages.lock.json',
]);

const SKIP_DIRS = new Set(['node_modules', 'vendor', '.git', '.venv', 'venv', '__pycache__']);

/** Parse one lockfile by its file name. Null when the name is not one this reads. */
export function readLockfile(file: string, text: string): LockfileRead | null {
  const reader = READERS[path.basename(file)];
  if (!reader) return null;
  try {
    return { file, ...reader(text, file) };
  } catch (error) {
    return { file, packages: [], skipped: [`the whole file - it did not parse: ${(error as Error).message}`] };
  }
}

/** Every lockfile under `target`, read; plus the recognised ones that are not. `exclude` means what scan --exclude means. */
export function findLockfiles(target: string, exclude: readonly string[] = []): { read: LockfileRead[]; unread: string[] } {
  const read: LockfileRead[] = [];
  const unread: string[] = [];
  const patterns = exclude.map(globToRegExp);
  const visit = (p: string): void => {
    const relative = path.relative(target, p).split(path.sep).join('/');
    if (relative && patterns.some((re) => re.test(relative))) return;
    if (statSync(p).isDirectory()) {
      for (const entry of readdirSync(p)) if (!SKIP_DIRS.has(entry)) visit(path.join(p, entry));
      return;
    }
    const name = path.basename(p);
    if (UNREAD_LOCKFILES.has(name)) unread.push(p);
    else if (READERS[name]) read.push(readLockfile(p, readFileSync(p, 'utf8'))!);
  };
  visit(target);
  return { read, unread };
}

const OSV = 'https://api.osv.dev/v1';
const BATCH = 1000; // OSV's own limit per querybatch call

/**
 * Ask OSV about every pinned package. Sends name, ecosystem and version only.
 * `fetchImpl` is injectable so the tests can run without a network.
 */
export async function queryOsv(
  pinned: readonly Pinned[],
  fetchImpl: typeof fetch = fetch,
): Promise<{ hits: DependencyHit[]; checked: number; incomplete: string[] }> {
  const unique = [...new Map(pinned.map((p) => [`${p.ecosystem}|${p.name}|${p.version}`, p])).values()];
  const call = async (url: string, body?: unknown): Promise<unknown> => {
    const signal = AbortSignal.timeout(30_000);
    const response = await fetchImpl(
      url,
      body
        ? { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' }, signal }
        : { signal },
    );
    if (!response.ok) throw new Error(`OSV answered ${response.status} for ${url}`);
    return response.json();
  };

  const idsPer: string[][] = [];
  const incomplete: string[] = [];
  for (let i = 0; i < unique.length; i += BATCH) {
    const chunk = unique.slice(i, i + BATCH);
    const answer = (await call(`${OSV}/querybatch`, {
      queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })),
    })) as { results?: Array<{ vulns?: Array<{ id: string }>; next_page_token?: string }> };
    if (!Array.isArray(answer.results) || answer.results.length !== chunk.length) {
      throw new Error('OSV returned a batch answer of the wrong shape - nothing was checked');
    }
    answer.results.forEach((r, j) => {
      idsPer.push((r.vulns ?? []).map((v) => v.id));
      if (r.next_page_token) incomplete.push(`${chunk[j]!.name} ${chunk[j]!.version} - more advisories exist than one page`);
    });
  }

  // ponytail: one GET per distinct advisory, all at once; add a concurrency cap if OSV starts refusing.
  const details = new Map<string, OsvVuln>();
  await Promise.all(
    [...new Set(idsPer.flat())].map(async (id) => details.set(id, (await call(`${OSV}/vulns/${encodeURIComponent(id)}`)) as OsvVuln)),
  );

  const hits = unique.flatMap((pkg, i): DependencyHit[] => {
    const ids = idsPer[i]!;
    return ids.length ? [{ pkg, advisories: mergeSame(ids.map((id) => toAdvisory(details.get(id)!, pkg))) }] : [];
  });
  return { hits, checked: unique.length, incomplete };
}


const RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

/**
 * The whole check for `scan --deps`: find lockfiles, ask OSV, and return one
 * signature-based finding per affected package, located on its lockfile line.
 * `display` turns an absolute path into the one the report shows.
 */
export async function checkDependencies(
  target: string,
  display: (file: string) => string,
  exclude: readonly string[] = [],
  fetchImpl: typeof fetch = fetch,
): Promise<{ findings: SignatureFinding[]; report: DependencyReport }> {
  const { read, unread } = findLockfiles(target, exclude);
  const pinned = read.flatMap((r) => r.packages);
  const answer = pinned.length ? await queryOsv(pinned, fetchImpl) : { hits: [], checked: 0, incomplete: [] };
  const texts = new Map<string, string[]>();
  const linesOf = (file: string): string[] => {
    if (!texts.has(file)) texts.set(file, readFileSync(file, 'utf8').split(/\r?\n/));
    return texts.get(file)!;
  };
  return {
    findings: answer.hits.map((h) => dependencyFinding(h, linesOf(h.pkg.file), display(h.pkg.file))),
    report: {
      source: 'api.osv.dev',
      checkedAt: new Date().toISOString(),
      read: read.map((r) => ({ file: display(r.file), packages: r.packages.length, skipped: r.skipped })),
      notRead: unread.map(display),
      checked: answer.checked,
      incomplete: answer.incomplete,
    },
  };
}

export function dependencyFinding(hit: DependencyHit, lines: readonly string[], file: string): SignatureFinding {
  const { pkg, advisories } = hit;
  // ponytail: first line naming the package (with its version, if one does); a lockfile has no AST to point at.
  const named = (needle: string) => lines.findIndex((l) => l.includes(needle));
  const at = [`node_modules/${pkg.name}"`, `"${pkg.name}"`, pkg.name]
    .map((n) => {
      const withVersion = lines.findIndex((l) => l.includes(n) && l.includes(pkg.version));
      return withVersion >= 0 ? withVersion : named(n);
    })
    .find((i) => i >= 0) ?? 0;
  const text = (lines[at] ?? '').trim();
  const rated = advisories.filter((a) => a.severity !== 'unrated');
  const top = rated.reduce((best, a) => (RANK[a.severity]! > RANK[best]! ? a.severity : best), 'low');
  const severity = (rated.length ? top : 'medium') as Severity;
  const ids = advisories.map((a) => [a.id, ...a.aliases.filter((x) => x.startsWith('CVE-'))].join('/'));
  const fixed = [...new Set(advisories.flatMap((a) => a.fixed))];
  return signatureFinding({
    ruleId: DEPENDENCY_RULE.id,
    ruleName: DEPENDENCY_RULE.name,
    cwe: 'CWE-1395',
    owasp: DEPENDENCY_RULE.owasp,
    severity,
    message:
      `${pkg.name} ${pkg.version} has ${advisories.length} published advisor${advisories.length === 1 ? 'y' : 'ies'}` +
      (fixed.length ? ` - fixed versions: ${fixed.join(', ')}` : ' - no fixed version published'),
    location: {
      file,
      startLine: at + 1,
      startColumn: 1,
      endLine: at + 1,
      endColumn: (lines[at]?.length ?? 0) + 1,
      astNodeType: 'lockfile-entry',
      astNodePath: `${pkg.ecosystem} lockfile`,
      snippet: text.length > 160 ? `${text.slice(0, 159)}…` : text,
    },
    reasoning:
      `osv.dev lists ${ids.join(', ')} for ${pkg.ecosystem} ${pkg.name} ${pkg.version}: ` +
      advisories.map((a) => `${a.summary} (${a.severity})`).join('; ') +
      '.' +
      (rated.length
        ? ''
        : ' None of these advisories carries a severity rating, so medium is a placeholder, not an assessment.'),
    limitations: DEPENDENCY_RULE.limitations,
  });
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  database_specific?: { severity?: string };
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ type?: string; events?: Array<{ fixed?: string }> }>;
  }>;
}

/**
 * One flaw, one entry. OSV holds the same CVE once per database (GHSA-, GO-,
 * PYSEC-...), so a project would otherwise see one bug listed two or three
 * times. Entries naming each other, or sharing an alias, are folded into one;
 * a rated entry wins over an unrated one, and every id is kept in `aliases`.
 */
export function mergeSame(advisories: readonly Advisory[]): Advisory[] {
  const groups: Advisory[][] = [];
  for (const a of advisories) {
    const names = new Set([a.id, ...a.aliases]);
    const group = groups.find((g) => g.some((b) => b.id === a.id || names.has(b.id) || b.aliases.some((x) => names.has(x))));
    if (group) group.push(a);
    else groups.push([a]);
  }
  return groups.map((g) => {
    const lead = g.find((a) => a.severity !== 'unrated') ?? g[0]!;
    const ids = new Set(g.flatMap((a) => [a.id, ...a.aliases]));
    ids.delete(lead.id);
    return { ...lead, aliases: [...ids], fixed: [...new Set(g.flatMap((a) => a.fixed))] };
  });
}

function toAdvisory(v: OsvVuln, pkg: Pinned): Advisory {
  const fixed = (v.affected ?? [])
    .filter((a) => a.package?.name === pkg.name && a.package?.ecosystem === pkg.ecosystem)
    // GIT ranges name commits, not versions anyone can install.
    .flatMap((a) => (a.ranges ?? []).filter((r) => r.type !== 'GIT'))
    .flatMap((r) => (r.events ?? []).flatMap((e) => (e.fixed ? [e.fixed] : [])));
  const rated = v.database_specific?.severity?.toLowerCase().replace('moderate', 'medium');
  return {
    id: v.id,
    summary: v.summary ?? v.details?.split('\n')[0]?.slice(0, 160) ?? '(no summary published)',
    aliases: v.aliases ?? [],
    severity: rated && ['critical', 'high', 'medium', 'low'].includes(rated) ? rated : 'unrated',
    fixed: [...new Set(fixed)],
  };
}
