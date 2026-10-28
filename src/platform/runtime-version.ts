/**
 * THE RUNTIME VERSION CHECK: WHICH PHP DOES THIS PROJECT SAY IT RUNS ON?
 * =====================================================================
 *
 * Every other check in Defuse reads the code a project contains. PHP2Shell
 * (CVE-2026-109618 / CVE-2026-109619, October 2026) was a reminder that perfect
 * code on PHP 8.2.20 is still a server an attacker can take over: the bug was
 * in PHP itself. Reading code cannot find that. Reading the version the
 * project declares can - Dockerfiles, compose files, composer.json and
 * `.php-version` all say which PHP the project expects.
 *
 * WHAT IT CAN AND CANNOT CLAIM. A declaration is not the server. A Dockerfile
 * that says 8.2.20 may have been replaced, and one that says `php:8.2-apache`
 * gets whatever 8.2 release was current when the image was built. So every
 * result here is signature-based - a match against a declaration, never a
 * proof about what runs - and every message says which file it read and how
 * old the facts behind it are (php-facts.ts).
 *
 * Platform-free like the rest of the analysis: it takes text and returns
 * findings, and the walker in engine/ decides which files to hand it.
 */

import { signatureFinding, type Severity, type SignatureFinding } from '../core/finding.js';
import { isTestPath } from '../rules/lib/strings.js';
import {
  PHP_ADVISORIES,
  PHP_END_OF_LIFE,
  PHP_FACTS_CHECKED,
  PHP_SECURITY_UNTIL,
  type PhpAdvisory,
} from './php-facts.js';

export const RUNTIME_VERSION_RULE = {
  id: 'runtime-version',
  name: 'PHP version with a known critical flaw or no security support',
  owasp: 'A03:2025 Software Supply Chain Failures',
  explanation:
    'A program is only as safe as the language runtime under it. When the PHP version a project ' +
    'runs on has a known critical flaw, or no longer gets security fixes at all, an attacker can ' +
    'break in without any mistake in the project\'s own code. The fix is an upgrade, not a code change.',
  limitations:
    'Reads only: FROM lines that use the official `php` Docker image (Dockerfile, Dockerfile.*, *.dockerfile), ' +
    '`image:` lines in docker-compose and compose files, composer.json (`require.php` and `config.platform.php`) ' +
    'and `.php-version`. NOT read: other images that contain PHP (bitnami, webdevops, a distribution image with ' +
    'PHP installed by apt or apk), CI matrices, php.ini settings, or the running server - a declaration is not ' +
    'the server, so confirm with `php -v` where the code runs. Linux distributions often backport security ' +
    'fixes without changing the version number, so an old number in a distribution package may be patched; ' +
    'this check knows the official numbers only. The advisory list holds critical, exploited issues only and ' +
    'is not a vulnerability database. Runs in the command line and the client report, not the browser page.',
} as const;

/** One file the walker handed over. `path` is the path a reader should see. */
export interface RuntimeInputFile {
  readonly path: string;
  readonly text: string;
}

/** A version a project declares, with what the facts table says about it. */
export interface DeclaredRuntime {
  readonly file: string;
  readonly line: number;
  /** Where it came from, in words: "Dockerfile FROM", "composer.json require". */
  readonly source: string;
  /** Exactly as written: `php:8.2-apache`, `^7.4 || ^8.0`, `8.2.20`. */
  readonly declared: string;
  /** What Defuse concluded, in one plain sentence. */
  readonly status: string;
}

export interface RuntimeCheckResult {
  readonly findings: readonly SignatureFinding[];
  readonly declared: readonly DeclaredRuntime[];
  /** Things a reader must know that are not findings - a gap is never silent. */
  readonly notes: readonly string[];
  /** The date the facts table was checked against php.net. */
  readonly factsChecked: string;
}

export interface RuntimeCheckOptions {
  /** ISO date of the scan. End of support is judged against this, not the table date. */
  readonly today: string;
  /** How many PHP source files the scan read - a project with none needs no PHP version. */
  readonly phpFilesScanned: number;
}

/* ------------------------------------------------------------ versions -- */

type Version = readonly [number, number, number];

const cmpVersion = (a: Version, b: Version): number => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
const branchOf = (v: Version): string => `${v[0]}.${v[1]}`;
const branchVersion = (branch: string): Version => {
  const [maj, min] = branch.split('.').map(Number);
  return [maj ?? 0, min ?? 0, 0];
};
const cmpBranch = (a: string, b: string): number => cmpVersion(branchVersion(a), branchVersion(b));

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
/** `2026-12-31` -> `31 Dec 2026`. */
export function readableDate(iso: string): string {
  const [y, m, d] = iso.split('-').map(Number);
  return `${d} ${MONTHS[(m ?? 1) - 1]} ${y}`;
}
const daysBetween = (from: string, to: string): number =>
  Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / 86_400_000);

/** Every branch the table knows, oldest first. */
const KNOWN_BRANCHES = [...Object.keys(PHP_END_OF_LIFE), ...Object.keys(PHP_SECURITY_UNTIL)].sort(cmpBranch);
const NEWEST_KNOWN = KNOWN_BRANCHES[KNOWN_BRANCHES.length - 1] ?? '8.5';
const OLDEST_KNOWN = KNOWN_BRANCHES[0] ?? '5.0';

type BranchStatus =
  | { readonly kind: 'supported'; readonly until: string }
  | { readonly kind: 'eol'; readonly since: string | null }
  | { readonly kind: 'unknown' };

function branchStatus(branch: string, today: string): BranchStatus {
  const until = PHP_SECURITY_UNTIL[branch];
  if (until) return today > until ? { kind: 'eol', since: until } : { kind: 'supported', until };
  const since = PHP_END_OF_LIFE[branch];
  if (since) return { kind: 'eol', since };
  if (cmpBranch(branch, OLDEST_KNOWN) < 0) return { kind: 'eol', since: null };
  return { kind: 'unknown' };
}

/** Branches still supported on the day of the scan, newest first. */
const supportedBranches = (today: string): string[] =>
  Object.keys(PHP_SECURITY_UNTIL)
    .filter((b) => branchStatus(b, today).kind === 'supported')
    .sort((a, b) => cmpBranch(b, a));

/** How an advisory bears on one branch: fixed from a release, never fixed, or not affected. */
function advisoryFor(
  adv: PhpAdvisory,
  branch: string,
): { readonly fixedIn: string } | { readonly noFix: true } | null {
  const fixed = adv.fixedIn[branch];
  if (fixed) return { fixedIn: fixed };
  const fixedBranches = Object.keys(adv.fixedIn).sort(cmpBranch);
  const oldestFixed = fixedBranches[0];
  if (oldestFixed && cmpBranch(branch, adv.oldestAffected) >= 0 && cmpBranch(branch, oldestFixed) < 0) {
    return { noFix: true };
  }
  return null;
}

const parseExact = (s: string): Version | null => {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(s);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
};

/* --------------------------------------------------------- what is said -- */

/**
 * What one declaration pins down. `exact` is a full version; `branch` is a
 * floating tag that gets whatever release of the branch was current when it
 * was built; `unknown` is a declaration whose version cannot be read.
 */
type Pinned =
  | { readonly kind: 'exact'; readonly version: Version; readonly prerelease: boolean }
  | { readonly kind: 'branch'; readonly branch: string; readonly how: string }
  | { readonly kind: 'unknown'; readonly why: string };

/** The tag of the official image: `8.2.20-apache`, `8.2-fpm`, `8-cli`, `apache`, none. */
function pinnedByTag(tag: string | null, today: string): Pinned {
  if (tag === null || tag === '' || tag === 'latest' || /^[a-z]/i.test(tag)) {
    const newest = supportedBranches(today)[0];
    return newest
      ? { kind: 'branch', branch: newest, how: `a tag with no version number, which follows the newest release (${newest} today)` }
      : { kind: 'unknown', why: 'a tag with no version number, and no branch in the table is still supported' };
  }
  const m = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?((?:rc|alpha|beta)\d*)?(?:-|$)/i.exec(tag);
  if (!m) return { kind: 'unknown', why: `a tag Defuse cannot read a version from (\`${tag}\`)` };
  const [maj, min, patch, pre] = [m[1], m[2], m[3], m[4]];
  if (min !== undefined && patch !== undefined) {
    return { kind: 'exact', version: [Number(maj), Number(min), Number(patch)], prerelease: pre !== undefined };
  }
  if (min !== undefined) {
    return { kind: 'branch', branch: `${maj}.${min}`, how: `a branch tag, which follows the newest ${maj}.${min} release` };
  }
  const newestOfMajor = supportedBranches(today).find((b) => b.startsWith(`${maj}.`));
  return newestOfMajor
    ? { kind: 'branch', branch: newestOfMajor, how: `a major-version tag, which follows the newest ${maj}.x release (${newestOfMajor} today)` }
    : { kind: 'unknown', why: `a major-version tag (\`${tag}\`) with no supported branch in the table` };
}

interface Declaration {
  readonly file: string;
  readonly line: number;
  readonly column: number;
  readonly text: string;
  readonly lineText: string;
  readonly source: string;
  /** "the Dockerfile on line 3" - how a message refers to it. */
  readonly where: string;
  readonly nodeType: string;
  readonly pinned: Pinned | null;
  /** A composer version range; only one of `pinned` / `range` is set. */
  readonly range?: string;
}

/* ------------------------------------------------------------- readers -- */

const isOfficialPhpImage = (name: string): boolean =>
  name === 'php' || name === 'docker.io/php' || /(^|\/)library\/php$/.test(name);

/** `php:8.2-apache@sha256:...` -> name, tag and digest. */
function splitImage(ref: string): { name: string; tag: string | null; digest: string | null } {
  const at = ref.indexOf('@');
  const digest = at >= 0 ? ref.slice(at + 1) : null;
  const base = at >= 0 ? ref.slice(0, at) : ref;
  const slash = base.lastIndexOf('/');
  const colon = base.lastIndexOf(':');
  if (colon > slash) return { name: base.slice(0, colon).toLowerCase(), tag: base.slice(colon + 1), digest };
  return { name: base.toLowerCase(), tag: null, digest };
}

function readImage(
  file: string,
  lineNo: number,
  column: number,
  lineText: string,
  ref: string,
  source: string,
  where: string,
  nodeType: string,
  today: string,
): Declaration | null {
  if (/\$/.test(ref)) {
    const { name } = splitImage(ref.replace(/\$\{?\w+(?::-[^}]*)?\}?/g, 'x'));
    if (!isOfficialPhpImage(name)) return null;
    return {
      file, line: lineNo, column, text: ref, lineText, source, where, nodeType,
      pinned: { kind: 'unknown', why: 'a version set by a build argument with no default value in the file' },
    };
  }
  const { name, tag, digest } = splitImage(ref);
  if (!isOfficialPhpImage(name)) return null;
  const pinned: Pinned =
    tag === null && digest !== null
      ? { kind: 'unknown', why: 'an image pinned by digest only, which does not show the version' }
      : pinnedByTag(tag, today);
  return { file, line: lineNo, column, text: ref, lineText, source, where, nodeType, pinned };
}

function readDockerfile(file: RuntimeInputFile, today: string): Declaration[] {
  const out: Declaration[] = [];
  const args = new Map<string, string>();
  const stages = new Set<string>();
  file.text.split(/\r?\n/).forEach((lineText, index) => {
    const arg = /^\s*ARG\s+(\w+)=["']?([^"'\s]*)["']?\s*$/i.exec(lineText);
    if (arg?.[1] && arg[2] !== undefined) args.set(arg[1], arg[2]);
    const from = /^(\s*FROM\s+(?:--\S+\s+)*)(\S+)(?:\s+AS\s+(\S+))?/i.exec(lineText);
    if (!from?.[2]) return;
    const raw = from[2];
    const ref = raw.replace(/\$\{(\w+)(?::-([^}]*))?\}|\$(\w+)/g, (whole, a, dflt, b) => {
      const value = args.get(a ?? b);
      return value !== undefined && value !== '' ? value : dflt !== undefined ? dflt : whole;
    });
    if (stages.has(ref.toLowerCase())) return; // an earlier build stage, not an image
    if (from[3]) stages.add(from[3].toLowerCase());
    const declaration = readImage(
      file.path, index + 1, (from[1]?.length ?? 0) + 1, lineText, ref,
      'Dockerfile FROM', `${file.path} on line ${index + 1}`, 'dockerfile-from', today,
    );
    if (declaration) out.push(declaration);
  });
  return out;
}

function readCompose(file: RuntimeInputFile, today: string): Declaration[] {
  const out: Declaration[] = [];
  file.text.split(/\r?\n/).forEach((lineText, index) => {
    const m = /^(\s*image:\s*)["']?([^"'\s#]+)["']?/.exec(lineText);
    if (!m?.[2]) return;
    const declaration = readImage(
      file.path, index + 1, (m[1]?.length ?? 0) + 1, lineText, m[2],
      'compose image', `${file.path} on line ${index + 1}`, 'compose-image', today,
    );
    if (declaration) out.push(declaration);
  });
  return out;
}

/** The 1-based line holding `"php": "<value>"`, searching from a given line. */
function lineOfPhpKey(lines: readonly string[], value: string, from = 0): number {
  const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`"php"\\s*:\\s*"${escaped}"`);
  for (let i = from; i < lines.length; i++) if (re.test(lines[i] ?? '')) return i + 1;
  return 1;
}

function readComposerJson(file: RuntimeInputFile, notes: string[]): Declaration[] {
  let json: unknown;
  try {
    json = JSON.parse(file.text);
  } catch {
    notes.push(`${file.path} is not valid JSON, so the PHP version it declares could not be read.`);
    return [];
  }
  const obj = (json ?? {}) as { require?: Record<string, unknown>; config?: { platform?: Record<string, unknown> } };
  const lines = file.text.split(/\r?\n/);
  const out: Declaration[] = [];
  const required = obj.require?.['php'];
  if (typeof required === 'string') {
    const line = lineOfPhpKey(lines, required);
    out.push({
      file: file.path, line, column: 1, text: required, lineText: lines[line - 1] ?? '',
      source: 'composer.json require', where: `${file.path} (\`require\`, line ${line})`,
      nodeType: 'composer-require', pinned: null, range: required,
    });
  }
  const platform = obj.config?.platform?.['php'];
  if (typeof platform === 'string') {
    const configLine = Math.max(0, lines.findIndex((l) => /"platform"\s*:/.test(l)));
    const line = lineOfPhpKey(lines, platform, configLine);
    const version = parseExact(platform.trim());
    const branch = /^(\d+)\.(\d+)$/.exec(platform.trim());
    out.push({
      file: file.path, line, column: 1, text: platform, lineText: lines[line - 1] ?? '',
      source: 'composer.json config.platform', where: `${file.path} (\`config.platform\`, line ${line})`,
      nodeType: 'composer-platform',
      pinned: version
        ? { kind: 'exact', version, prerelease: false }
        : branch
          ? { kind: 'branch', branch: `${branch[1]}.${branch[2]}`, how: 'a branch number with no release number' }
          : { kind: 'unknown', why: `a platform version Defuse cannot read (\`${platform}\`)` },
    });
  }
  return out;
}

function readPhpVersionFile(file: RuntimeInputFile): Declaration[] {
  const lines = file.text.split(/\r?\n/);
  const index = lines.findIndex((l) => l.trim() !== '' && !l.trim().startsWith('#'));
  if (index < 0) return [];
  const raw = (lines[index] ?? '').trim();
  const value = raw.replace(/^php[-@]?/i, '');
  const version = parseExact(value);
  const branch = /^(\d+)\.(\d+)$/.exec(value);
  return [{
    file: file.path, line: index + 1, column: 1, text: raw, lineText: raw,
    source: '.php-version', where: `${file.path}`, nodeType: 'php-version-file',
    pinned: version
      ? { kind: 'exact', version, prerelease: false }
      : branch
        ? { kind: 'branch', branch: `${branch[1]}.${branch[2]}`, how: 'a branch number with no release number' }
        : { kind: 'unknown', why: `a value Defuse cannot read a version from (\`${raw}\`)` },
  }];
}

/** Which reader a file needs, by its name alone. Exported for the walker. */
export function runtimeFileKind(fileName: string): 'dockerfile' | 'compose' | 'composer' | 'php-version' | null {
  const name = fileName.toLowerCase();
  if (name === 'dockerfile' || name.startsWith('dockerfile.') || name.endsWith('.dockerfile')) return 'dockerfile';
  if (/^(docker-)?compose(\.[\w-]+)?\.ya?ml$/.test(name)) return 'compose';
  if (name === 'composer.json') return 'composer';
  if (name === '.php-version') return 'php-version';
  return null;
}

/* --------------------------------------------------------- version ranges -- */

type Comparison = { readonly op: '>=' | '>' | '<' | '<=' | '=' | '!='; readonly v: Version };

/**
 * A composer version constraint, as alternatives of conditions - `^7.4 || ^8.0`
 * is two alternatives. Null when any part cannot be read: an unreadable range
 * is reported as unreadable, never guessed at.
 */
export function parseComposerRange(constraint: string): Comparison[][] | null {
  const alternatives = constraint.split(/\s*\|\|?\s*/).filter((a) => a.trim() !== '');
  if (alternatives.length === 0) return null;
  const out: Comparison[][] = [];
  for (const alternative of alternatives) {
    const hyphen = /^\s*(\S+)\s+-\s+(\S+)\s*$/.exec(alternative);
    if (hyphen?.[1] && hyphen[2]) {
      const low = partial(hyphen[1]);
      const high = partial(hyphen[2]);
      if (!low || !high) return null;
      out.push([
        { op: '>=', v: low.v },
        high.parts === 3 ? { op: '<=', v: high.v } : { op: '<', v: bump(high.v, high.parts - 1) },
      ]);
      continue;
    }
    const conditions: Comparison[] = [];
    for (const token of alternative.trim().split(/[\s,]+/)) {
      const parsed = condition(token);
      if (!parsed) return null;
      conditions.push(...parsed);
    }
    out.push(conditions);
  }
  return out;
}

/** `8.2` -> [8,2,0] with 2 parts given. */
function partial(text: string): { v: Version; parts: number } | null {
  const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.\d+)?$/.exec(text.replace(/@\w+$/, '').replace(/-[\w.]+$/, ''));
  if (!m) return null;
  const parts = m[3] !== undefined ? 3 : m[2] !== undefined ? 2 : 1;
  return { v: [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0)], parts };
}

/** The next version up at a given position: bump([8,2,0], 1) is 8.3.0. */
function bump(v: Version, position: number): Version {
  if (position <= 0) return [v[0] + 1, 0, 0];
  if (position === 1) return [v[0], v[1] + 1, 0];
  return [v[0], v[1], v[2] + 1];
}

function condition(token: string): Comparison[] | null {
  if (token === '*' || token === '') return [];
  const wildcard = /^v?(\d+)(?:\.(\d+))?\.\*$/.exec(token);
  if (wildcard) {
    const v: Version = [Number(wildcard[1]), Number(wildcard[2] ?? 0), 0];
    return [{ op: '>=', v }, { op: '<', v: bump(v, wildcard[2] === undefined ? 0 : 1) }];
  }
  const m = /^(\^|~|>=|<=|>|<|==?|!=)?(.+)$/.exec(token);
  if (!m?.[2]) return null;
  const p = partial(m[2]);
  if (!p) return null;
  switch (m[1]) {
    case '^':
      return [{ op: '>=', v: p.v }, { op: '<', v: bump(p.v, 0) }];
    case '~':
      return [{ op: '>=', v: p.v }, { op: '<', v: bump(p.v, p.parts >= 3 ? 1 : 0) }];
    case '>=': case '>': case '<': case '<=': case '!=':
      return [{ op: m[1], v: p.v }];
    default:
      // A bare `8.2` is read as the whole 8.2 branch, `8` as all of 8.x.
      return p.parts === 3
        ? [{ op: '=', v: p.v }]
        : [{ op: '>=', v: p.v }, { op: '<', v: bump(p.v, p.parts - 1) }];
  }
}

function satisfies(v: Version, range: readonly (readonly Comparison[])[]): boolean {
  return range.some((conditions) =>
    conditions.every(({ op, v: w }) => {
      const c = cmpVersion(v, w);
      return op === '>=' ? c >= 0 : op === '>' ? c > 0 : op === '<' ? c < 0 : op === '<=' ? c <= 0 : op === '=' ? c === 0 : c !== 0;
    }),
  );
}

/** Whether any release of a branch fits the range. Tried at both ends of the branch. */
const branchAllowed = (branch: string, range: readonly (readonly Comparison[])[]): boolean => {
  const [maj, min] = branchVersion(branch);
  return satisfies([maj, min, 0], range) || satisfies([maj, min, 999], range);
};

/* -------------------------------------------------------------- verdicts -- */

interface Verdict {
  readonly severity: Severity | null;
  readonly cwe: string;
  readonly message: string;
  readonly reasoning: string;
  readonly status: string;
}

const confirmHint = 'Defuse read the version this file declares; the server can run a different one, so confirm with `php -v` where the code runs.';

function exactVerdict(d: Declaration, v: Version, prerelease: boolean, today: string): Verdict {
  const version = v.join('.') + (prerelease ? ' (a pre-release)' : '');
  const branch = branchOf(v);
  const status = branchStatus(branch, today);
  if (status.kind === 'unknown') {
    return {
      severity: null, cwe: 'CWE-1395', message: '', reasoning: '',
      status: `PHP ${version}: branch ${branch} is newer than Defuse's table (checked ${readableDate(PHP_FACTS_CHECKED)}), so nothing is known about it`,
    };
  }
  const hits = PHP_ADVISORIES.map((adv) => ({ adv, bearing: advisoryFor(adv, branch) })).filter(
    (h): h is { adv: PhpAdvisory; bearing: NonNullable<ReturnType<typeof advisoryFor>> } =>
      h.bearing !== null &&
      ('noFix' in h.bearing || cmpVersion(v, parseExact(h.bearing.fixedIn) ?? [0, 0, 0]) < 0),
  );
  const lines: string[] = [];
  for (const { adv, bearing } of hits) {
    lines.push(
      'fixedIn' in bearing
        ? `PHP ${version} is older than ${bearing.fixedIn}, the release that fixes ${adv.cves.join(' and ')} ` +
            `("${adv.name}", ${readableDate(adv.published)}): ${adv.impact}. Upgrade to ${bearing.fixedIn} or later.`
        : `PHP ${version} is affected by ${adv.cves.join(' and ')} ("${adv.name}", ${readableDate(adv.published)}): ` +
            `${adv.impact}. No official ${branch} release has the fix; some Linux distributions ship their own patched builds.`,
    );
  }
  if (status.kind === 'eol') {
    lines.push(
      status.since
        ? `Branch ${branch} has had no security fixes since ${readableDate(status.since)}; move to a supported branch (${supportedBranches(today).slice().reverse().join(', ')}).`
        : `Branch ${branch} went out of support long before any date in Defuse's table.`,
    );
  }
  if (lines.length === 0) {
    return {
      severity: null, cwe: 'CWE-1395', message: '', reasoning: '',
      status:
        `PHP ${version}: no critical advisory in Defuse's table` +
        (status.kind === 'supported' ? `; security support until ${readableDate(status.until)}` : ''),
    };
  }
  const first = hits[0];
  const message = first
    ? 'fixedIn' in first.bearing
      ? `PHP ${version} (${d.source}) is missing the ${first.adv.name} fix - ${first.bearing.fixedIn} has it`
      : `PHP ${version} (${d.source}) is out of support - no official release has the ${first.adv.name} fix`
    : `PHP ${version} (${d.source}) gets no security fixes any more`;
  return {
    severity: hits.length > 0 ? 'critical' : 'high',
    cwe: hits.length > 0 ? 'CWE-1395' : 'CWE-1104',
    message,
    reasoning: `${d.where} declares PHP ${version}. ${lines.join(' ')} ${confirmHint}`,
    status: hits.length > 0 ? `PHP ${version}: ${hits.map((h) => h.adv.name).join(', ')} not fixed` : `PHP ${version}: out of support`,
  };
}

function branchVerdict(d: Declaration, branch: string, how: string, today: string): Verdict {
  const status = branchStatus(branch, today);
  if (status.kind === 'unknown') {
    return {
      severity: null, cwe: 'CWE-1395', message: '', reasoning: '',
      status: `PHP ${branch}: newer than Defuse's table (checked ${readableDate(PHP_FACTS_CHECKED)}), so nothing is known about it`,
    };
  }
  if (status.kind === 'eol') {
    // Every build of an out-of-support branch is the same answer as a pinned one.
    const noFix = PHP_ADVISORIES.filter((adv) => advisoryFor(adv, branch) !== null);
    const since = status.since ? ` since ${readableDate(status.since)}` : '';
    return {
      severity: noFix.length > 0 ? 'critical' : 'high',
      cwe: noFix.length > 0 ? 'CWE-1395' : 'CWE-1104',
      message: `PHP ${branch} (${d.source}) is out of support${noFix.length > 0 ? ` - no official release has the ${noFix[0]?.name} fix` : ''}`,
      reasoning:
        `${d.where} declares \`${d.text}\` - ${how}. Branch ${branch} has had no security fixes${since}` +
        (noFix.length > 0
          ? `, and no official ${branch} release will fix ${noFix.map((a) => `${a.cves.join(' and ')} ("${a.name}": ${a.impact})`).join('; ')}.`
          : '.') +
        ` Move to a supported branch (${supportedBranches(today).slice().reverse().join(', ')}). ${confirmHint}`,
      status: `PHP ${branch}: out of support`,
    };
  }
  const fixes = PHP_ADVISORIES.flatMap((adv) => {
    const bearing = advisoryFor(adv, branch);
    return bearing && 'fixedIn' in bearing ? [{ adv, fixedIn: bearing.fixedIn }] : [];
  });
  if (fixes.length === 0) {
    return {
      severity: null, cwe: 'CWE-1395', message: '', reasoning: '',
      status: `PHP ${branch} (floating): security support until ${readableDate(status.until)}`,
    };
  }
  const newest = fixes[0];
  return {
    severity: 'low',
    cwe: 'CWE-1395',
    message: `${d.text} (${d.source}) has the ${newest?.adv.name} fix only if built after ${readableDate(newest?.adv.published ?? '')}`,
    reasoning:
      `${d.where} declares \`${d.text}\` - ${how}, so the exact release depends on when the image was built or ` +
      `pulled, and Defuse cannot see that. ` +
      fixes
        .map(
          ({ adv, fixedIn }) =>
            `${adv.cves.join(' and ')} ("${adv.name}": ${adv.impact}) ${adv.cves.length > 1 ? 'are' : 'is'} fixed in ${fixedIn}, released ` +
            `${readableDate(adv.published)}; an image built before then does not have it.`,
        )
        .join(' ') +
      ` Rebuild with \`docker build --pull\` (or pin ${newest?.fixedIn} or later). ${confirmHint}`,
    status: `PHP ${branch} (floating): has the ${newest?.adv.name} fix only if built after ${readableDate(newest?.adv.published ?? '')}`,
  };
}

function rangeVerdict(d: Declaration, range: string, today: string): Verdict {
  const parsed = parseComposerRange(range);
  if (!parsed) {
    return { severity: null, cwe: 'CWE-1104', message: '', reasoning: '', status: `\`${range}\`: a range Defuse cannot read` };
  }
  const allowedKnown = KNOWN_BRANCHES.filter((b) => branchAllowed(b, parsed));
  const allowedSupported = supportedBranches(today).filter((b) => branchAllowed(b, parsed));
  const [nmaj, nmin] = branchVersion(NEWEST_KNOWN);
  const allowsNewer = satisfies([nmaj, nmin + 1, 0], parsed) || satisfies([nmaj + 1, 0, 0], parsed);
  if (allowedSupported.length > 0 || allowsNewer || allowedKnown.length === 0) {
    return {
      severity: null, cwe: 'CWE-1104', message: '', reasoning: '',
      status:
        allowedSupported.length > 0
          ? `\`${range}\`: allows supported branches (${allowedSupported.slice().reverse().join(', ')}); a range does not say which one runs`
          : `\`${range}\`: allows only branches newer than Defuse's table`,
    };
  }
  const newest = allowedKnown[allowedKnown.length - 1] ?? '';
  const noFix = PHP_ADVISORIES.filter((adv) => allowedKnown.every((b) => advisoryFor(adv, b) !== null));
  return {
    severity: 'high',
    cwe: 'CWE-1104',
    message: `composer.json allows only PHP versions that are out of security support (\`${range}\`)`,
    reasoning:
      `${d.where} requires PHP \`${range}\`, which fits no branch that still gets security fixes - the newest it ` +
      `allows is ${newest}, out of support since ${readableDate(PHP_END_OF_LIFE[newest] ?? PHP_SECURITY_UNTIL[newest] ?? PHP_FACTS_CHECKED)}.` +
      (noFix.length > 0
        ? ` No official release in those branches fixes ${noFix.map((a) => `${a.cves.join(' and ')} ("${a.name}")`).join(', ')}.`
        : '') +
      ' This is the range the project says it runs on, not proof of what the server runs: confirm with `php -v` where the code runs.',
    status: `\`${range}\`: out-of-support branches only`,
  };
}

/* ------------------------------------------------------------------ main -- */

export function checkRuntimeVersions(
  files: readonly RuntimeInputFile[],
  options: RuntimeCheckOptions,
): RuntimeCheckResult {
  const notes: string[] = [];
  const declarations: Declaration[] = [];
  for (const file of files) {
    const kind = runtimeFileKind(file.path.split(/[\\/]/).pop() ?? '');
    if (kind === 'dockerfile') declarations.push(...readDockerfile(file, options.today));
    else if (kind === 'compose') declarations.push(...readCompose(file, options.today));
    else if (kind === 'composer') declarations.push(...readComposerJson(file, notes));
    else if (kind === 'php-version') declarations.push(...readPhpVersionFile(file));
  }

  const findings: SignatureFinding[] = [];
  const declared: DeclaredRuntime[] = [];
  for (const d of declarations) {
    const verdict =
      d.range !== undefined
        ? rangeVerdict(d, d.range, options.today)
        : d.pinned?.kind === 'exact'
          ? exactVerdict(d, d.pinned.version, d.pinned.prerelease, options.today)
          : d.pinned?.kind === 'branch'
            ? branchVerdict(d, d.pinned.branch, d.pinned.how, options.today)
            : null;
    declared.push({
      file: d.file,
      line: d.line,
      source: d.source,
      declared: d.text,
      status: verdict?.status ?? `version not visible: ${d.pinned?.kind === 'unknown' ? d.pinned.why : 'unreadable'}`,
    });
    if (!verdict?.severity) continue;
    const inTestFile = isTestPath(d.file);
    const severity: Severity = !inTestFile
      ? verdict.severity
      : verdict.severity === 'critical' ? 'medium' : verdict.severity === 'high' ? 'low' : verdict.severity;
    const snippet = d.lineText.trim();
    findings.push(
      signatureFinding({
        ruleId: RUNTIME_VERSION_RULE.id,
        ruleName: RUNTIME_VERSION_RULE.name,
        cwe: verdict.cwe,
        owasp: RUNTIME_VERSION_RULE.owasp,
        severity,
        message: verdict.message,
        location: {
          file: d.file,
          startLine: d.line,
          startColumn: d.column,
          endLine: d.line,
          endColumn: d.column + d.text.length,
          astNodeType: d.nodeType,
          astNodePath: `${d.source}`,
          snippet: snippet.length > 160 ? `${snippet.slice(0, 159)}…` : snippet,
        },
        reasoning:
          `${verdict.reasoning} Facts from php.net, checked ${readableDate(PHP_FACTS_CHECKED)}.` +
          (inTestFile
            ? ' NOTE: this file looks like a test, fixture or example. The finding is accurate about the ' +
              'file, but a test setup is not reachable by an attacker, so severity is lowered rather than ' +
              'the finding dropped.'
            : ''),
        limitations: RUNTIME_VERSION_RULE.limitations,
      }),
    );
  }

  /*
   * THE SILENCE THIS CHECK MUST NOT LEAVE. A PHP project with no readable
   * version declaration gets no finding - and "no finding" would read as "the
   * PHP version is fine". Say what was not checked instead.
   */
  if (options.phpFilesScanned > 0) {
    if (declarations.length === 0) {
      notes.push(
        'This project has PHP files but declares no PHP version Defuse can read (the official php image in a ' +
          'Dockerfile or compose file, composer.json, or .php-version), so the PHP version it runs on was not checked.',
      );
    } else if (declarations.every((d) => d.range !== undefined)) {
      notes.push(
        'The only PHP version this project declares is a composer.json range, which does not say which release ' +
          'runs. Check the server with `php -v`.',
      );
    }
  }
  const age = daysBetween(PHP_FACTS_CHECKED, options.today);
  if (declarations.length > 0 && age > 180) {
    notes.push(
      `Defuse's PHP release table was checked ${age} days before this scan (${readableDate(PHP_FACTS_CHECKED)}). ` +
        'Releases and advisories since then are not known to it.',
    );
  }

  return { findings, declared, notes, factsChecked: PHP_FACTS_CHECKED };
}
