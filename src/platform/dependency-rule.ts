/**
 * The dependency check's rule text and report shape, kept apart from deps.ts
 * because the reports (which also run in the browser) need them and deps.ts
 * reads the file system. Browser-safe: no imports.
 */

export const DEPENDENCY_RULE = {
  id: 'vulnerable-dependency',
  name: 'Library version with a published advisory',
  owasp: 'A03:2025 Software Supply Chain Failures',
  summary: 'A library this project pins has a published security advisory for that exact version.',
  fix: 'Upgrade the library to a fixed version and regenerate the lockfile.',
  explanation:
    'Most of the code a project runs was written by someone else and arrives through its lockfile. ' +
    'When a pinned library version has a published advisory, the flaw is installed with it - whatever ' +
    'the project\'s own code does. The fix is usually an upgrade, not a code change.',
  limitations:
    'Says the vulnerable version is installed, not that this project calls the vulnerable part - many ' +
    'advisories cover one function the project never uses. Reads package-lock.json, composer.lock, ' +
    'requirements.txt (== pins only) and go.mod; other lockfiles are listed as not read. Advisories come ' +
    'from osv.dev at scan time, so the same lockfile can gain findings tomorrow. Runs only with --deps, ' +
    'because it is the one check that sends anything off the machine: package names and versions, never code.',
} as const;

/** What the dependency check read and asked, for the report's "what was checked" section. */
export interface DependencyReport {
  readonly source: 'api.osv.dev';
  readonly checkedAt: string;
  readonly read: ReadonlyArray<{ readonly file: string; readonly packages: number; readonly skipped: readonly string[] }>;
  readonly notRead: readonly string[];
  readonly checked: number;
  readonly incomplete: readonly string[];
}
