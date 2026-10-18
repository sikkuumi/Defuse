/**
 * THE CLIENT REPORT
 * =================
 *
 * The terminal report is for the person who ran the scan. This one is for the
 * person who did not: a project owner who will read it once, possibly printed,
 * and decide what to do. It is one self-contained HTML file - no script, no
 * stylesheet or font fetched from anywhere, the mark drawn inline - so it can
 * be emailed, opened offline and printed to PDF from any browser.
 *
 * It says the same things the terminal does, in the same order of trust:
 *
 *   1. what was PROVEN, each with the path that proves it;
 *   2. what was only MATCHED, said plainly to be unproven;
 *   3. what was checked and CLEARED, with the reason;
 *   4. what was NOT CHECKED at all.
 *
 * The fourth section is not an appendix to skip. A report that lists problems
 * and stays silent about what it never looked at invites the reader to treat
 * "not listed" as "fine" - the exact failure this tool exists to avoid - and a
 * client report is where that misreading costs the most.
 *
 * Two labels, never blended: a proven finding is a filled dot, a guess a
 * hollow ring, so the difference survives a black-and-white printer. The
 * mark's purple is used on the mark and the name only.
 *
 * PLATFORM-FREE ON PURPOSE: string in, string out, no Node imports, so the
 * browser UI can produce the same file from the same engine.
 *
 * EVERY PIECE OF TEXT FROM THE SCANNED CODE IS ESCAPED. A snippet is whatever
 * the scanned project contains, and a report that rendered it as markup would
 * be an XSS vector aimed at the person reading a security report. The test
 * suite feeds it a hostile snippet to make sure.
 */

import type { ScanResult } from '../engine/scan.js';
import type { Finding, FlowStep, Severity } from '../core/finding.js';
import { LICENCE_SPDX } from '../core/licence.js';
import { LANGUAGES } from '../parse/languages.js';
import { ALL_RULES } from '../rules/registry.js';
import { isTestPath } from '../rules/lib/strings.js';
import { markSvg } from './mark.js';

export interface HtmlReportOptions {
  /** Shown as the project name. Defaults to the last segment of the target path. */
  readonly projectName?: string;
  /** Optional: the person or firm who ran the scan and reviewed the report. */
  readonly preparedBy?: string;
  /**
   * Optional: one line printed under the header - that this is a sample, a
   * draft, or which branch was scanned. Escaped like every other string here.
   */
  readonly note?: string;
  /** When the scan ran. Passed in so the output is reproducible in tests. */
  readonly generatedAt: Date;
  /**
   * The scanned folder as the finding paths spell it. The CLI writes paths
   * relative to where it was run (`corpus/app/views.py`) while the target is
   * absolute, so both prefixes are stripped to show `views.py`'s place in the
   * project rather than on the scanning machine.
   */
  readonly root?: string;
  /**
   * Anything the shell that gathered the files left out on its own terms -
   * the browser reads at most 4,000 files and none over 2 MB. Printed in
   * section 4, because a file that never reached the engine is a gap the
   * engine cannot report by itself.
   */
  readonly intake?: string;
}

const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

/** Escape for HTML text and attribute values. Everything from the scan goes through this. */
export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const e = escapeHtml;

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`;
}

/** The path as the reader knows it: relative to the scanned folder, forward slashes. */
function relativeTo(...roots: readonly string[]): (file: string) => string {
  const norm = (p: string): string => p.replace(/\\/g, '/');
  const bases = roots
    .map((r) => norm(r).replace(/^\.\//, '').replace(/\/+$/, ''))
    .filter((b) => b && b !== '.');
  return (file: string): string => {
    const f = norm(file).replace(/^\.\//, '');
    for (const base of bases) if (f.startsWith(`${base}/`)) return f.slice(base.length + 1);
    return f;
  };
}

function lastSegment(path: string): string {
  const parts = path.replace(/\\/g, '/').replace(/\/+$/, '').split('/');
  return parts[parts.length - 1] || path;
}

/*
 * A REPORT IS NOT A SAFE PLACE FOR A SECRET. The terminal and --json show a
 * hardcoded credential in full, because the person running the scan already
 * has the code. This file is made to be sent to someone, so the value of a
 * reported secret is cut to at most its first three characters (fewer for a
 * short one) and its length - enough to find it in the code, not to use it.
 */
export function maskSecretLiterals(snippet: string): string {
  return snippet.replace(/(["'`])((?:\\.|(?!\1)[^\\])*)\1/g, (whole, quote: string, inner: string) =>
    inner.length < 4
      ? whole
      : `${quote}${inner.slice(0, Math.min(3, Math.floor(inner.length / 4)))}…${quote} [${inner.length} characters, hidden in this report]`,
  );
}

function bySeverityThenPlace(a: Finding, b: Finding): number {
  const s = SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity);
  if (s !== 0) return s;
  const f = a.location.file.localeCompare(b.location.file);
  return f !== 0 ? f : a.location.startLine - b.location.startLine;
}

function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function renderHtmlReport(result: ScanResult, options: HtmlReportOptions): string {
  const rel = relativeTo(result.target, options.root ?? '');
  const rules = new Map(ALL_RULES.map((r) => [r.id, r]));
  const proven = result.findings.filter((f) => f.confidence === 'flow-verified').sort(bySeverityThenPlace);
  const guessed = result.findings.filter((f) => f.confidence === 'signature-based').sort(bySeverityThenPlace);
  const cleared = [...result.verifiedClean].sort(
    (a, b) => a.file.localeCompare(b.file) || a.line - b.line,
  );
  const guessedInTests = guessed.filter((f) => isTestPath(f.location.file));
  const project = options.projectName?.trim() || lastSegment(result.target);
  const date = options.generatedAt.toISOString().slice(0, 10);
  const version = result.coverage.engine.version;

  const languagesSeen = Object.entries(result.byLanguage)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([id, n]) => `${LANGUAGES.find((l) => l.id === id)?.displayName ?? id} (${n.toLocaleString('en-US')})`);

  /* ------------------------------------------------------------ pieces -- */

  const severityPill = (s: Severity): string => `<span class="sev sev-${s}">${SEVERITY_LABEL[s]}</span>`;
  const where = (file: string, line: number): string => `<span class="where">${e(rel(file))}:${line}</span>`;
  const code = (text: string): string => `<code class="snippet">${e(text)}</code>`;

  const stepLabel: Record<FlowStep['kind'], string> = {
    source: 'Enters',
    propagation: 'Passes',
    sanitizer: 'Cleaned',
    sink: 'Lands',
  };

  const provenCard = (f: Finding, index: number): string => {
    const rule = rules.get(f.ruleId);
    const steps = (f.flowPath ?? [])
      .map(
        (s) =>
          `<li class="step step-${s.kind}"><span class="step-kind">${stepLabel[s.kind]}</span>` +
          `<span class="step-body">${where(s.location.file, s.location.startLine)} ${code(s.location.snippet)}` +
          `<span class="step-why">${e(s.description)}</span></span></li>`,
      )
      .join('');
    return (
      `<article class="finding card proven" data-rule="${e(f.ruleId)}">` +
      `<header><span class="dot dot-proven" aria-hidden="true"></span>` +
      `<span class="num">P${index + 1}</span>${severityPill(f.severity)}` +
      `<h3>${e(f.ruleName)}</h3></header>` +
      `<p class="loc">${where(f.location.file, f.location.startLine)}</p>` +
      `<p class="what">${e(f.message)}</p>` +
      `<h4>The path Defuse followed</h4><ol class="path">${steps}</ol>` +
      (rule ? `<h4>What this is, and how to fix it</h4><p>${e(rule.explanation)}</p>` : '') +
      `<p class="ref">${e(f.cwe)} · ${e(f.owasp)}</p>` +
      `</article>`
    );
  };

  const shown = (f: Finding): string =>
    f.ruleId === 'hardcoded-secret' ? maskSecretLiterals(f.location.snippet) : f.location.snippet;

  const guessRow = (f: Finding, ruleLimitations: string): string =>
    `<tr class="finding guess"><td>${severityPill(f.severity)}</td>` +
    `<td>${where(f.location.file, f.location.startLine)}</td>` +
    `<td><div>${e(f.message)}</div>${code(shown(f))}` +
    (f.limitations && f.limitations !== ruleLimitations
      ? `<div class="hitnote">${e(f.limitations)}</div>`
      : '') +
    `</td></tr>`;

  const guessTable = (rows: readonly Finding[], ruleLimitations: string): string =>
    `<table class="rows"><thead><tr><th>Severity</th><th>Where</th><th>What was matched</th></tr></thead>` +
    `<tbody>${rows.map((f) => guessRow(f, ruleLimitations)).join('')}</tbody></table>`;

  /* ----------------------------------------------------------- sections -- */

  const provenCounts = countBySeverity(proven);
  const guessedCounts = countBySeverity(guessed);

  const severityTable =
    `<table class="sevtable"><thead><tr><th></th>${SEVERITIES.filter((s) => s !== 'info')
      .map((s) => `<th>${SEVERITY_LABEL[s]}</th>`)
      .join('')}</tr></thead><tbody>` +
    `<tr><th><span class="dot dot-proven" aria-hidden="true"></span>Proven</th>${SEVERITIES.filter((s) => s !== 'info')
      .map((s) => `<td>${provenCounts[s]}</td>`)
      .join('')}</tr>` +
    `<tr><th><span class="dot dot-guess" aria-hidden="true"></span>To review</th>${SEVERITIES.filter((s) => s !== 'info')
      .map((s) => `<td>${guessedCounts[s]}</td>`)
      .join('')}</tr></tbody></table>`;

  const verdict =
    (proven.length > 0
      ? `Defuse proved ${plural(proven.length, 'problem')} by following attacker-controlled input to the place it does harm. `
      : 'Defuse did not prove any problem in this code. That is not the same as finding none - see section 4 for what it does not check. ') +
    (guessed.length > 0
      ? `It also found ${plural(guessed.length, 'place')} that match a known risky pattern and need a person to check them` +
        (guessedInTests.length > 0 ? ` (${guessedInTests.length.toLocaleString('en-US')} of them in test or example files)` : '') +
        '. '
      : 'Nothing else matched a risky pattern. ') +
    (cleared.length > 0
      ? `${plural(cleared.length, 'line')} that looked risky ${cleared.length === 1 ? 'was' : 'were'} checked and cleared, each with the reason.`
      : '');

  const provenSection =
    `<section id="proven"><h2><span class="secnum">1</span>Proven problems</h2>` +
    `<p class="lead">Each of these comes with the path Defuse followed: where outside input enters, every step it passes through, and where it lands. ` +
    `Read the path - it is the evidence, and it can be checked line by line. A step marked as passing through a function Defuse does not know is an assumption, and says so.</p>` +
    (proven.length > 0
      ? proven.map(provenCard).join('')
      : `<p class="empty">No problem was proven. Section 2 lists what still needs a person to look at it, and section 4 what was not checked.</p>`) +
    `</section>`;

  const guessGroups = [...new Set(guessed.map((f) => f.ruleId))]
    .map((id) => ({ id, rows: guessed.filter((f) => f.ruleId === id) }))
    .sort((a, b) => {
      const top = (rows: readonly Finding[]): number => Math.min(...rows.map((f) => SEVERITIES.indexOf(f.severity)));
      return top(a.rows) - top(b.rows) || b.rows.length - a.rows.length;
    });

  const guessSection =
    `<section id="review"><h2><span class="secnum">2</span>To review: matched, not proven</h2>` +
    `<p class="lead">These lines match the shape of a known problem, but Defuse could not follow the data to prove it. ` +
    `Some will be real and some will be false alarms. Under each heading is what the check cannot tell - that is the question a reviewer has to answer for each line. ` +
    `Lines in test and example files are listed separately: they rarely run in production, but they are still in the code.</p>` +
    (guessGroups.length > 0
      ? guessGroups
          .map(({ id, rows }) => {
            const rule = rules.get(id);
            const name = rule?.name ?? rows[0]?.ruleName ?? id;
            const limits = rule?.limitations ?? rows[0]?.limitations ?? '';
            const main = rows.filter((f) => !isTestPath(f.location.file));
            const tests = rows.filter((f) => isTestPath(f.location.file));
            return (
              `<div class="group" data-rule="${e(id)}"><h3><span class="dot dot-guess" aria-hidden="true"></span>${e(name)} <span class="count">${rows.length}</span></h3>` +
              (rule ? `<p class="explain">${e(rule.explanation)}</p>` : '') +
              `<p class="limits"><strong>What this check cannot tell:</strong> ${e(limits)}</p>` +
              (id === 'hardcoded-secret'
                ? `<p class="hitnote">The values below are cut to their first three characters, so this report does not pass the secrets on. The full values are in the code, and in the scan's own output.</p>`
                : '') +
              (main.length > 0 ? `<h4>In the application code (${main.length})</h4>${guessTable(main, limits)}` : '') +
              (tests.length > 0 ? `<h4>In test and example files (${tests.length})</h4>${guessTable(tests, limits)}` : '') +
              `</div>`
            );
          })
          .join('')
      : `<p class="empty">Nothing matched a risky pattern.</p>`) +
    `</section>`;

  const clearedSection =
    `<section id="cleared"><h2><span class="secnum">3</span>Checked and cleared</h2>` +
    `<p class="lead">These lines looked like a problem, and Defuse proved they are not - a value that is fixed on every path, a sanitiser that is shown to run, or the code's own statement of purpose. ` +
    `Each reason is the claim it rests on.` +
    (result.stats.regionsProvedUnreachable > 0
      ? ` Separately, ${plural(result.stats.regionsProvedUnreachable, 'branch', 'branches')} were skipped because a fixed condition means they cannot run.`
      : '') +
    `</p>` +
    (cleared.length > 0
      ? `<table class="rows"><thead><tr><th>Where</th><th>Check</th><th>Why it is clear</th></tr></thead><tbody>` +
        cleared
          .map(
            (c) =>
              `<tr class="cleared"><td>${where(c.file, c.line)}</td><td>${e(rules.get(c.ruleId)?.name ?? c.ruleId)}</td>` +
              `<td>${e(c.reason ?? 'A sanitiser for this kind of problem was proven to run on the path into this line.')}</td></tr>`,
          )
          .join('') +
        `</tbody></table>`
      : `<p class="empty">No line needed clearing.</p>`) +
    `</section>`;

  /* ---- 4. what was not checked ---- */
  const presentLanguages = new Set(Object.entries(result.byLanguage).filter(([, n]) => n > 0).map(([id]) => id));
  const gapsHere = result.coverage.gaps.filter((g) => presentLanguages.has(g.language));
  const noRule = result.coverage.owaspCoverage.filter((c) => c.state === 'none');
  const partial = result.coverage.owaspCoverage.filter((c) => c.state === 'partial');
  const limits = result.traceLimits;
  const notCheckedItems: string[] = [];
  /*
   * Always present, because it is always true: the walker skips dependency
   * and build folders, and Defuse does not check which package versions are
   * known to be vulnerable. A client asking "is this app secure?" needs to
   * know that half of the question is a different tool.
   */
  notCheckedItems.push(
    `<li><strong>Other people's code.</strong> Dependency and build folders (node_modules, vendor, dist, build, ` +
      `virtual environments and the like) are not scanned, and Defuse does not check whether the libraries the ` +
      `project uses have known vulnerabilities. That is a separate check, done by a dependency scanner.</li>`,
  );
  if (options.intake?.trim()) {
    notCheckedItems.push(`<li><strong>How the files were gathered.</strong> ${e(options.intake.trim())}</li>`);
  }
  if (noRule.length > 0) {
    notCheckedItems.push(
      `<li><strong>Whole kinds of problem Defuse has no check for.</strong> Silence here means nothing either way:<ul>` +
        noRule.map((c) => `<li>${e(c.id)} ${e(c.title)} - for example ${e(c.examples)}</li>`).join('') +
        `</ul></li>`,
    );
  }
  if (partial.length > 0) {
    notCheckedItems.push(
      `<li><strong>Kinds of problem checked only in part.</strong><ul>` +
        partial.map((c) => `<li>${e(c.id)} ${e(c.title)}: Defuse checks ${e(c.weCheck ?? '')}</li>`).join('') +
        `</ul></li>`,
    );
  }
  if (gapsHere.length > 0) {
    notCheckedItems.push(
      `<li><strong>Checks that are partial or missing for the languages in this project.</strong><ul>` +
        gapsHere
          .map(
            (g) =>
              `<li>${e(g.ruleName)} in ${e(LANGUAGES.find((l) => l.id === g.language)?.displayName ?? g.language)}: ${e(g.note)}</li>`,
          )
          .join('') +
        `</ul></li>`,
    );
  }
  if (result.coverage.unscannedExtensions.length > 0) {
    notCheckedItems.push(
      `<li><strong>Files Defuse cannot read</strong> were present and were not scanned: ${e(result.coverage.unscannedExtensions.join(', '))}.</li>`,
    );
  }
  if (result.excluded.fileCount > 0) {
    notCheckedItems.push(
      `<li><strong>Left out on request:</strong> ${plural(result.excluded.fileCount, 'file')} matching ${e(result.excluded.patterns.join(', '))}.</li>`,
    );
  }
  if (result.oversizedFiles.length > 0) {
    notCheckedItems.push(
      `<li><strong>Too large to read:</strong> ${result.oversizedFiles.map((f) => e(rel(f))).join(', ')}.</li>`,
    );
  }
  if (result.parseProblems.length > 0) {
    notCheckedItems.push(
      `<li><strong>Files that did not parse cleanly</strong> (the readable parts were checked; findings near the damage may be missing): ` +
        result.parseProblems.map((p) => e(rel(p.file))).join(', ') +
        `.</li>`,
    );
  }
  if (limits.depthTruncations + limits.recursionStops + limits.unmodelledHops > 0) {
    notCheckedItems.push(
      `<li><strong>Where the data-flow trace stopped or assumed.</strong> ` +
        `${plural(limits.depthTruncations, 'trace')} reached the depth limit, ` +
        `${plural(limits.recursionStops, 'call')} ${limits.recursionStops === 1 ? 'was' : 'were'} not re-entered because the function was already being followed, and ` +
        `${plural(limits.unmodelledHops, 'step')} passed through a function Defuse has no entry for, where the value was assumed to carry through. ` +
        `A sanitiser hidden past such a point is missed, and the line is reported rather than cleared.</li>`,
    );
  }
  if (result.suppressions.length > 0) {
    notCheckedItems.push(
      `<li><strong>Silenced in the code itself</strong> with a defuse:ignore comment: ` +
        result.suppressions.map((s) => `${e(rel(s.file))}:${s.line} (${e(s.ruleId)})`).join(', ') +
        `.</li>`,
    );
  }
  /*
   * The engine's own list of what it does not do, word for word. Long, and
   * written for engineers - so it is an appendix rather than the body of
   * section 4, but it is printed in full: shortening it would be choosing which
   * limits a client gets to see.
   */
  const engineLimits =
    `<section id="engine-limits" class="appendix"><h2><span class="secnum">A</span>Appendix: the engine's known limits, in full</h2>` +
    `<p class="lead">Defuse's own statement of what its analysis does not do, as printed by every scan.</p><ul>` +
    result.coverage.engine.notImplemented.map((n) => `<li>${e(n)}</li>`).join('') +
    `</ul></section>`;

  const notCheckedSection =
    `<section id="not-checked"><h2><span class="secnum">4</span>What this scan did not check</h2>` +
    `<p class="lead">A problem of a kind listed here would not appear in this report even if it is in the code. ` +
    `"Not listed above" must not be read as "safe".</p>` +
    `<ul class="notchecked">${notCheckedItems.join('')}</ul>` +
    `<p class="lead">The appendix lists the engine's own limits in full.</p>` +
    `</section>`;

  const aboutSection =
    `<section id="about"><h2><span class="secnum">5</span>About this report</h2>` +
    `<p>Produced by Defuse ${e(version)}, a static analysis tool: it reads the source code and does not run the application. ` +
    `So neither label proves a problem can be exploited in production - that depends on how the code is deployed and called. ` +
    `What the labels do say is how much was checked: <span class="dot dot-proven" aria-hidden="true"></span><strong>proven</strong> means a complete path was followed and is printed; ` +
    `<span class="dot dot-guess" aria-hidden="true"></span><strong>to review</strong> means a pattern matched and nothing more.</p>` +
    `<p>${plural(result.stats.filesParsed, 'file')} read, ${plural(result.stats.shapesExamined, 'code shape')} examined, ` +
    `${plural(result.traceLimits.sourcesFound, 'input source')} recognised. ` +
    `Defuse is open source under ${e(LICENCE_SPDX)}: github.com/Sikkuumi/Defuse.</p>` +
    `</section>`;

  /* ------------------------------------------------------------- page -- */

  const meta: Array<[string, string]> = [
    ['Project', project],
    ['Scanned', date],
    ['Files read', `${result.stats.filesParsed.toLocaleString('en-US')}${languagesSeen.length ? ` - ${languagesSeen.join(', ')}` : ''}`],
    ['Engine', `Defuse ${version} · ${result.coverage.engine.analysisLabel.toLowerCase()}`],
  ];
  if (options.preparedBy?.trim()) meta.push(['Prepared by', options.preparedBy.trim()]);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="Defuse ${e(version)}">
<title>${e(project)} - Defuse security scan report</title>
<style>${STYLES}</style>
</head>
<body>
<main class="report" data-count-proven="${proven.length}" data-count-review="${guessed.length}" data-count-cleared="${cleared.length}">
<header class="top">
  <div class="brand">${markSvg(34)}<span class="brand-name">Defuse</span></div>
  <div class="doc">Security scan report</div>
</header>
<h1>${e(project)}</h1>
<table class="meta"><tbody>${meta.map(([k, v]) => `<tr><th>${e(k)}</th><td>${e(v)}</td></tr>`).join('')}</tbody></table>
${options.note?.trim() ? `<p class="note">${e(options.note.trim())}</p>` : ''}

<section id="glance">
<div class="stats">
  <div class="stat"><div class="stat-n"><span class="dot dot-proven big" aria-hidden="true"></span>${proven.length.toLocaleString('en-US')}</div><div class="stat-l">Proven</div><div class="stat-d">A path from outside input to harm was followed and is printed.</div></div>
  <div class="stat"><div class="stat-n"><span class="dot dot-guess big" aria-hidden="true"></span>${guessed.length.toLocaleString('en-US')}</div><div class="stat-l">To review</div><div class="stat-d">Matches a risky pattern. Not proven; some will be false alarms.</div></div>
  <div class="stat"><div class="stat-n"><span class="tick" aria-hidden="true">✓</span>${cleared.length.toLocaleString('en-US')}</div><div class="stat-l">Cleared</div><div class="stat-d">Looked risky, and was shown not to be, with the reason.</div></div>
</div>
<p class="verdict">${e(verdict)}</p>
${severityTable}
</section>

${provenSection}
${guessSection}
${clearedSection}
${notCheckedSection}
${aboutSection}
${engineLimits}
<footer>Defuse ${e(version)} · ${e(date)} · every finding is labelled proven or to review, and nothing in between.</footer>
</main>
</body>
</html>
`;
}

/*
 * One stylesheet, light, built for paper first. System fonts only - a report
 * that fetched a web font would be a report that phones home when opened.
 */
const STYLES = `
:root{--ink:#1d1c18;--muted:#5d5c56;--line:#dcdad3;--soft:#f4f3ef;--paper:#fff;--brand:#792CF7;
--crit:#a3122f;--high:#b4441b;--med:#7a5a00;--low:#4b5563}
*{box-sizing:border-box}
html{background:var(--paper)}
body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.report{max-width:860px;margin:0 auto;padding:32px 24px 48px}
.top{display:flex;align-items:center;justify-content:space-between;border-bottom:2px solid var(--ink);padding-bottom:12px}
.brand{display:flex;align-items:center;gap:10px}
.brand-name{font-weight:700;font-size:20px;letter-spacing:-.01em;color:var(--brand)}
.doc{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
h1{font-size:28px;line-height:1.2;margin:22px 0 10px;letter-spacing:-.01em;overflow-wrap:anywhere}
h2{font-size:19px;margin:36px 0 8px;padding-top:14px;border-top:1px solid var(--line);display:flex;align-items:baseline;gap:10px}
.secnum{font:600 12px/1 ui-monospace,"SF Mono",Menlo,Consolas,monospace;color:var(--muted);border:1px solid var(--line);border-radius:3px;padding:3px 6px}
h3{font-size:15.5px;margin:0}
h4{font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:16px 0 6px}
p{margin:6px 0}
.lead{color:var(--muted);max-width:72ch}
.meta{border-collapse:collapse;margin:0 0 8px}
.note{border-left:3px solid var(--brand);background:var(--soft);padding:9px 14px;margin:14px 0 6px;max-width:72ch}
.meta th{text-align:left;font-weight:500;color:var(--muted);padding:2px 18px 2px 0;vertical-align:top;white-space:nowrap}
.meta td{padding:2px 0;overflow-wrap:anywhere}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:20px 0 12px}
.stat{border:1px solid var(--line);border-radius:6px;padding:12px 14px}
.stat-n{font-size:30px;font-weight:700;display:flex;align-items:center;gap:10px;line-height:1.1}
.stat-l{font-weight:600;margin-top:2px}
.stat-d{color:var(--muted);font-size:12.5px}
.tick{font-size:22px;color:var(--ink)}
.verdict{font-size:15px;max-width:72ch}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px;vertical-align:1px;flex:none}
.dot.big{width:14px;height:14px;margin-right:0}
.dot-proven{background:var(--ink);border:2px solid var(--ink)}
.dot-guess{background:transparent;border:2px solid var(--ink)}
.sevtable{border-collapse:collapse;margin:12px 0 0;font-variant-numeric:tabular-nums}
.sevtable th,.sevtable td{border:1px solid var(--line);padding:5px 12px;text-align:right}
.sevtable thead th{font-weight:600;font-size:12px;color:var(--muted)}
.sevtable tbody th{text-align:left;font-weight:500;white-space:nowrap}
.sev{display:inline-block;font:600 11px/1 ui-monospace,"SF Mono",Menlo,Consolas,monospace;letter-spacing:.04em;text-transform:uppercase;border:1px solid currentColor;border-radius:3px;padding:3px 5px;white-space:nowrap}
.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}.sev-low,.sev-info{color:var(--low)}
.where{font:12.5px/1.4 ui-monospace,"SF Mono",Menlo,Consolas,monospace;overflow-wrap:anywhere}
.snippet{display:block;font:12px/1.45 ui-monospace,"SF Mono",Menlo,Consolas,monospace;background:var(--soft);border-radius:4px;padding:5px 8px;margin:4px 0;white-space:pre-wrap;overflow-wrap:anywhere}
.card{border:1px solid var(--line);border-left:4px solid var(--ink);border-radius:6px;padding:14px 16px;margin:14px 0;break-inside:avoid}
.card header{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.num{font:600 12px/1 ui-monospace,"SF Mono",Menlo,Consolas,monospace;color:var(--muted)}
.loc{margin:6px 0 2px}
.what{font-weight:500}
.path{list-style:none;padding:0;margin:0;counter-reset:s}
.step{display:flex;gap:10px;padding:6px 0;border-top:1px dashed var(--line)}
.step:first-child{border-top:0}
.step-kind{flex:none;width:58px;font:600 11px/1.9 ui-monospace,"SF Mono",Menlo,Consolas,monospace;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.step-source .step-kind,.step-sink .step-kind{color:var(--ink)}
.step-body{flex:1;min-width:0}
.step-why{display:block;color:var(--muted);font-size:13px}
.ref{color:var(--muted);font-size:12.5px;margin-top:10px}
.group{margin:18px 0 26px}
.group h3{display:flex;align-items:center}
.count{font:600 12px/1 ui-monospace,"SF Mono",Menlo,Consolas,monospace;color:var(--muted);margin-left:8px}
.explain{max-width:72ch}
.limits{background:var(--soft);border-radius:4px;padding:8px 10px;font-size:13px;max-width:none}
.rows{width:100%;border-collapse:collapse;table-layout:fixed;margin:4px 0}
.rows th{text-align:left;font-size:12px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--line);padding:5px 8px}
.rows td{border-bottom:1px solid var(--line);padding:7px 8px;vertical-align:top;overflow-wrap:anywhere}
.rows tr{break-inside:avoid}
.rows th:nth-child(1){width:96px}.rows th:nth-child(2){width:32%}
#cleared .rows th:nth-child(1){width:34%}#cleared .rows th:nth-child(2){width:22%}
.hitnote{color:var(--muted);font-size:12.5px;margin-top:4px}
.empty{border:1px dashed var(--line);border-radius:6px;padding:12px 14px;color:var(--muted)}
.notchecked{padding-left:18px}
.notchecked>li{margin:8px 0}
.notchecked ul{margin:4px 0;padding-left:18px;color:var(--muted)}
.appendix ul{font-size:12.5px;color:var(--muted);padding-left:18px}
.appendix li{margin:5px 0}
footer{margin-top:40px;padding-top:10px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}
@media (max-width:640px){.stats{grid-template-columns:1fr}.report{padding:20px 16px 40px}h1{font-size:23px}
.rows,.rows tbody,.rows tr,.rows td{display:block;width:auto}.rows thead{display:none}
.rows tr{border-bottom:1px solid var(--line);padding:8px 0}.rows td{border:0;padding:2px 0}}
@page{size:A4;margin:16mm 14mm}
@media print{.report{max-width:none;padding:0}.appendix{break-before:page}h2{break-after:avoid}.group h3,.group h4{break-after:avoid}a{color:inherit}}
`;
