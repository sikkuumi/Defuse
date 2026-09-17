/**
 * SARIF 2.1.0 EXPORT
 *
 * SARIF is the OASIS format GitHub, GitLab and Azure DevOps read. Emitting it
 * is what turns this from "a thing you run" into "a thing a pull request runs",
 * and it is the single cheapest step on the roadmap.
 *
 * THE PROBLEM SARIF CREATES FOR THIS PROJECT, and how it is solved here.
 *
 * Every finding this tool emits is labelled signature-based (pattern matched,
 * data flow NOT traced) or flow-verified (a source-to-sink path was followed
 * and is printed). That distinction is the whole product. SARIF has no field
 * for it: `level` carries severity, and there is nowhere that means "we did not
 * check this one".
 *
 * So a naive export loses the differentiator at exactly the moment it matters -
 * in CI, where nobody reads a terminal and a red annotation looks equally
 * certain either way. Three things carry it across instead, deliberately
 * redundant, because a consumer that ignores one should still meet the others:
 *
 *   1. `message.text` OPENS with the label. It is the one string every SARIF
 *      consumer displays, so the label cannot be dropped by a viewer that
 *      ignores everything else.
 *   2. `properties.confidence` holds the machine-readable value, alongside
 *      `properties.limitations` - the rule's own statement of what it did not
 *      check.
 *   3. `codeFlows` is populated for flow-verified findings ONLY. SARIF has a
 *      first-class representation for a traced path, and GitHub renders it as a
 *      clickable sequence of steps. A finding with a codeFlow is one we proved;
 *      a finding without one is one we guessed. That asymmetry is visible in
 *      the UI without reading any of our text.
 *
 * WHAT IS DELIBERATELY NOT CLAIMED: `securitySeverity` is emitted because
 * GitHub sorts by it, but it is derived from our severity rather than from CVSS,
 * and the property block says so. Inventing a CVSS vector we never computed
 * would be the same class of lie the confidence labels exist to prevent.
 */

import type * as Sarif from 'sarif';
import type { Finding, Severity } from '../core/finding.js';
import type { ScanResult } from '../engine/scan.js';

/**
 * SARIF has four levels; we have five severities.
 *
 * `low` maps to note rather than warning on purpose: a note does not fail a
 * default GitHub check, and after the test-file ranking work most `low`
 * findings are exactly the "unescaped, but no source traced" class that should
 * be visible without blocking anyone's merge.
 */
const SARIF_LEVEL: Record<Severity, 'error' | 'warning' | 'note' | 'none'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'none',
};

/** GitHub buckets these: >=9 critical, >=7 high, >=4 medium, >0 low. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.3',
  high: '7.5',
  medium: '5.0',
  low: '3.0',
  info: '0.0',
};

/** SARIF wants a URI, and a Windows path is not one. */
function toUri(filePath: string): string {
  return filePath.replace(/\\/g, '/').replace(/^\.\//, '');
}

function regionOf(location: Finding['location']) {
  return {
    startLine: Math.max(1, location.startLine),
    startColumn: Math.max(1, location.startColumn + 1), // SARIF columns are 1-based
    endLine: Math.max(1, location.endLine),
    endColumn: Math.max(1, location.endColumn + 1),
    ...(location.snippet ? { snippet: { text: location.snippet } } : {}),
  };
}

function physicalLocation(location: Finding['location']) {
  return {
    physicalLocation: {
      artifactLocation: { uri: toUri(location.file) },
      region: regionOf(location),
    },
  };
}

export function renderSarif(result: ScanResult, pretty = true): string {
  // One rule descriptor per rule that actually fired. Emitting the whole
  // catalogue would list rules this run never applied, which reads as coverage.
  const seen = new Map<string, Finding>();
  for (const finding of result.findings) {
    if (!seen.has(finding.ruleId)) seen.set(finding.ruleId, finding);
  }

  const rules = [...seen.values()].map((finding) => ({
    id: finding.ruleId,
    name: finding.ruleName,
    shortDescription: { text: finding.ruleName },
    fullDescription: {
      // The limitations text travels with the rule, so a consumer reading the
      // rule metadata meets the caveats without opening our JSON report.
      text: finding.limitations,
    },
    help: {
      text: `${finding.ruleName}\n\n${finding.limitations}`,
      markdown: `**${finding.ruleName}**\n\n${finding.limitations}`,
    },
    properties: {
      tags: ['security', finding.cwe, finding.owasp].filter(Boolean),
      'security-severity': SECURITY_SEVERITY[finding.severity],
      precision: 'medium',
    },
  }));

  const results = result.findings.map((finding) => {
    const label = finding.verified ? 'flow-verified' : 'signature-based, UNVERIFIED';
    const base = {
      ruleId: finding.ruleId,
      level: SARIF_LEVEL[finding.severity],
      message: { text: `[${label}] ${finding.message}\n\n${finding.reasoning}` },
      locations: [physicalLocation(finding.location)],
      properties: {
        confidence: finding.confidence,
        severity: finding.severity,
        cwe: finding.cwe,
        owasp: finding.owasp,
        limitations: finding.limitations,
        'security-severity': SECURITY_SEVERITY[finding.severity],
        securitySeverityIsDerived:
          'Derived from our own severity, not from a CVSS vector. No CVSS score was computed.',
      },
    };

    // A traced path becomes a real SARIF codeFlow. Signature findings get none,
    // which is the honest shape: there is no flow to show.
    if (!finding.verified || !finding.flowPath || finding.flowPath.length === 0) return base;

    return {
      ...base,
      codeFlows: [
        {
          message: { text: `Traced ${finding.flowPath.length} steps from source to sink.` },
          threadFlows: [
            {
              locations: finding.flowPath.map((step) => ({
                location: {
                  ...physicalLocation(step.location),
                  message: { text: `${step.kind}: ${step.description}` },
                },
                // SARIF's own vocabulary for taint. A consumer that understands
                // it can render source and sink differently without parsing our
                // prose.
                kinds:
                  step.kind === 'source'
                    ? ['taint', 'source']
                    : step.kind === 'sink'
                      ? ['taint', 'sink']
                      : ['taint'],
              })),
            },
          ],
        },
      ],
    };
  });

  /*
   * TYPED AS `Sarif.Log`, WHICH IS THE POINT.
   *
   * The JSON report's own comment says emitting invalid SARIF and calling it
   * SARIF would be its own small lie. A hand-rolled object literal that merely
   * LOOKS like SARIF is exactly that lie waiting to happen, so the shape is
   * checked by the compiler against the official 2.1.0 type definitions
   * (@types/sarif, a devDependency). A misspelled property or a wrong nesting
   * level fails `npm run build` rather than failing silently inside somebody's
   * CI three months from now.
   *
   * This validates STRUCTURE, not semantics: the compiler confirms this is a
   * well-formed SARIF log, not that GitHub will render it the way intended.
   */
  const document: Sarif.Log = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Defuse',
            version: result.coverage.engine.version,
            informationUri: 'https://github.com/',
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            // Files we could not parse are stated, not swallowed - a green CI
            // run over a file nobody read is the quietest kind of false clean.
            ...(result.parseProblems.length > 0
              ? {
                  toolExecutionNotifications: result.parseProblems.map((problem) => ({
                    level: 'warning' as const,
                    message: {
                      text:
                        `${problem.file} did not parse cleanly (${problem.issues.length} issue(s)). ` +
                        `Findings in this file may be incomplete.`,
                    },
                  })),
                }
              : {}),
          },
        ],
        properties: {
          // The same honesty block the JSON report leads with. A CI consumer
          // that only ever reads SARIF still gets the engine's own account of
          // what it does not do.
          signatureBasedFindings: result.findings.filter((f) => !f.verified).length,
          flowVerifiedFindings: result.findings.filter((f) => f.verified).length,
          notImplemented: result.coverage.engine.notImplemented,
          meaningOfConfidence: result.coverage.engine.meaningOfConfidence,
          filesParsed: result.stats.filesParsed,
          filesSkipped: result.stats.filesSkipped,
        },
      },
    ],
  };

  return pretty ? JSON.stringify(document, null, 2) : JSON.stringify(document);
}
