/**
 * MACHINE-READABLE REPORT
 *
 * Two rules for this format:
 *
 * 1. It is a SUPERSET of the human report. Anything the terminal shows must be
 *    in here, including the gaps and the suppressions. A JSON consumer must not
 *    be able to build a rosier picture than a human reading the same scan.
 *
 * 2. `confidence` is a top-level field on every finding, and the `honesty`
 *    block at the document root explains what the values mean. A dashboard that
 *    ingests this cannot accidentally present unverified matches as confirmed
 *    vulnerabilities without deliberately discarding the field.
 *
 * RELATIONSHIP TO SARIF: this shape deliberately resembles SARIF (the OASIS
 * standard GitHub code scanning consumes) without pretending to be it, because
 * emitting invalid SARIF and calling it SARIF would be its own small lie. Real
 * SARIF now exists behind `--sarif` (report/sarif.ts), typed against the
 * official 2.1.0 definitions so the compiler rejects a malformed document.
 * This format stays because it carries things SARIF has no room for - the
 * coverage matrix, verified-clean lines, trace limits and the score gauges.
 */

import type { ScanResult } from '../engine/scan.js';
import { LICENCE_SPDX } from '../core/licence.js';

export function renderJson(result: ScanResult, pretty = true): string {
  const bySeverity: Record<string, number> = {};
  for (const finding of result.findings) {
    bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
  }

  const document = {
    tool: {
      name: 'Defuse',
      version: result.coverage.engine.version,
      analysis: result.coverage.engine.analysisLabel,
      // Taken from the capability block rather than retyped here. This list was
      // hand-written once and went stale immediately - it still claimed the
      // tracer worked "within one function (JS/TS/Python)" long after it
      // followed values across files in every language. A machine-readable
      // report that overstates OR understates the engine is the same bug.
      analysisTypes: result.coverage.engine.implemented,
      // Machine-readable, because a consumer feeding this into a compliance
      // pipeline should not have to read a README to learn the terms.
      license: LICENCE_SPDX,
    },
    target: result.target,
    scannedAt: new Date().toISOString(),

    // Placed BEFORE findings on purpose: a consumer reading top-to-bottom meets
    // the caveats before the results.
    honesty: {
      signatureBasedFindings: result.findings.filter((f) => f.confidence === 'signature-based')
        .length,
      flowVerifiedFindings: result.findings.filter((f) => f.confidence === 'flow-verified').length,
      signatureGuessesSupersededByProof: result.stats.signaturesUpgraded,
      signatureGuessesWithdrawnAsSanitised: result.stats.signaturesRetracted,
      meaningOfConfidence: result.coverage.engine.meaningOfConfidence,
      notImplemented: result.coverage.engine.notImplemented,
      dataFlowCoverageByLanguage: result.coverage.taint,
      crossFileResolution: result.crossFile,
      warning:
        'Findings labelled signature-based are UNVERIFIED pattern matches - the data flow was ' +
        'not traced and they may be false positives. Findings labelled flow-verified carry a ' +
        'complete source-to-sink path in `flowPath`; check it rather than trusting the label. ' +
        'Neither label proves exploitability in a running system.',
    },

    summary: {
      total: result.findings.length,
      bySeverity,
      byConfidence: {
        'signature-based': result.findings.filter((f) => f.confidence === 'signature-based').length,
        'flow-verified': result.findings.filter((f) => f.confidence === 'flow-verified').length,
      },
      suppressed: result.suppressions.length,
    },

    findings: result.findings.map((finding) => ({
      ruleId: finding.ruleId,
      ruleName: finding.ruleName,
      severity: finding.severity,
      confidence: finding.confidence,
      verified: finding.verified,
      flowPath: finding.flowPath,
      cwe: finding.cwe,
      owasp: finding.owasp,
      message: finding.message,
      reasoning: finding.reasoning,
      limitations: finding.limitations,
      location: finding.location,
      detectedAt: finding.detectedAt,
    })),

    coverage: {
      counts: result.coverage.counts,
      gaps: result.coverage.gaps,
      matrix: result.coverage.matrix,
      fileTypesPresentButNotScanned: result.coverage.unscannedExtensions,
    },

    diagnostics: {
      stats: result.stats,
      filesByLanguage: result.byLanguage,
      parseProblems: result.parseProblems,
      suppressions: result.suppressions,
      verifiedClean: result.verifiedClean,
      oversizedFilesSkipped: result.oversizedFiles,
      excludedByUser: result.excluded,
      /**
       * What the scan spent on syntax trees.
       *
       * `reparses` above zero means the project did not fit in the tree budget
       * and files were parsed more than once. The findings are unaffected - a
       * re-parse of the same bytes with the same grammar is the same tree - but
       * the scan took longer than it needed to, and saying so is the difference
       * between a user tuning the budget and a user assuming the tool is slow.
       */
      treeMemory: {
        ...result.treeMemory,
        note:
          result.treeMemory.reparses === 0
            ? 'Every file was parsed exactly once; the project fitted in the tree budget.'
            : `The project did not fit in the tree budget, so ${result.treeMemory.reparses} ` +
              'file(s) were parsed more than once. Answers are unchanged; the scan was slower. ' +
              'Raise DEFUSE_TREE_BUDGET_MB to trade memory back for speed.',
      },
    },
  };

  return JSON.stringify(document, null, pretty ? 2 : 0);
}
