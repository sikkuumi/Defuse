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
 * FORWARD COMPATIBILITY: the shape deliberately resembles SARIF (the OASIS
 * standard that GitHub code scanning consumes) without pretending to be it.
 * Emitting invalid SARIF and calling it SARIF would be its own small lie;
 * a real SARIF exporter is a named Phase 6 item.
 */

import type { ScanResult } from '../engine/scan.js';

export function renderJson(result: ScanResult, pretty = true): string {
  const bySeverity: Record<string, number> = {};
  for (const finding of result.findings) {
    bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
  }

  const document = {
    tool: {
      name: 'NS-1 SecureScan',
      version: result.coverage.engine.version,
      analysis: result.coverage.engine.analysisLabel,
      // Taken from the capability block rather than retyped here. This list was
      // hand-written once and went stale immediately - it still claimed the
      // tracer worked "within one function (JS/TS/Python)" long after it
      // followed values across files in all five languages. A machine-readable
      // report that overstates OR understates the engine is the same bug.
      analysisTypes: result.coverage.engine.implemented,
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
    },
  };

  return JSON.stringify(document, null, pretty ? 2 : 0);
}
