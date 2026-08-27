/**
 * THE NODE SHELL
 * ==============
 *
 * Everything that only makes sense on a machine with a filesystem: walking a
 * directory, honouring --exclude, reading bytes, and shortening paths against
 * the working directory so terminal output stays readable.
 *
 * The analysis itself is NOT here. It moved to src/core/analyze.ts when the
 * browser UI arrived, so the web version could run the same code rather than a
 * lookalike. What is left is the pipeline seam:
 *
 *   collectFiles  ->  read text  ->  analyze()  ->  a ScanResult
 *
 * If you find yourself wanting to change how a FINDING is produced, this is the
 * wrong file - that belongs in core/analyze.ts, where the browser sees it too.
 */

import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { analyze, type AnalysisResult, type SourceFile } from '../core/analyze.js';
import { buildCoverageReport, type CoverageReport } from '../core/coverage.js';
import type { Finding } from '../core/finding.js';
import { SCANNABLE_EXTENSIONS } from '../parse/languages.js';
import { useNodeGrammars } from '../parse/node-grammars.js';
import { collectFiles } from './walk.js';

export type { FileParseProblem, Suppression } from '../core/analyze.js';

export interface ScanOptions {
  /** Only run these rule ids. Empty = all. */
  readonly only?: readonly string[];
  /** Glob-ish paths to skip entirely. Reported, never silently applied. */
  readonly exclude?: readonly string[];
  /** Turn off cross-file resolution (faster, less memory, fewer findings). */
  readonly noCrossFile?: boolean;
  /** Print progress to stderr. */
  readonly onProgress?: (done: number, total: number, file: string) => void;
}

export interface ScanResult {
  readonly target: string;
  readonly findings: readonly Finding[];
  /** Lines the tracer proved safe. Reported so "clean" can mean "checked". */
  readonly verifiedClean: AnalysisResult['verifiedClean'];
  /** Per-file participation, so a file a flow passes through is never "clean". */
  readonly fileRoles: AnalysisResult['fileRoles'];
  /** Where the tracer ran out, counted for this scan. */
  readonly traceLimits: AnalysisResult['traceLimits'];
  readonly stats: AnalysisResult['stats'] & {
    readonly filesFound: number;
    readonly filesWithParseErrors: number;
  };
  readonly byLanguage: AnalysisResult['byLanguage'];
  readonly parseProblems: AnalysisResult['parseProblems'];
  readonly oversizedFiles: readonly string[];
  /** What --exclude removed. A gap the user chose is still a gap worth printing. */
  readonly excluded: {
    readonly patterns: readonly string[];
    readonly fileCount: number;
    readonly directories: readonly string[];
  };
  /** Findings the code explicitly asked us to ignore. Reported, never hidden. */
  readonly suppressions: AnalysisResult['suppressions'];
  readonly coverage: CoverageReport;
  /** How cross-file resolution went. */
  readonly crossFile: AnalysisResult['crossFile'];
}

export async function scan(target: string, options: ScanOptions = {}): Promise<ScanResult> {
  // Tell the parser it is running on Node before anything loads a grammar.
  // The browser worker makes the equivalent call with its own loader.
  useNodeGrammars();

  const walk = await collectFiles(target, {
    scannable: SCANNABLE_EXTENSIONS,
    exclude: options.exclude ?? [],
  });

  // Read the text. A file we cannot read simply never reaches the analyzer;
  // it shows up as the gap between filesFound and filesParsed.
  const inputs: SourceFile[] = [];
  for (const filePath of walk.files) {
    try {
      inputs.push({ path: filePath, source: await readFile(filePath, 'utf8') });
    } catch {
      // permissions, a broken symlink, a race with a build tool
    }
  }

  const result = await analyze(inputs, {
    ...(options.only ? { only: options.only } : {}),
    ...(options.noCrossFile !== undefined ? { noCrossFile: options.noCrossFile } : {}),
    ...(options.onProgress ? { onProgress: options.onProgress } : {}),
    toDisplay: (absolutePath) => path.relative(process.cwd(), absolutePath) || absolutePath,
  });

  return {
    target,
    findings: result.findings,
    verifiedClean: result.verifiedClean,
    fileRoles: result.fileRoles,
    traceLimits: result.traceLimits,
    stats: {
      ...result.stats,
      filesFound: walk.files.length,
      filesSkipped: walk.files.length - result.stats.filesParsed,
      filesWithParseErrors: result.parseProblems.length,
    },
    byLanguage: result.byLanguage,
    parseProblems: result.parseProblems,
    oversizedFiles: walk.oversizedFiles,
    excluded: {
      patterns: options.exclude ?? [],
      fileCount: walk.excludedCount,
      directories: walk.excludedDirectories,
    },
    suppressions: result.suppressions,
    crossFile: result.crossFile,
    // Rebuilt here because only the walker knows which file types it passed
    // over - the analyzer never saw them.
    coverage: buildCoverageReport(
      [...walk.skippedByExtension.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 12)
        .map(([ext, count]) => `${ext} (${count} file${count === 1 ? '' : 's'})`),
    ),
  };
}
