/**
 * THE ENGINE, WITH NO PLATFORM ATTACHED
 * =====================================
 *
 * The browser UI was promised, from the first day of this project, to run THIS
 * engine rather than a second implementation of it. Two scanners that drift
 * apart is the failure mode: the web one quietly becoming more optimistic than
 * the CLI, or the reverse, and nobody noticing until a finding disagrees with
 * itself.
 *
 * So the analysis lives here and touches nothing platform-specific - no
 * `node:fs`, no `process`, no file walking. It takes text that is already in
 * memory and returns findings.
 *
 * Two thin shells wrap it:
 *   src/engine/scan.ts   walks a directory and reads files      (the CLI)
 *   ui/worker.js         receives dropped files in a Web Worker (the browser)
 *
 * If either shell ever needs to change how a FINDING is produced, that is the
 * signal that the change belongs in here instead.
 */

import type { Node } from 'web-tree-sitter';
import { buildCoverageReport, type CoverageReport } from './coverage.js';
import {
  flowVerifiedFinding,
  signatureFinding,
  type Finding,
  type Severity,
  SEVERITY_ORDER,
} from './finding.js';
import { extractShapes } from '../engine/shapes.js';
import { nodeLocation } from '../parse/location.js';
import { initEngine, parseSourceFile, type ParsedFile, type ParseIssue } from '../parse/parser.js';
import {
  createTreeStore,
  DEFAULT_TREE_BUDGET_BYTES,
  type TreeStoreStats,
} from '../parse/tree-store.js';
import type { RuleContext, Shape } from '../rules/contract.js';
import { isTestPath } from '../rules/lib/strings.js';
import { getRule, rulesForLanguage, validateRegistry } from '../rules/registry.js';
import {
  buildProjectIndex,
  importSpecifiers,
  indexFunctions,
  type IndexedFileInput,
  type ProjectIndexStats,
} from '../taint/project.js';
import { traceFile, type TraceLimits } from '../taint/tracer.js';

/** A file's text, already loaded by whichever shell is in charge of loading. */
export interface SourceFile {
  readonly path: string;
  readonly source: string;
}

export interface AnalyzeOptions {
  readonly only?: readonly string[];
  readonly noCrossFile?: boolean;
  readonly onProgress?: (done: number, total: number, file: string) => void;
  /** Absolute path -> the path a human should see. Defaults to unchanged. */
  readonly toDisplay?: (absolutePath: string) => string;
  /**
   * How much WebAssembly heap the scan may spend on syntax trees before it
   * starts freeing the least recently used one and parsing it again on demand.
   * See src/parse/tree-store.ts. Bigger is faster; smaller finishes on machines
   * where the default would be killed.
   */
  readonly treeBudgetBytes?: number;
}

export interface FileParseProblem {
  readonly file: string;
  readonly issues: readonly ParseIssue[];
}

export interface Suppression {
  readonly file: string;
  readonly line: number;
  readonly ruleId: string;
  readonly comment: string;
}

export interface AnalysisStats {
  readonly filesParsed: number;
  readonly filesSkipped: number;
  readonly shapesExamined: number;
  readonly flowsVerified: number;
  readonly signaturesUpgraded: number;
  readonly signaturesRetracted: number;
  readonly durationMs: number;
}

/**
 * A place where the tracer followed attacker data to a dangerous call and
 * proved a sanitiser covers it. Not a finding - the opposite of one.
 *
 * Until now these were only COUNTED (`signaturesRetracted`). Naming the lines
 * lets a reader see the difference between "we found nothing here" and "we
 * checked here and it is genuinely fine", which are very different facts.
 */
export interface VerifiedClean {
  readonly file: string;
  readonly line: number;
  readonly ruleId: string;
  readonly kind: string;
}

/**
 * How one file participates in the results.
 *
 * This exists because of a real way the report could mislead. A finding is
 * reported at its SINK - the line where the damage happens - which is correct:
 * that is where the untrusted value is executed. But in a cross-file flow the
 * sink is often innocent plumbing. Given
 *
 *     handler.js:6   runQuery("SELECT ... " + req.query.id)   <- the actual bug
 *     db.js:4        conn.query(sqlText)                      <- reported here
 *
 * `db.js` gets the finding and `handler.js` gets nothing. A file list built
 * only from finding locations would show handler.js as unremarkable - and if
 * it also happened to contain a sanitised line, it would show as *green*. The
 * file a developer has to edit would be the one marked safe.
 *
 * So participation is reported explicitly, and a surface that lists files can
 * say "attacker data passes through here" as its own state - neither a finding
 * nor a clean bill.
 */
export interface FileRole {
  readonly file: string;
  /** Findings whose reported location is in this file. */
  readonly findingsReported: number;
  /**
   * Findings reported in a DIFFERENT file whose traced path passes through
   * this one. Not a finding here, but emphatically not clean either.
   */
  readonly onPathOf: number;
  /** Lines here the tracer reached and proved a sanitiser covers. */
  readonly verifiedCleanLines: number;
  /** Lines here that are a hop on some traced path. Ordered, deduplicated. */
  readonly pathLines: readonly number[];
}

export interface AnalysisResult {
  readonly findings: readonly Finding[];
  /** Lines proven safe by a sanitiser the tracer actually saw run. */
  readonly verifiedClean: readonly VerifiedClean[];
  /** Per-file participation, so "not listed" is never read as "clean". */
  readonly fileRoles: readonly FileRole[];
  /** Where the tracer ran out, counted for THIS scan rather than disclaimed. */
  readonly traceLimits: TraceLimits;
  readonly stats: AnalysisStats;
  readonly byLanguage: Readonly<Record<string, number>>;
  readonly parseProblems: readonly FileParseProblem[];
  readonly suppressions: readonly Suppression[];
  readonly coverage: CoverageReport;
  readonly crossFile:
    | (ProjectIndexStats & { readonly enabled: true })
    | { readonly enabled: false; readonly reason: string };
  /**
   * What the scan spent on syntax trees, and whether it had to trade time for
   * memory to finish. Reported rather than assumed: a scan that spilled gave
   * the same answers more slowly, and the user is entitled to know which of
   * those two things happened to them.
   */
  readonly treeMemory: TreeStoreStats;
}

/**
 * A line ending in `defuse:ignore <rule-id> - <reason>` suppresses that rule
 * on that line. Suppressions are COUNTED AND LISTED in the report: silencing a
 * finding is a decision someone made, and the report should show it, not erase it.
 */
const SUPPRESSION = /defuse:ignore\s+([a-z0-9-]+)(?:\s*[-:]\s*(.*))?/i;

function suppressionOnLine(
  sourceLines: readonly string[],
  line: number,
): { ruleId: string; comment: string } | null {
  // Check the finding's own line and the line above it - both are common.
  for (const candidate of [line - 1, line - 2]) {
    const text = sourceLines[candidate];
    if (!text) continue;
    const match = SUPPRESSION.exec(text);
    if (match?.[1]) return { ruleId: match[1], comment: (match[2] ?? '').trim() };
  }
  return null;
}

/** Findings at the same rule+file+line are the same finding reported twice. */
function dedupeKey(finding: Finding): string {
  return `${finding.ruleId}:${finding.location.file}:${finding.location.startLine}:${finding.location.startColumn}`;
}

export async function analyze(
  inputs: readonly SourceFile[],
  options: AnalyzeOptions = {},
): Promise<AnalysisResult> {
  const started = Date.now();

  // Refuse to run at all if a rule breaks the honesty contract.
  validateRegistry();
  await initEngine();

  const findings: Finding[] = [];
  const seenFindings = new Set<string>();
  // Verified flows are collected separately so that, at the end, we can let a
  // confirmed finding SUPERSEDE the unverified guess at the same place rather
  // than reporting the same bug twice at two different confidence levels.
  const flowFindings: Finding[] = [];
  const seenFlows = new Set<string>();
  const flowRanges: Array<{ ruleId: string; file: string; start: number; end: number }> = [];
  const cleanRanges: Array<{ ruleId: string; file: string; start: number; end: number }> = [];
  const verifiedClean: VerifiedClean[] = [];
  /** Summed across every file, so the report can say where the trace ran out. */
  const traceLimits = {
    astTruncations: 0, depthTruncations: 0, recursionStops: 0, unmodelledHops: 0,
    sourcesFound: 0,
  };
  const suppressions: Suppression[] = [];
  const parseProblems: FileParseProblem[] = [];
  const byLanguage: Record<string, number> = {};

  let filesParsed = 0;
  let filesSkipped = 0;
  let shapesExamined = 0;

  const only = options.only && options.only.length > 0 ? new Set(options.only) : null;

  /* ---------------------------------------------------------------------- *
   * PASS 1 - parse everything, index it, and hand the tree to the store.
   *
   * Analysis cannot begin until the import graph exists, and the import graph
   * cannot exist until every file has been read, so this remains two passes.
   * What CHANGED is what survives in between.
   *
   * It used to be every syntax tree in the project, all at once. A tree lives
   * in WebAssembly memory that the garbage collector cannot reclaim, and
   * nothing ever called delete(), so a scan cost about sixty times the size of
   * the source it was scanning - a hard ceiling around 44 MB of source on an
   * 8 GB machine, past which the operating system killed the process.
   *
   * The comment that used to sit here blamed cross-file tracing and pointed at
   * --no-cross-file as the escape hatch. Measured, that was simply untrue:
   * cross-file OFF used 535.8 MB against 528.8 MB with it ON. The trees were
   * never freed in either mode.
   *
   * Now what survives PASS 1 is a RECORD per file - its text, its parse
   * problems, its functions as byte offsets, its import specifiers as strings -
   * and the tree goes to the store, which keeps as many as the budget allows
   * and re-parses the rest on demand. See src/parse/tree-store.ts.
   * ---------------------------------------------------------------------- */
  const store = createTreeStore(options.treeBudgetBytes ?? DEFAULT_TREE_BUDGET_BYTES);

  /** Everything about a parsed file that does NOT keep its tree alive. */
  interface FileRecord extends IndexedFileInput {
    readonly parsed: Omit<ParsedFile, 'tree' | 'root'>;
  }

  const fileRecords: FileRecord[] = [];
  for (let index = 0; index < inputs.length; index++) {
    const input = inputs[index];
    if (!input) continue;
    options.onProgress?.(index + 1, inputs.length * 2, input.path);

    const outcome = await parseSourceFile(input.path, input.source);
    if (outcome.status === 'skipped') {
      filesSkipped++;
      continue;
    }
    const { tree, root, ...rest } = outcome.file;
    const languageId = outcome.file.language.id;

    // Everything the index needs is read out HERE, while the tree is in hand.
    // After this line nothing but the store may hold it.
    fileRecords.push({
      path: outcome.file.path,
      language: languageId,
      functions: indexFunctions(root, languageId),
      importSpecifiers: importSpecifiers(root, languageId),
      parsed: rest,
    });
    store.admit(outcome.file.path, outcome.file.source, outcome.file.grammar, tree);

    filesParsed++;
    byLanguage[languageId] = (byLanguage[languageId] ?? 0) + 1;
    if (outcome.file.parseIssues.length > 0) {
      parseProblems.push({ file: input.path, issues: outcome.file.parseIssues });
    }
  }

  // How an absolute path should be shown to a human. The CLI shortens paths
  // against the working directory; a browser has no working directory, so it
  // passes them straight through. Everything downstream uses whatever this says.
  const toDisplay = options.toDisplay ?? ((absolutePath: string): string => absolutePath);

  /* ---------------------------------------------------------------------- *
   * PASS 2 - build the import graph, then analyse.
   * ---------------------------------------------------------------------- */
  /**
   * The cross-file ceiling, which is now about the INDEX rather than the trees.
   *
   * It used to be justified by "cross-file analysis needs every syntax tree in
   * memory at once, and a tree costs roughly ten times its source" - two claims,
   * both wrong. The trees were held whether or not cross-file was on, and the
   * cost is nearer sixty times than ten. What the index genuinely holds is a
   * name, a parameter list and two integers per function, which is a few
   * megabytes on a project of this size.
   *
   * The limit stays because an index over an enormous project is still real
   * memory and a resolution over it is still real time, and because a stated
   * limit that fires is better than an unstated one that kills the process. It
   * is now what it always should have been: a threshold with a reason, not a
   * consequence of a leak.
   */
  const MAX_CROSS_FILE_SOURCE_BYTES = 64 * 1024 * 1024;
  const totalSourceBytes = fileRecords.reduce((sum, f) => sum + f.parsed.source.length, 0);
  const tooBig = totalSourceBytes > MAX_CROSS_FILE_SOURCE_BYTES;

  const crossFileEnabled = !options.noCrossFile && !tooBig;
  const crossFileOffReason = options.noCrossFile
    ? 'cross-file resolution was switched off'
    : `project is ${(totalSourceBytes / 1048576).toFixed(0)}MB of source, over the ` +
      `${MAX_CROSS_FILE_SOURCE_BYTES / 1048576}MB ceiling for indexing every function in the project`;
  const projectIndex = crossFileEnabled ? buildProjectIndex(fileRecords, store) : undefined;

  // A finding can now land in a file other than the one being scanned, so the
  // suppression check needs any file's lines on demand. Splitting every source
  // eagerly doubled peak memory on a large tree for data most scans never read,
  // so it is computed lazily and cached.
  const sourceByDisplayPath = new Map<string, string>();
  for (const record of fileRecords) {
    sourceByDisplayPath.set(toDisplay(record.path), record.parsed.source);
  }
  const lineCache = new Map<string, string[]>();
  const linesOf = (displayPath: string): string[] => {
    const cached = lineCache.get(displayPath);
    if (cached) return cached;
    const lines = (sourceByDisplayPath.get(displayPath) ?? '').split('\n');
    lineCache.set(displayPath, lines);
    return lines;
  };

  for (let index = 0; index < fileRecords.length; index++) {
    const record = fileRecords[index];
    if (!record) continue;
    const filePath = record.path;
    options.onProgress?.(inputs.length + index + 1, inputs.length * 2, filePath);

    /* ---- the tree comes back here, and is pinned for this iteration ----
     *
     * Usually it was never gone: the store holds everything that fits in the
     * budget, so a normal project parses each file exactly once and this is a
     * lookup. On a project too big for the budget it is a re-parse, which costs
     * time the old code did not spend - and the old code, on a project that
     * size, did not finish at all.
     *
     * The pin is what makes it safe. Every Node produced below points into this
     * tree's memory; freeing it while a rule or the tracer still holds one would
     * not raise an error, it would read whatever moved in afterwards.        */
    store.pin(filePath);
    const tree = store.get(filePath);
    const file: ParsedFile = { ...record.parsed, tree, root: tree.rootNode };

    const displayPath = toDisplay(filePath);
    const sourceLines = linesOf(displayPath);

    const context: RuleContext = {
      file,
      language: file.language.id,
      text: (node: Node) => (node.text ?? '').replace(/\s+/g, ' ').trim(),
    };

    const shapes = await extractShapes(file, file.language.id);
    shapesExamined += shapes.length;

    const rules = rulesForLanguage(file.language.id).filter((r) => !only || only.has(r.id));

    for (const shape of shapes) {
      for (const rule of rules) {
        if (!rule.shapes.includes(shape.kind as Shape['kind'])) continue;

        let hit;
        try {
          hit = rule.check(shape, context);
        } catch (error) {
          // A crashing rule must not take the scan down, and must not be silent.
          parseProblems.push({
            file: filePath,
            issues: [
              {
                kind: 'ERROR',
                line: shape.node.startPosition.row + 1,
                column: shape.node.startPosition.column + 1,
                text: `rule '${rule.id}' threw: ${(error as Error).message}`.slice(0, 120),
              },
            ],
          });
          continue;
        }
        if (!hit) continue;

        const location = nodeLocation(hit.node, displayPath);

        const suppressed = suppressionOnLine(sourceLines, location.startLine);
        if (suppressed && (suppressed.ruleId === rule.id || suppressed.ruleId === 'all')) {
          suppressions.push({
            file: displayPath,
            line: location.startLine,
            ruleId: rule.id,
            comment: suppressed.comment || '(no reason given)',
          });
          continue;
        }

        /*
         * TEST-FILE SEVERITY, DECIDED IN ONE PLACE FOR EVERY RULE.
         *
         * This policy used to live inside hardcoded-secret alone, which meant a
         * fake password in a test dropped to low while an `eval()` in the file
         * next to it stayed critical. Scanning pandas made the cost visible: 41
         * critical findings, 33 of them inside the test suite, burying the eight
         * in shipped code that were the actual answer.
         *
         * The reason to discount a test file is not that the finding is wrong -
         * `eval()` in a test IS Python's eval - it is that the attacker position
         * does not exist. Nobody reaches your test suite over the network. So
         * the finding is kept, always, and only its rank changes.
         *
         * Doing it here rather than in each rule means a rule added next year
         * inherits it without anyone remembering to.
         *
         * NOT APPLIED TO FLOW-VERIFIED FINDINGS, deliberately. isTestPath is a
         * guess about a path, and it is wrong sometimes in the expensive
         * direction: pandas SHIPS `pandas/_testing/`, and plenty of projects
         * ship an `examples/` directory that real users copy from. A traced
         * source-to-sink path is the strongest evidence this tool produces, and
         * a filename pattern is not good enough grounds to quiet it.
         */
        const inTestFile = isTestPath(file.path);
        const testRank = (s: Severity): Severity =>
          !inTestFile ? s : s === 'critical' ? 'medium' : s === 'high' ? 'low' : s;

        const finding = signatureFinding({
          ruleId: rule.id,
          ruleName: rule.name,
          cwe: rule.cwe,
          owasp: rule.owasp,
          severity: testRank(hit.severity ?? rule.severity),
          message: hit.message,
          location,
          reasoning:
            hit.reasoning +
            (inTestFile
              ? ' NOTE: this file looks like a test, fixture or example. The finding is ' +
                'accurate about the code, but a test suite is not reachable by an attacker, ' +
                'so severity is lowered rather than the finding dropped - test code does get ' +
                'copied into production, and this is still in git history either way.'
              : ''),
          limitations: hit.limitations ?? rule.limitations,
        });

        const key = dedupeKey(finding);
        if (seenFindings.has(key)) continue;
        seenFindings.add(key);
        findings.push(finding);
      }
    }

    /* ------------------------------------------------------------------ *
     * PHASE 3a: data-flow verification.
     *
     * The signature pass above asked "does this code have the SHAPE of a bug?".
     * This pass asks the harder question: "did attacker-controlled data
     * actually get here?" Only this pass may produce flow-verified findings,
     * and only because it can hand over the path that proves it.
     * ------------------------------------------------------------------ */
    const trace = traceFile(file, file.language.id, projectIndex, toDisplay);
    traceLimits.astTruncations += trace.limits.astTruncations;
    traceLimits.depthTruncations += trace.limits.depthTruncations;
    traceLimits.recursionStops += trace.limits.recursionStops;
    traceLimits.unmodelledHops += trace.limits.unmodelledHops;
    traceLimits.sourcesFound += trace.limits.sourcesFound;

    // Lines where a tainted value reached a sink but was properly sanitised.
    // The signature pass cannot see a sanitiser, so it guessed; the tracer can,
    // so the guess is withdrawn rather than left to nag.
    for (const clean of trace.sanitized) {
      verifiedClean.push({
        file: clean.filePath || displayPath,
        line: clean.sinkNode.startPosition.row + 1,
        ruleId: clean.ruleId,
        kind: clean.kind,
      });
      cleanRanges.push({
        ruleId: clean.ruleId,
        file: clean.filePath || displayPath,
        start: clean.sinkNode.startPosition.row + 1,
        end: clean.sinkNode.endPosition.row + 1,
      });
    }

    /** Supersede the signature pass everywhere this flow touched. */
    const recordFlowRanges = (
      f: (typeof trace.flows)[number],
      file: string,
    ): void => {
      flowRanges.push({
        ruleId: f.ruleId,
        file,
        start: f.sinkNode.startPosition.row + 1,
        end: f.sinkNode.endPosition.row + 1,
      });
      for (const hop of f.path) {
        flowRanges.push({
          ruleId: f.ruleId,
          file: hop.location.file,
          start: hop.location.startLine,
          end: hop.location.endLine,
        });
      }
    };

    for (const flow of trace.flows) {
      if (only && !only.has(flow.ruleId)) continue;
      const rule = getRule(flow.ruleId);
      if (!rule) continue;

      // The sink may be in a different file from the one we are scanning.
      const flowFile = flow.filePath || displayPath;
      const location = nodeLocation(flow.node, flowFile);
      const suppressed = suppressionOnLine(linesOf(flowFile), location.startLine);
      if (suppressed && (suppressed.ruleId === flow.ruleId || suppressed.ruleId === 'all')) {
        suppressions.push({
          file: flowFile,
          line: location.startLine,
          ruleId: flow.ruleId,
          comment: suppressed.comment || '(no reason given)',
        });
        continue;
      }

      const hops = flow.path.length;
      const unmodelled = [...new Set(flow.unknownHops)];
      const unmodelledNote =
        unmodelled.length > 0
          ? ` THIS PATH PASSES THROUGH ${unmodelled.length} FUNCTION(S) WE DO NOT MODEL ` +
            `(${unmodelled.map((n) => `\`${n}()\``).join(', ')}). We assumed each one preserves ` +
            `the value. If any of them sanitises it, this finding is wrong - check those hops first.`
          : '';
      /*
       * A BRANCH WAS ASSUMED, SO THIS IS A GUESS - AND IT IS STILL REPORTED.
       *
       * The tracer keeps taint through a clean write it cannot prove happens,
       * which is deliberately cautious and right: it errs toward reporting a
       * value that might be clean rather than staying silent about one that
       * might be dirty. What it may not do is hand that assumption to
       * flowVerifiedFinding(), which prints "this is not a pattern guess - the
       * data flow was followed". At that point nothing was followed.
       *
       * Django found it. In contrib/admin/options.py a tainted `msg` is set in
       * an `except` block and a clean literal `msg` is set in an `elif` forty
       * lines later; the sink is reachable only through the second. Seven
       * correct-looking hops, across two files, proving a flow that cannot run.
       *
       * DROPPING IT WAS THE WRONG FIX, and the benchmark said so within a
       * minute: recall fell 89.3% to 75.5%, because 89 real vulnerabilities in
       * BenchmarkJava sit behind exactly this shape and the signature rules did
       * not cover those lines. Silence about a real bug is the failure this
       * scanner cannot detect in itself.
       *
       * So the finding survives with the label it has earned. The path is still
       * printed - a reader can check the branch themselves - and the reasoning
       * says which assumption it rests on.
       */
      /*
       * THE SECOND REASON A TRACE CANNOT CALL ITSELF PROVEN.
       *
       * branchAssumed is "we did not evaluate the branch". containerGuess is
       * "we did not track which element". Both are the same failure in the same
       * place - the engine wrote its own imprecision into the path and then
       * labelled the result proven anyway - so both get the same treatment: the
       * finding survives, the path is still printed, and the label tells the
       * truth about what was and was not followed.
       *
       * Measured on OWASP BenchmarkJava: flow-verified paths that collect into a
       * container scored 50.5% precision against 71.5% for paths that do not.
       * Half the bucket was a coin flip wearing a certificate.
       */
      if (flow.branchAssumed || flow.containerGuess) {
        const downgraded = signatureFinding({
            ruleId: rule.id,
            ruleName: rule.name,
            cwe: rule.cwe,
            owasp: rule.owasp,
            severity: rule.severity,
            message: `Possibly attacker-controlled data from \`${flow.origin}\` reaches ${flow.sinkDescription}`,
            location,
            reasoning: flow.branchAssumed
              ? `A value from \`${flow.origin}\` can reach ${flow.sinkDescription}, but the ` +
              `path depends on a BRANCH THIS ENGINE DOES NOT EVALUATE: somewhere along it a ` +
              `clean assignment sits inside an if/else, and we keep the taint rather than ` +
              `assume the clean write always happens. That is the cautious reading, not a ` +
              `proven one - if the two writes are in mutually exclusive branches, this path ` +
              `cannot actually run. Check the branch before acting on it.`
              : `A value from \`${flow.origin}\` can reach ${flow.sinkDescription}, but the ` +
                `path runs through a COLLECTION THAT TOOK MORE THAN ONE ELEMENT. We taint a ` +
                `container as a whole and do not model which index or key comes back out, so ` +
                `the value printed here may be one of the clean ones that went in. The dirty ` +
                `value really is in that container - this is worth checking - but the trace ` +
                `does not prove it is the one that arrives.`,
            limitations: rule.limitations,
          });
        const key = dedupeKey(downgraded);
        if (!seenFlows.has(key)) {
          seenFlows.add(key);
          flowFindings.push(downgraded);
          /*
           * RECORD THE RANGES EVEN THOUGH NOTHING WAS PROVEN.
           *
           * A downgraded flow and the signature rule that fired on the same
           * line are ONE bug described twice, exactly as in the verified case,
           * and before this the downgraded branch skipped straight past the
           * bookkeeping - so branch-assumed.py has been reporting line 46
           * twice, once from the rule and once from the tracer, for as long as
           * branchAssumed has existed. It was invisible because so few lines hit
           * both paths; containerGuess routes 183 more BenchmarkJava cases
           * through here and would have made it loud.
           *
           * The tracer's version wins because it carries the path: same
           * confidence, strictly more for a reader to check.
           */
          recordFlowRanges(flow, flowFile);
        }
        continue;
      }

      const finding = flowVerifiedFinding({
        unmodelledHops: flow.unknownHops,
        ruleId: rule.id,
        ruleName: rule.name,
        cwe: rule.cwe,
        owasp: rule.owasp,
        severity: rule.severity,
        message: `Attacker-controlled data from \`${flow.origin}\` reaches ${flow.sinkDescription}`,
        location,
        reasoning:
          `Traced ${hops} step${hops === 1 ? '' : 's'}${
            new Set(flow.path.map((step) => step.location.file)).size > 1
              ? ' across more than one file'
              : ''
          }: the value starts at ` +
          `\`${flow.origin}\`, which is attacker-controlled, and arrives at ${flow.sinkDescription} ` +
          `with no sanitiser for a ${flow.kind} sink applied on the way. Every hop is listed below. ` +
          `This is not a pattern guess - the data flow was followed.`,
        limitations:
          'FLOW-VERIFIED: the value was followed hop by hop, across function boundaries and - ' +
          'where imports resolve - across files. Only files included in this scan are resolved: ' +
          'a call into a third-party package, a dynamic import, or a name several modules define ' +
          'all end the trace. The tracer identifies sources by expression shape (a `req.query`-' +
          'looking expression is assumed to be a real request), reads statements in order without ' +
          'evaluating branch conditions, and does not track the interior of objects. It confirms ' +
          'the data flow, not exploitability in production - authentication, a WAF or ' +
          'framework-level escaping may still stand in the way.' + unmodelledNote,
        flowPath: flow.path,
      });

      const key = dedupeKey(finding);
      if (seenFlows.has(key)) continue;
      seenFlows.add(key);
      flowFindings.push(finding);
      // Record EVERY line the verified flow passes through, not just the sink.
      // `const sql = "..." + userId;` on one line and `db.query(sql)` on the
      // next are one bug, and the signature pass reports the first line while
      // the tracer reports the second. Superseding along the whole path stops
      // the same bug appearing twice at two confidence levels.
      flowRanges.push({
        ruleId: flow.ruleId,
        file: flowFile,
        start: flow.sinkNode.startPosition.row + 1,
        end: flow.sinkNode.endPosition.row + 1,
      });
      for (const hop of flow.path) {
        flowRanges.push({
          ruleId: flow.ruleId,
          file: hop.location.file,
          start: hop.location.startLine,
          end: hop.location.endLine,
        });
      }
    }

    /* ---- the only safe place to let trees go ----
     *
     * Everything above has finished with this file: the rules have run, the
     * tracer has returned, and every finding has been copied into plain data
     * (paths, line numbers, text) rather than nodes. No Node from this file or
     * from any file the tracer descended into is reachable any more, so the
     * pins can be dropped and the store can reclaim whatever it needs to.
     *
     * Releasing anywhere INSIDE the loop body would be a use-after-free waiting
     * for a big enough project to expose it.                                 */
    store.releaseAll();
  }

  // Findings are plain data by now; nothing below reads a syntax node.
  const treeStoreStats = store.stats();
  store.disposeAll();

  /* -------------------------------------------------------------------- *
   * MERGE. A signature finding at a place we have now verified is not a
   * second bug - it is the same bug, guessed at. The verified one wins and
   * the guess is dropped. Everything the tracer could NOT confirm stays
   * exactly as it was, still labelled signature-based. That is the whole
   * point: precision where we earned it, recall everywhere else, and a
   * report that shows you the split.
   * -------------------------------------------------------------------- */
  const supersededBy = (finding: Finding): boolean =>
    flowRanges.some(
      (range) =>
        range.ruleId === finding.ruleId &&
        range.file === finding.location.file &&
        finding.location.startLine >= range.start &&
        finding.location.startLine <= range.end,
    );

  const provenClean = (finding: Finding): boolean =>
    cleanRanges.some(
      (range) =>
        range.ruleId === finding.ruleId &&
        range.file === finding.location.file &&
        finding.location.startLine >= range.start &&
        finding.location.startLine <= range.end,
    );

  const afterUpgrade = findings.filter((f) => !supersededBy(f));
  const signaturesUpgraded = findings.length - afterUpgrade.length;
  const survivingSignatures = afterUpgrade.filter((f) => !provenClean(f));
  const signaturesRetracted = afterUpgrade.length - survivingSignatures.length;
  const allFindings: Finding[] = [...flowFindings, ...survivingSignatures];

  allFindings.sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (bySeverity !== 0) return bySeverity;
    const byFile = a.location.file.localeCompare(b.location.file);
    if (byFile !== 0) return byFile;
    return a.location.startLine - b.location.startLine;
  });

  // Participation is derived here, once, from the finished finding list - so
  // the terminal and the browser cannot disagree about which files a flow
  // touches, and neither one has to work it out for itself.
  const roles = new Map<string, { reported: number; via: number; clean: number; lines: Set<number> }>();
  const roleFor = (file: string) => {
    let entry = roles.get(file);
    if (!entry) {
      entry = { reported: 0, via: 0, clean: 0, lines: new Set() };
      roles.set(file, entry);
    }
    return entry;
  };
  for (const finding of allFindings) {
    roleFor(finding.location.file).reported++;
    for (const file of new Set((finding.flowPath ?? []).map((s) => s.location.file))) {
      // Counted only when the finding is reported SOMEWHERE ELSE - otherwise
      // every flow-verified finding would also mark its own file as "on path",
      // which says nothing.
      if (file !== finding.location.file) roleFor(file).via++;
    }
    for (const step of finding.flowPath ?? []) {
      roleFor(step.location.file).lines.add(step.location.startLine);
    }
  }
  for (const clean of verifiedClean) roleFor(clean.file).clean++;

  const fileRoles: FileRole[] = [...roles.entries()]
    .map(([file, entry]) => ({
      file,
      findingsReported: entry.reported,
      onPathOf: entry.via,
      verifiedCleanLines: entry.clean,
      pathLines: [...entry.lines].sort((a, b) => a - b),
    }))
    .sort((a, b) => a.file.localeCompare(b.file));

  return {
    findings: allFindings,
    verifiedClean,
    fileRoles,
    traceLimits,
    stats: {
      filesParsed,
      filesSkipped,
      shapesExamined,
      flowsVerified: flowFindings.length,
      signaturesUpgraded,
      signaturesRetracted,
      durationMs: Date.now() - started,
    },
    byLanguage,
    parseProblems,
    suppressions,
    crossFile: projectIndex
      ? { enabled: true as const, ...projectIndex.stats() }
      : { enabled: false as const, reason: crossFileOffReason },
    treeMemory: treeStoreStats,
    coverage: buildCoverageReport(),
  };
}
