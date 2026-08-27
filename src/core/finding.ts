/**
 * THE HONESTY CONTRACT
 * ====================
 *
 * This file is the most important file in the project. Everything else is
 * plumbing. Read this one carefully.
 *
 * NS-1 SecureScan promises one thing that Snyk / Semgrep / SonarQube do not
 * promise clearly: every single finding tells you HOW SURE we are, in a way you
 * can act on. There are exactly two levels, and they mean precise things:
 *
 *   "signature-based"  We matched a SHAPE in your code. We saw a pattern that
 *                      is *often* a vulnerability. We did NOT trace where the
 *                      data actually came from. This might be a real bug, or it
 *                      might be completely safe. YOU still have to look.
 *
 *   "flow-verified"    We traced actual data, step by step, from a place an
 *                      attacker controls (a "source", e.g. an HTTP request)
 *                      all the way into a dangerous operation (a "sink", e.g.
 *                      a database query), and we confirmed nothing cleaned it
 *                      up along the way. We can show you every hop.
 *
 * A RULE CAN ONLY EVER PRODUCE "signature-based". Only the taint engine can
 * produce the other label.
 *
 * We do not enforce that with willpower or a code review checklist. We enforce
 * it with the type system:
 *
 *   - A FlowVerifiedFinding REQUIRES a non-empty `flowPath` of concrete steps.
 *   - Only the taint engine can build one. A rule cannot, because a rule only
 *     ever sees a single shape - it has no idea where the value came from.
 *   - So a rule physically cannot emit a "flow-verified" finding: there is no
 *     path it could supply, and TypeScript refuses to compile the attempt.
 *
 * That is the difference between a promise and a guarantee.
 *
 * ARCHITECTURAL DECISION (matters later): we are modelling Finding as a
 * "discriminated union" - two shapes sharing one `confidence` tag - rather than
 * one flat object with an optional flag. The taint engine supplies the second
 * shape, and every report renderer is forced by the compiler to handle it.
 * Nothing silently upgrades its own confidence.
 */

import { LANGUAGES } from '../parse/languages.js';


/** The two - and only two - confidence levels this tool will ever emit. */
export type Confidence = 'signature-based' | 'flow-verified';

/**
 * Severity = "how bad is this if it turns out to be real?"
 * Deliberately separate from confidence, which is "how sure are we it's real?"
 * Conflating those two numbers is the single most common lie in SAST tooling:
 * a tool shows one "risk" bar and you cannot tell whether it means
 * "probably harmless but catastrophic if not" or "definitely real but minor".
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/**
 * Exactly where in the code this was found.
 * We keep the raw AST node type and its ancestry so a finding is reproducible:
 * you can point at the same node again later and check whether we were right.
 */
export interface CodeLocation {
  /** Path as the user gave it to us (relative where possible - nicer to read). */
  readonly file: string;
  /** 1-based, because humans and editors count from 1. Tree-sitter counts from 0. */
  readonly startLine: number;
  readonly startColumn: number;
  readonly endLine: number;
  readonly endColumn: number;
  /** The tree-sitter node type we matched, e.g. "binary_expression". */
  readonly astNodeType: string;
  /** Ancestry of that node, e.g. "program > lexical_declaration > call_expression". */
  readonly astNodePath: string;
  /** The exact source text that matched, trimmed for display. */
  readonly snippet: string;
}

/**
 * One hop in a data-flow trace. Produced only by the taint engine, which is the
 * only component that watches a value move. Defined as a public, reviewable
 * shape rather than a vague promise: if a hop cannot be described and located,
 * it does not belong in a path.
 */
export interface FlowStep {
  readonly kind: 'source' | 'propagation' | 'sanitizer' | 'sink';
  readonly location: CodeLocation;
  readonly description: string;
}

interface FindingBase {
  /** Stable machine id, e.g. "sql-injection". Used by --json and by tests. */
  readonly ruleId: string;
  /** Human title, e.g. "SQL query built by string concatenation". */
  readonly ruleName: string;
  /** Common Weakness Enumeration id, the industry's shared bug catalogue. */
  readonly cwe: string;
  /** Which OWASP Top 10 (2025) category this belongs to. */
  readonly owasp: string;
  readonly severity: Severity;
  /** One line, plain language, shown in terminal output. */
  readonly message: string;
  readonly location: CodeLocation;
  /**
   * WHY did this match? Written for a human who is deciding whether to care.
   * Required, never optional - a finding with no explanation is a guess with a
   * badge on.
   */
  readonly reasoning: string;
  /**
   * What this particular check CANNOT tell you. Required for the same reason.
   * e.g. "We did not check whether `userId` is attacker-controlled."
   */
  readonly limitations: string;
  /** ISO-8601 timestamp of the scan that produced this. */
  readonly detectedAt: string;
}

/** A pattern match. Unverified by design - this is what the rule engine emits. */
export interface SignatureFinding extends FindingBase {
  readonly confidence: 'signature-based';
  readonly verified: false;
  /** Explicitly null, not missing: "we looked at flow" is never implied. */
  readonly flowPath: null;
}

/** A confirmed source-to-sink trace. Only the taint engine can construct one. */
export interface FlowVerifiedFinding extends FindingBase {
  readonly confidence: 'flow-verified';
  readonly verified: true;
  /** Must contain at least a source and a sink. Enforced at construction. */
  readonly flowPath: readonly FlowStep[];
  /**
   * Functions on this path that we do not model, named.
   *
   * THE WEAKEST LINK, PROMOTED TO A FIELD. `flow-verified` promises the value
   * was traced with no sanitiser on the path. When a hop passes through a
   * function we have never heard of, "no sanitiser" is an ASSUMPTION rather
   * than an observation - if that function sanitises, the finding is wrong.
   *
   * The path step and the prose limitations both said so already. This did not:
   * a consumer filtering `confidence === 'flow-verified'` out of --json got the
   * unqualified promise with no way to tell a fully-modelled trace from one
   * resting on an assumption. A caveat that only exists in prose is a caveat
   * machines cannot honour, which makes it half a caveat.
   *
   * Empty means every hop on this path is modelled. That is the strong case.
   */
  readonly unmodelledHops: readonly string[];
}

export type Finding = SignatureFinding | FlowVerifiedFinding;

/**
 * The constructor for everything the RULE engine produces.
 *
 * Note what it does not accept: there is no `confidence` parameter. A rule
 * author cannot pass "flow-verified" even by mistake, because the value is
 * hard-coded here and nowhere else.
 */
export function signatureFinding(
  input: Omit<FindingBase, 'detectedAt'> & { detectedAt?: string },
): SignatureFinding {
  return {
    ruleId: input.ruleId,
    ruleName: input.ruleName,
    cwe: input.cwe,
    owasp: input.owasp,
    severity: input.severity,
    message: input.message,
    location: input.location,
    reasoning: input.reasoning,
    limitations: input.limitations,
    detectedAt: input.detectedAt ?? new Date().toISOString(),
    confidence: 'signature-based',
    verified: false,
    flowPath: null,
  };
}

/**
 * THE SECOND CONSTRUCTOR.
 *
 * For the whole first stretch of this project, this function threw. It was a
 * deliberate, documented stub: the type for a flow-verified finding existed, so
 * anyone could read what the claim would REQUIRE, but nothing could produce one.
 *
 * It is real now, and the requirement did not soften. Note the runtime checks
 * below: a flow-verified finding must carry a path that BEGINS at a source and
 * ENDS at a sink. Not "a path". Not "some steps". If the taint engine ever
 * hands over a path that doesn't start where attacker data enters and finish
 * where it does damage, this throws rather than emitting the claim.
 *
 * The type system stops a rule from lying. This function stops the ENGINE from
 * lying - including a future version of it written by someone in a hurry.
 */
export function flowVerifiedFinding(
  input: Omit<FindingBase, 'detectedAt'> & {
    detectedAt?: string;
    flowPath: readonly FlowStep[];
    unmodelledHops?: readonly string[];
  },
): FlowVerifiedFinding {
  const path = input.flowPath;

  if (path.length < 2) {
    throw new Error(
      `flowVerifiedFinding: a verified path needs at least a source and a sink, got ${path.length} step(s).`,
    );
  }
  if (path[0]?.kind !== 'source') {
    throw new Error(
      `flowVerifiedFinding: path must begin at a source, begins at '${path[0]?.kind}'.`,
    );
  }
  if (path[path.length - 1]?.kind !== 'sink') {
    throw new Error(
      `flowVerifiedFinding: path must end at a sink, ends at '${path[path.length - 1]?.kind}'.`,
    );
  }
  // A path containing a sanitiser is, by definition, not a confirmed exploit.
  // If the engine ever tries to report one, that is a bug in the engine and we
  // would rather crash the scan than publish the claim.
  const sanitised = path.find((step) => step.kind === 'sanitizer');
  if (sanitised) {
    throw new Error(
      `flowVerifiedFinding: path contains a sanitiser (${sanitised.description}) - that is a CLEAN flow, not a verified vulnerability.`,
    );
  }

  return {
    ruleId: input.ruleId,
    ruleName: input.ruleName,
    cwe: input.cwe,
    owasp: input.owasp,
    severity: input.severity,
    message: input.message,
    location: input.location,
    reasoning: input.reasoning,
    limitations: input.limitations,
    detectedAt: input.detectedAt ?? new Date().toISOString(),
    confidence: 'flow-verified',
    verified: true,
    flowPath: path,
    unmodelledHops: input.unmodelledHops ?? [],
  };
}

/** What this build of the engine can and cannot do. Printed in every report. */
export const ENGINE_CAPABILITIES = {
  /**
   * What the banner prints, on the terminal and in the browser.
   *
   * A phase number used to live here. It described OUR build order, not
   * anything a user of the tool can act on - and it went stale the moment work
   * happened out of order: the banner read "PHASE 3C" while the version string
   * read "phase2", which is precisely the kind of small lie this project exists
   * to not tell. A capability label cannot drift, because it can only change
   * when the engine actually changes.
   */
  analysisLabel: 'SIGNATURE + DATA FLOW',
  version: '0.5.0',
  implemented: [
    `Tree-sitter AST parsing for ${LANGUAGES.map((l) => l.displayName).join(', ')}`,
    'Pattern (signature) matching over real syntax trees, not text/regex',
    `Taint analysis in all ${LANGUAGES.length} languages: source to sink, following values into other functions AND - in every language except PHP - into other files through resolved imports`,
    'Prepared-statement awareness: arguments bound to a prepared query are parameters, not instructions',
    'Kind-scoped sanitiser recognition - an HTML escaper does not clear a SQL sink',
    'Retraction: a signature guess is withdrawn when the tracer proves a sanitiser runs',
    'Verified-clean reporting: lines the tracer reached and proved safe are listed, so "no finding here" can be told apart from "never looked here"',
    'One engine, two shells: the terminal and the browser run the same compiled analysis module, not two implementations of it',
    'Receiver state: a tainted argument dirties the object it was handed to, so `sb.append(dirty)` and `list.add(dirty)` are followed - and a sink that takes NO arguments because the payload was loaded earlier (`pb.command(list); pb.start()`) is recognised',
    'Return-value sinks in Python: a Flask/Django view that returns an HTML string is treated as writing the response body, so the commonest reflected XSS in Python is seen at all - and the escaped version is credited as clean rather than merely unflagged',
    'Escape proof before complaint (JavaScript/TypeScript): before reporting a value written into HTML, local variables, local render helpers and their arguments are resolved to see whether every spliced-in value is a literal, a number, or the output of a known escaper. A finding that survives names the exact sub-expression it could not prove safe.',
    'SQL is recognised by statement SHAPE (SELECT paired with FROM, INSERT with INTO) inside a bounded window, not by keywords scattered anywhere in the text - so a paragraph of prose containing "call" and "where" is not a query',
    'Per-rule and per-language coverage reporting, including gaps',
  ],
  notImplemented: [
    'Third-party code: only files inside the scan are resolved. A call into node_modules, a JAR or a vendored package ends the trace.',
    'Ambiguous imports: when several files in scope define the same function name, we decline to guess and the trace stops there. The count is reported.',
    'Re-exports, dynamic imports, computed requires, and build-tool path aliases (tsconfig paths, webpack) are not resolved.',
    'Whether a function is actually EXPORTED is not checked - a module-private helper with a matching name could be entered.',
    'Call chains deeper than four functions are not followed.',
    'Object and field state: `obj.field = dirty` and `sb.append(dirty)` are invisible - we track variables, not the interiors of objects.',
    'Sources are recognised by expression shape (req.query, request.form), not by proving the object really is a request.',
    'Branch conditions are not evaluated. We do not read the condition, so we make the weaker claim that a CONDITIONAL write cannot prove a value clean: taint set anywhere survives a clean assignment inside an if/else, switch or loop, while an unconditional one still clears it. That errs toward reporting a value that might be clean rather than staying silent about one that might be dirty - and it is why `if (cond) bar = dirty; else bar = "safe";` is still reported.',
    'Loops are not iterated to a fixpoint, so a value that becomes tainted late in a loop body is missed.',
    'Containers are tainted whole, not per element: after `list.add(clean)` and `list.add(dirty)`, or after `Object[] a = {"safe", dirty}`, every read from that container is treated as dirty. This is the price of following values into objects at all, and it errs toward reporting rather than missing.',
    'Framework awareness: Express routing, Django views and Spring @RequestParam are not modelled, so a value that only becomes attacker-controlled through a framework binding is not seen as a source.',
    'The escape proof is JavaScript and TypeScript only, and same-file only. An escaper imported from another module, applied by a framework, or reached through more than six nested calls reads as unproven - so Python, Java, PHP and Go HTML sinks still report on shape alone.',
    'Vendor documentation example credentials (a key matching a published format but ending in EXAMPLE, or filled with 0000/1234567890) are treated as placeholders and not reported. A real credential that happened to look like one would be missed.',
  ],
  meaningOfConfidence: {
    'signature-based':
      'Pattern matched in the syntax tree. Data flow NOT traced. May be a false positive.',
    'flow-verified':
      'Attacker-controlled data was traced from a source into a sink - across functions and, where imports resolve, across files - with no sanitiser on the path. Every hop is listed in flowPath, with its own file and line.',
  },
} as const;
