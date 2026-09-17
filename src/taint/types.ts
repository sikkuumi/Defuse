/**
 * TAINT ANALYSIS - THE VOCABULARY
 * ===============================
 *
 * "Taint" is the oldest metaphor in program analysis and still the clearest:
 * data that came from outside your program is DIRTY. Dirt spreads when you copy
 * or combine the value. Washing it is possible, but only with the right soap for
 * the right job. A vulnerability is dirt arriving somewhere dangerous unwashed.
 *
 * Four words, and the whole engine is built out of them:
 *
 *   SOURCE      where dirt enters. `req.query.id`, `request.form['x']`,
 *               `sys.argv`. Someone outside your program chose this value.
 *
 *   PROPAGATION dirt spreading. `const b = a;` `"x" + a` `a.trim()` `f"{a}"`.
 *               A copy of a dirty value is dirty. So is a string containing it.
 *
 *   SANITISER   washing. `html.escape(a)` for HTML, `shlex.quote(a)` for shells,
 *               `parseInt(a)` for anything that should be a number.
 *
 *   SINK        where dirt does damage. `db.query(...)`, `exec(...)`,
 *               `el.innerHTML = ...`. These read strings as instructions.
 *
 * THE PART MOST TOOLS GET WRONG - soap is job-specific.
 *
 * `escapeHtml(x)` makes a value safe to put in a web page. It does absolutely
 * nothing to make it safe inside a SQL query - `&lt;` is not valid SQL escaping,
 * and the dangerous characters for SQL (quotes) are not the dangerous characters
 * for HTML (angle brackets). A scanner that keeps one boolean "is it clean?"
 * will silently accept HTML-escaping in front of a database call.
 *
 * So taint here carries a SET of kinds it has been cleaned for, and a sink only
 * accepts soap matching its own kind. That's the `sanitizedFor` field below, and
 * it is a small design decision with a large correctness payoff.
 */

import type { FlowStep } from '../core/finding.js';

/** The categories of damage a dirty value can do. */
export type SinkKind =
  | 'sql'
  | 'command'
  | 'xss'
  | 'deserialization'
  | 'code'
  | 'ssrf'
  /**
   * A tainted FORMAT STRING (CWE-134). C-family only, and the cleanest sink in
   * this union: `printf(name)` reads the attacker's string as a format, so
   * `%n` turns a logging call into an arbitrary memory write. It is separate
   * from `command` because the fix is different (make the format constant) and
   * separate from `xss` because nothing is being rendered.
   */
  | 'format'
  /**
   * A tainted value reaching a copy with NO LENGTH BOUND (CWE-120).
   *
   * Read the name carefully: it is not `buffer-overflow`. Whether a copy
   * actually overflows depends on the destination's size, which this engine
   * does not model - it tracks values, not sizes. What is provable from data
   * flow alone is that attacker-controlled data reached a function that writes
   * until it meets a NUL byte, with the attacker choosing where that is. The
   * finding says exactly that and no more.
   */
  | 'overflow';

export const SINK_KIND_RULE: Record<SinkKind, string> = {
  sql: 'sql-injection',
  command: 'command-injection',
  xss: 'xss',
  deserialization: 'unsafe-deserialization',
  code: 'code-injection',
  ssrf: 'ssrf',
  format: 'format-string',
  overflow: 'unbounded-copy',
};

/**
 * What we know about one value.
 *
 * There is no `tainted: false` state - an untainted value is simply `null`.
 * Modelling "clean" as the absence of a record keeps the engine honest: we only
 * ever claim dirt we can trace, never cleanliness we assumed.
 */
export interface Taint {
  /** Every hop so far, starting with the source. Becomes the finding's flowPath. */
  readonly steps: readonly FlowStep[];
  /** Kinds of sink this value has been properly washed for. */
  readonly sanitizedFor: ReadonlySet<SinkKind>;
  /** Short label for the origin, e.g. "req.query.id". Used in messages. */
  readonly origin: string;
}

/** A pattern that means "an attacker chose this value". */
export interface SourceSpec {
  /** Matched against the source text of an expression. */
  readonly pattern: RegExp;
  /** Plain-language description for the flow path, e.g. "HTTP query string". */
  readonly description: string;
}

/** A call that does something dangerous with a string. */
export interface CallSinkSpec {
  readonly kind: SinkKind;
  /** Method or function names, last segment only. */
  readonly methods: readonly string[];
  /**
   * WHICH arguments are dangerous. This matters enormously: in
   * `db.query("SELECT ... ?", [userId])` argument 0 is the instruction and
   * argument 1 is data the driver keeps separate. Treating every argument as a
   * sink would report the CORRECT, parameterised form as a vulnerability - the
   * single worst false positive a SQL rule can produce, because it punishes the
   * fix.
   */
  readonly argIndexes: readonly number[] | 'all';
  /**
   * Only a sink when the call sits on one of these receivers.
   *
   * `loads` and `load` are dangerous on `pickle` and meaningless on everything
   * else, and every Python codebase has a settings loader. Matching the method
   * name alone reported `json.loads(request.data)` - the SAFE parser - as a
   * deserialization sink, which is the same class of mistake as flagging a
   * parameterised query.
   */
  readonly requiredReceivers?: readonly string[];
  /**
   * Only a sink when the call has NO receiver at all.
   *
   * The mirror of requiredReceivers, for built-in functions. `compile(src)` is
   * Python's builtin; `re.compile(pattern)` is a regular expression and shares
   * only the name. See BARE_BUILTINS in rules/code-injection.ts.
   */
  readonly bareOnly?: boolean;
  /** Receivers that keep a bareOnly sink alive, because they ARE the evaluator. */
  readonly allowedReceivers?: readonly string[];
  /**
   * Only a sink when the receiver EXPRESSION matches this.
   *
   * The looser sibling of requiredReceivers, for receivers that are themselves
   * calls: `response.getWriter().write(x)` has no single name to compare.
   *
   * This is what replaced `contentCheck: 'html'` on the Java response sinks.
   * The content check was there to stop `sb.append(x)` reading as XSS, but it
   * demanded that the ARGUMENT look like HTML - and the argument is usually an
   * opaque variable, so it rejected 204 real cases to avoid one false one.
   * Asking about the RECEIVER instead separates them exactly: a servlet writer
   * writes to the page, a StringBuilder does not, whatever is passed to either.
   */
  readonly receiverPattern?: RegExp;
  /**
   * For sinks whose DESTINATION is argument zero rather than the receiver.
   *
   * `fmt.Fprintf(w, format, args...)` writes to `w`. The receiver is `fmt`,
   * which says nothing at all, so `receiverPattern` cannot reach this shape -
   * and it is the one shape in the sink table that stayed wrong through a whole
   * scoping sweep, still reporting `fmt.Fprintf(out, ...)` in a test mock as
   * cross-site scripting.
   *
   * When set, argument zero's text (or its declared type) must match, AND
   * argument zero is excluded from the tainted-value check - it is where the
   * output goes, not what is written.
   */
  readonly writerArgPattern?: RegExp;
  /** Only a sink when the call text also shows a shell being used. */
  readonly requiresShellOption?: RegExp;
  /**
   * NOT a sink when the call text shows the dangerous behaviour turned off.
   *
   * The mirror image of requiresShellOption, and it exists because the safe
   * form of a deserialiser is the dangerous call plus an argument:
   *
   *     unserialize($data, ['allowed_classes' => false])   // PHP
   *     yaml.load(text, Loader=yaml.SafeLoader)            // Python
   *
   * Both are still a call to the risky function. Reporting them would punish
   * the fix, which is the worst thing an injection rule can do - it teaches
   * people that hardening does not help.
   *
   * This reads the VISIBLE TEXT of the call, so an options object assembled in
   * another variable is missed and the finding still fires. That errs toward
   * reporting, which is the safe direction, and it is stated in the rule's
   * limitations rather than left for someone to discover.
   */
  readonly unlessOption?: RegExp;
  /**
   * Only a sink when the argument's literal text actually looks like this kind
   * of content. Needed because method names collide across libraries: `exec` is
   * both a database call and a shell call, and `append` is both a jQuery HTML
   * insertion and an ordinary array method. Without this, `exec("ping " + host)`
   * gets reported as SQL injection - which it is not.
   */
  readonly contentCheck?: 'sql' | 'html';
  readonly description: string;
}

/** An assignment target that does something dangerous with a string. */
export interface AssignSinkSpec {
  readonly kind: SinkKind;
  /** Property names, last segment only: innerHTML, __html, srcdoc. */
  readonly properties: readonly string[];
  /**
   * Require the assigned text to LOOK like the thing this sink parses.
   *
   * `innerHTML` needs no such check - the property name is the proof, because
   * the browser will parse whatever lands there. A PHP page buffer is the
   * opposite: `$html`, `$output` and `$content` are conventions, and
   * `$sql .= $where` accumulates a query rather than a page. Requiring visible
   * markup is what separates the two without inventing a type system.
   */
  readonly contentCheck?: 'sql' | 'html';
  readonly description: string;
}

/** A function that makes a value safe - for SOME kinds of sink, not all. */
export interface SanitizerSpec {
  readonly names: readonly string[];
  /** Which sinks this soap actually works for. */
  readonly kinds: readonly SinkKind[];
  readonly description: string;
}

/** A function whose output is still dirty if its input was. */
export interface PropagatorSpec {
  readonly names: readonly string[];
}

export interface TaintDictionary {
  readonly sources: readonly SourceSpec[];
  /**
   * Sources that are PARAMETER DECLARATIONS rather than expressions.
   *
   * Every other source in this file is recognised by the text of an expression:
   * `req.query.id` looks like a query parameter wherever it appears. A Spring
   * handler has no such expression - the framework binds the request value to a
   * parameter NAME before the method body starts, and the only evidence in the
   * source is an annotation on the declaration:
   *
   *     public String lookup(@RequestParam String account) { ... }
   *
   * `account` is attacker-controlled from its first use and nothing in the body
   * says so. Matching the declaration is the only way to see it.
   */
  readonly parameterSources?: readonly SourceSpec[];
  readonly callSinks: readonly CallSinkSpec[];
  readonly assignSinks: readonly AssignSinkSpec[];
  readonly sanitizers: readonly SanitizerSpec[];
  readonly propagators: PropagatorSpec;
  /**
   * Methods where a tainted ARGUMENT dirties the RECEIVER.
   *
   *     sb.append(param);        // the taint lands on `sb`, not on a return
   *     argList.add(param);      // `add` returns a boolean
   *
   * Propagators are value-in / value-out: they carry taint through a return
   * value that someone assigns. These do not. `append` and `format` were both
   * already in the Java propagator list and still missed every case, because
   * the return is thrown away and the taint has to attach to the object.
   *
   * Measured on OWASP BenchmarkJava, this one shape is about 60% of all false
   * negatives - 49 StringBuilder cases plus 151 that push a request value into
   * a List or Map before the sink. It is the single largest recall gap, and it
   * is language-agnostic.
   */
  readonly mutators?: readonly string[];
  /**
   * Functions where a tainted argument dirties argument ZERO.
   *
   * `mutators` above binds taint to the receiver, which is where the filled
   * object sits in every language that has receivers. C has none: the
   * destination is the first argument.
   *
   *     sprintf(cmd, "ping %s", argv[1]);   ->  `cmd` is now tainted
   *     strcpy(buf, argv[1]);               ->  `buf` is now tainted
   *
   * Without this, C coverage is close to zero - the build-then-run pattern is
   * how every command injection in the language is actually written, and the
   * receiver rule cannot see it. See checkOutParamMutation in tracer.ts.
   */
  readonly outParamMutators?: readonly string[];
  /**
   * Functions that ARE a source and deliver their bytes through a parameter.
   *
   *     fgets(line, sizeof(line), stdin);   ->  `line` is now attacker input
   *     read(fd, buf, n);                   ->  `buf` is
   *     scanf("%s", name);                  ->  `name` is
   *
   * The ordinary source list matches the TEXT of an expression, which works
   * when the value is the call's return - `getenv("X")` reads as a source
   * wherever it appears. These functions return a count or a status; the data
   * goes into an argument, and the call is usually a statement whose result
   * nobody keeps. So there is no expression to match and nothing to bind,
   * unless the destination index is known - and it differs per function, which
   * is why this carries one rather than assuming zero.
   */
  readonly outParamSources?: readonly {
    readonly names: readonly string[];
    /** Which argument receives the bytes. */
    readonly destination: number;
    readonly description: string;
  }[];
  /**
   * KEYED mutators - a write into a named compartment of an object that is
   * primarily something else.
   *
   *     req.setAttribute("loginForm", dirty);
   *
   * These are mutators too, and they appear in `mutators` as well; this list
   * says something extra about a subset of them. The plain kind ARE the value
   * they were handed: after `sb.append(dirty)`, `sb` is the dirty string and
   * every read of `sb` is a read of it. A servlet request is not its attribute
   * map. It also has a method, a URI, a session and a context path, and none
   * of those changed because something was filed in a side compartment.
   *
   * Scanning Jenkins produced a flow-verified finding on `req.getContextPath()`
   * for exactly this reason: an unmodelled call carries its receiver's taint,
   * the receiver had been dirtied by setAttribute, so a container-configured
   * constant was reported as attacker-controlled. Worse, the tracer then
   * attributed the flow to the one argument the code did NOT escape, so the
   * escaper retraction added a version earlier never fired.
   *
   * The rule this enables is narrow: taint written through a keyed mutator
   * comes back out through `keyedReaders`, and not through anything else.
   * Reads out of the store stay deliberately KEY-INSENSITIVE - `setAttribute`
   * under one name and `getAttribute` under another is still treated as
   * tainted, because matching key literals would be a second guess layered on
   * a first. The imprecision is aimed, not removed.
   */
  readonly keyedMutators?: readonly string[];
  /**
   * The methods that legitimately read a keyed store back out. Only consulted
   * for taint that arrived via `keyedMutators`; every other method on such an
   * object is treated as untouched by the write.
   */
  readonly keyedReaders?: readonly string[];
  /**
   * Sinks fired by a tainted RECEIVER rather than a tainted argument.
   *
   *     pb.command(argList);   // argList is dirty, so pb is now dirty
   *     pb.start();            // <- the dangerous act, and it takes NO arguments
   *
   * Every other sink check in this engine reads the argument list. This shape
   * has an empty one: the payload was loaded into the object on an earlier
   * line, and the call that executes it carries nothing. It is the standard
   * ProcessBuilder idiom and it is all over OWASP BenchmarkJava.
   */
  readonly receiverSinks?: readonly {
    readonly methods: readonly string[];
    readonly kind: SinkKind;
    readonly description: string;
  }[];
  /**
   * `return "<h1>" + name + "</h1>"` is a sink in this language.
   *
   * In Flask and Django a view that returns a string HAS returned the response
   * body - there is no `res.send()` to match on, so the dangerous call this
   * engine looks for simply is not written anywhere. A tester's fixture caught
   * this: an obvious reflected XSS produced nothing, and - worse - the ESCAPED
   * version of the same code "passed" for the wrong reason, because with no
   * sink recognised there was nothing for `html.escape` to be credited against.
   *
   * Set only where returning a string plausibly means returning a page. Express
   * is deliberately excluded: it answers with `res.send`, which is already a
   * modelled call sink, so enabling this there would invent a second sink for
   * the same thing.
   */
  readonly htmlReturnIsSink?: boolean;
}
