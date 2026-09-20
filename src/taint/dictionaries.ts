/**
 * THE TAINT DICTIONARIES
 *
 * Pure data. The tracer in tracer.ts contains no knowledge of Express, Flask,
 * psycopg2 or DOMPurify - it only knows how to follow a value. Everything
 * language- and framework-specific lives here.
 *
 * That split is the reason Phase 3b (Java and Go) is a data task rather than an
 * engine task: write two more entries in this file and the same tracer works.
 *
 * HONESTY NOTE ON SOURCES. We recognise a source by the SHAPE of the
 * expression - `req.query.id` looks like an HTTP query parameter. We do not
 * prove that `req` is really an Express request object; proving that needs
 * type inference we do not have. In practice the convention is near-universal,
 * but it means a variable someone happened to name `req` with a `.body`
 * property would be treated as attacker-controlled. That approximation is
 * listed in ENGINE_CAPABILITIES.notImplemented and printed in every report.
 */

import type { LanguageId } from '../parse/languages.js';
import type { CallSinkSpec, SourceSpec, TaintDictionary } from './types.js';

/* ========================================================================== *
 * JavaScript / TypeScript
 * ========================================================================== */

const JS_DICTIONARY: TaintDictionary = {
  mutators: ['push', 'unshift', 'splice', 'add', 'set', 'append', 'write', 'writeln'],
  // Separable items only. `append` is left out: in JS it is DOM appendChild,
  // which takes a node rather than filing one string among many.
  elementMutators: ['push', 'unshift', 'splice', 'add', 'set'],

  sources: [
    {
      pattern: /\b(req|request|ctx)\.(query|body|params|param)\b/,
      description: 'HTTP request parameters (query string, body or route params)',
    },
    {
      pattern: /\b(req|request|ctx)\.(headers?|cookies|get)\b/,
      description: 'HTTP request headers or cookies',
    },
    {
      pattern: /\b(req|request)\.(url|originalUrl|path|hostname|ip)\b/,
      description: 'HTTP request URL or connection metadata',
    },
    {
      pattern: /\bevent\.(body|queryStringParameters|pathParameters|headers)\b/,
      description: 'serverless function event payload (AWS Lambda style)',
    },
    {
      pattern: /\b(location|document\.location|window\.location)\.(search|hash|href|pathname)\b/,
      description: 'the browser address bar - fully attacker-controllable via a link',
    },
    { pattern: /\bdocument\.referrer\b/, description: 'the HTTP Referer header' },
    { pattern: /\bwindow\.name\b/, description: 'window.name, settable by any page that opened this one' },
    { pattern: /\bdocument\.cookie\b/, description: 'document.cookie' },
    {
      pattern: /\bsearchParams\.get\s*\(/,
      description: 'a URL query parameter read via URLSearchParams',
    },
    { pattern: /\bprocess\.argv\b/, description: 'command-line arguments' },
    {
      pattern: /\b(localStorage|sessionStorage)\.getItem\s*\(/,
      description: 'browser storage, which any script on the page can write',
    },
  ],

  callSinks: [
    {
      kind: 'sql',
      // Deliberately NARROWER than the signature rule's list. `exec`, `run`,
      // `all`, `get` and `each` are database methods in some libraries and
      // completely unrelated methods in others. The signature rule can afford
      // them because it also demands SQL-looking text; a taint sink that fires
      // on an opaque variable cannot, so ambiguous names are left out.
      methods: [
        'query', 'execute', 'raw', 'prepare', 'queryRaw',
        '$queryRawUnsafe', '$executeRawUnsafe', 'unsafe',
      ],
      // `query` and `execute` belong to a database here and to a job runner,
      // an HTTP client or a GraphQL layer three files away. The content check
      // narrows the VALUE; this narrows the OBJECT, which is what every one of
      // the six scoping bugs got wrong.
      receiverPattern:
        /db|conn|client|pool|knex|sequelize|prisma|sql|database|mysql|maria|postgres|sqlite|mssql|oracle|\btrx\b|transaction|session|repo|cursor|orm|store|adapter/i,
      // ONLY argument 0. See the note on argIndexes in types.ts - this is what
      // stops us reporting the correct, parameterised form as a vulnerability.
      argIndexes: [0],
      contentCheck: 'sql',
      description: 'a database query',
    },
    {
      kind: 'command',
      methods: ['exec', 'execSync'],
      /*
       * `exec` IS ALSO RegExp.prototype.exec, and that one is everywhere.
       *
       * Unscoped, this entry produced the worst finding this project has made:
       * CRITICAL, FLOW-VERIFIED, in gitea's browser code, reading "attacker-
       * controlled data from `window.location.pathname` reaches a shell
       * command" over `/([^/]+)\/([^/]+)/.exec(pathname)`. No shell, no server,
       * no command - a regular expression matching a URL path in a browser tab.
       *
       * BARE, NOT BANNED. The normal way to reach the dangerous one is the
       * destructured import - `const {exec} = require('child_process')` - so a
       * bare call still fires, and only a call with an unrecognised receiver in
       * front of it is dropped. `require('child_process').exec(cmd)` in one
       * expression is missed by this and is a documented gap rather than a
       * silent one.
       */
      bareOnly: true,
      allowedReceivers: ['child_process', 'childProcess', 'cp', 'shell', 'proc'],
      argIndexes: [0],
      description: 'a shell command',
    },
    {
      kind: 'command',
      methods: ['spawn', 'spawnSync', 'execFile', 'execFileSync'],
      argIndexes: [0],
      requiresShellOption: /shell\s*:\s*true/,
      description: 'a shell command (shell: true is set on this call)',
    },
    {
      kind: 'ssrf',
      /*
       * RECEIVER-SCOPED, and the first version was not.
       *
       * `get`, `post` and `request` are among the most common method names in
       * any codebase. Scanning VS Code's server package produced a beautiful
       * eighteen-hop flow-verified SSRF - `req.url` traced through five
       * functions into `active(consumer)` - and the sink at the end of it was
       *
       *     this._consumers.get(consumer)      // a Map
       *
       * Eighteen correct hops to a wrong conclusion. The trace was right; the
       * sink list was wrong. Every other rule here learned to ask WHICH object
       * (pickle vs settings, mathjs vs re) and this one had not.
       */
      methods: ['get', 'request', 'post', 'put', 'patch', 'head', 'del'],
      requiredReceivers: [
        'http', 'https', 'axios', 'got', 'request', 'superagent',
        'needle', 'undici', 'fetch', 'agent', 'httpClient',
      ],
      argIndexes: [0],
      description: 'an outbound HTTP request, so the server fetches whatever host this names',
    },
    {
      kind: 'ssrf',
      // The global `fetch` and `got` take a URL with nothing in front of them.
      methods: ['fetch', 'got'],
      bareOnly: true,
      argIndexes: [0],
      description: 'an outbound HTTP request, so the server fetches whatever host this names',
    },
    {
      kind: 'code',
      methods: ['eval', 'Function', 'execScript'],
      // Bare, OR on an object that really is an evaluator. `mathjs.eval` has
      // its own CVEs; `compiler.compile` is somebody's SQL builder.
      bareOnly: true,
      allowedReceivers: ['mathjs', 'math', 'vm', 'window', 'global', 'globalThis', 'safeEval', 'eval5'],
      argIndexes: 'all',
      description: 'the JavaScript interpreter, which runs the string as program code',
    },
    {
      kind: 'code',
      // vm.runInNewContext IS a method - it is supposed to have a receiver.
      methods: ['runInNewContext', 'runInThisContext'],
      argIndexes: 'all',
      description: 'the JavaScript interpreter, which runs the string as program code',
    },
    {
      kind: 'code',
      // Only as a TAINT sink, never on shape - see the note in code-injection.ts.
      // A request cannot deliver a function, so a tainted value here is a string,
      // and a string argument to setTimeout is executed.
      methods: ['setTimeout', 'setInterval'],
      argIndexes: [0],
      description: 'setTimeout/setInterval, which execute a STRING argument as code',
    },
    {
      kind: 'xss',
      methods: ['write', 'writeln'],
      argIndexes: 'all',
      /*
       * `write` HAS TO BE SCOPED, because it is the single most common method
       * name in JavaScript that is attached to something other than a page.
       *
       * Unscoped, this entry produced nine of the fourteen flow-verified
       * findings in a scan of VS Code, every one of them a
       * `process.stdout.write(...)` in a command-line script - and every one of
       * them printed "reaches document.write, which parses its argument as
       * HTML" over a file with no browser anywhere in it. Streams, sockets,
       * file handles, hashes and every hand-rolled logger all have `.write()`.
       *
       * Two receivers earn the finding: a DOCUMENT (`document.write` parses
       * HTML by definition) and an HTTP RESPONSE (`res.write('<p>' + dirty)`
       * is the ordinary Express XSS, and is why this cannot simply require the
       * word "document"). Anything else is a byte sink, and a byte sink is not
       * a page.
       *
       * KNOWN CONSEQUENCE, stated rather than hidden: a response object stored
       * under a name we do not recognise - `httpOut.write(dirty)` - is now
       * missed. That is a false negative bought deliberately, because the
       * alternative was calling every terminal in every CLI a browser.
       */
      receiverPattern: /(^|\.)(document|doc|contentDocument)$|\b(res|resp|response|reply)\b/i,
      description: 'document.write or an HTTP response body, which is parsed as HTML',
    },
    {
      kind: 'xss',
      methods: ['insertAdjacentHTML'],
      argIndexes: [1], // argument 0 is the position ("beforeend"), not content
      description: 'insertAdjacentHTML, which parses its argument as HTML',
    },
    {
      kind: 'xss',
      methods: ['html', 'append', 'prepend'],
      // jQuery-style insertion, and ONLY that. `formData.append(k, v)`,
      // `headers.append(...)` and `searchParams.append(...)` are the same word
      // on objects that never touch a page.
      receiverPattern:
        /\$|jquery|element|\bel\b|\bnode\b|\bdom\b|container|wrapper|\bdiv\b|\bbody\b|target|parent|selector|\bhtml\b/i,
      argIndexes: [0],
      contentCheck: 'html',
      description: 'a jQuery-style HTML insertion',
    },
  ],

  assignSinks: [
    {
      kind: 'xss',
      properties: ['innerHTML', 'outerHTML', 'srcdoc', '__html'],
      description: 'a property the browser parses as HTML',
    },
  ],

  sanitizers: [
    {
      names: ['escapeHtml', 'escapeHTML', 'sanitize', 'sanitizeHtml', 'purify', 'encodeURIComponent'],
      kinds: ['xss'],
      description: 'HTML escaping / sanitising',
    },
    {
      names: ['escapeId', 'escapeIdentifier', 'escapeLiteral'],
      kinds: ['sql'],
      description: 'SQL identifier escaping',
    },
    {
      // parseInt/Number turn text into a number. A number cannot carry a quote,
      // a semicolon or a tag, so it is safe for every text-injection sink at
      // once. This is the strongest and most under-used sanitiser there is.
      names: ['parseInt', 'parseFloat', 'Number', 'BigInt'],
      kinds: ['sql', 'command', 'xss'],
      description: 'conversion to a number',
    },
    {
      names: ['quote', 'shellQuote', 'shellescape'],
      kinds: ['command'],
      description: 'shell quoting',
    },
  ],

  propagators: {
    names: [
      'String', 'toString', 'valueOf', 'trim', 'trimStart', 'trimEnd',
      'toLowerCase', 'toUpperCase', 'slice', 'substring', 'substr', 'concat',
      'join', 'split', 'padStart', 'padEnd', 'repeat', 'normalize', 'at',
      'charAt', 'replace', 'replaceAll', 'decodeURIComponent', 'decodeURI',
      'JSON.stringify', 'stringify',
    ],
  },
};

/* ========================================================================== *
 * Python
 * ========================================================================== */

const PYTHON_DICTIONARY: TaintDictionary = {
  mutators: ['append', 'add', 'insert', 'extend', 'update', 'setdefault', 'write', 'writelines'],
  // Python's `append` is a LIST element - the OPPOSITE classification to Java's
  // StringBuilder append, and the reason this list cannot be shared.
  elementMutators: ['append', 'add', 'insert', 'extend', 'update', 'setdefault'],

  // Flask and Django views return the response body directly - there is no
  // res.send() to match on. See htmlReturnIsSink in types.ts for why this is
  // needed and why JavaScript deliberately does not set it.
  htmlReturnIsSink: true,
  sources: [
    {
      pattern: /\brequest\.(args|form|values|json|data|files|query_params|GET|POST|body)\b/,
      description: 'HTTP request parameters (Flask/Django/DRF)',
    },
    {
      pattern: /\brequest\.(headers|cookies|META|COOKIES)\b/,
      description: 'HTTP request headers or cookies',
    },
    { pattern: /\bsys\.argv\b/, description: 'command-line arguments' },
    { pattern: /(^|[^.\w])input\s*\(/, description: 'input() read from the terminal' },
    {
      pattern: /\bself\.(get_argument|request\.(arguments|body|headers))\b/,
      description: 'Tornado request data',
    },
  ],

  callSinks: [
    {
      kind: 'sql',
      methods: ['execute', 'executemany', 'executescript', 'raw'],
      // `execute` is a DB-API cursor here and a task, a plan or a pipeline
      // elsewhere; `raw` is Django's queryset escape hatch and half of every
      // other library's byte accessor.
      receiverPattern:
        /cursor|\bcur\b|conn|\bdb\b|session|engine|objects|sqlalchemy|connection|pool|\bcnx\b|database/i,
      argIndexes: [0], // cursor.execute(sql, params) - params are safe by design
      contentCheck: 'sql',
      description: 'a database query',
    },
    {
      kind: 'sql',
      // SQLAlchemy's `text()` is imported and called bare - it has no receiver
      // to scope against, and `obj.text()` is somebody's accessor.
      methods: ['text'],
      bareOnly: true,
      allowedReceivers: ['sqlalchemy', 'sa', 'db'],
      argIndexes: [0],
      contentCheck: 'sql',
      description: 'a SQLAlchemy text() query',
    },
    {
      kind: 'command',
      methods: ['system', 'popen', 'getoutput', 'getstatusoutput'],
      argIndexes: [0],
      description: 'a shell command',
    },
    {
      kind: 'command',
      methods: ['run', 'call', 'check_call', 'check_output', 'Popen'],
      // `run` and `call` are two of the most reusable verbs in Python. Bare is
      // kept because `from subprocess import run` is the ordinary import.
      bareOnly: true,
      allowedReceivers: ['subprocess', 'sp', 'sub', 'commands'],
      argIndexes: [0],
      requiresShellOption: /shell\s*=\s*True/,
      description: 'a shell command (shell=True is set on this call)',
    },
    {
      kind: 'ssrf',
      methods: ['get', 'post', 'put', 'delete', 'head', 'patch', 'request', 'urlopen', 'Request'],
      requiredReceivers: ['requests', 'httpx', 'urllib', 'request', 'session', 'client'],
      argIndexes: [0],
      description: 'an outbound HTTP request, so the server fetches whatever host this names',
    },
    {
      kind: 'code',
      methods: ['eval', 'exec', 'compile'],
      // Builtins only. `re.compile(dirty)` is a regex, not an interpreter.
      bareOnly: true,
      allowedReceivers: ['builtins', '__builtins__'],
      argIndexes: [0],
      description: 'the Python interpreter, which runs the string as program code',
    },
    {
      kind: 'deserialization',
      methods: ['loads', 'load', 'Unpickler'],
      // Without this, `json.loads(request.data)` - the SAFE parser everyone is
      // told to use instead - reports as a deserialization sink.
      requiredReceivers: ['pickle', 'cPickle', 'dill', 'marshal', 'yaml', 'shelve', 'jsonpickle'],
      argIndexes: [0],
      unlessOption: /\b(SafeLoader|CSafeLoader|BaseLoader|safe_load)\b/,
      description: 'pickle/yaml deserialisation, which runs constructor code from the bytes',
    },
    {
      kind: 'xss',
      methods: ['mark_safe', 'Markup', 'render_template_string', 'format_html'],
      argIndexes: [0],
      description: 'a template escape hatch that marks the value as trusted HTML',
    },
    {
      kind: 'xss',
      methods: ['HttpResponse'],
      argIndexes: [0],
      description: 'an HTTP response body written without escaping',
    },
  ],

  assignSinks: [],

  sanitizers: [
    {
      names: ['escape', 'clean', 'conditional_escape', 'escapejs'],
      kinds: ['xss'],
      description: 'HTML escaping (html.escape / markupsafe / bleach)',
    },
    {
      names: ['quote'], // shlex.quote / pipes.quote
      kinds: ['command'],
      description: 'shell quoting (shlex.quote)',
    },
    {
      names: ['int', 'float'],
      kinds: ['sql', 'command', 'xss'],
      description: 'conversion to a number',
    },
    {
      names: ['adapt', 'bindparam', 'literal_column'],
      kinds: ['sql'],
      description: 'database adapter escaping',
    },
  ],

  propagators: {
    names: [
      'str', 'strip', 'lstrip', 'rstrip', 'lower', 'upper', 'title',
      'replace', 'join', 'split', 'rsplit', 'format', 'encode', 'decode',
      'ljust', 'rjust', 'center', 'removeprefix', 'removesuffix',
    ],
  },
};


/* ========================================================================== *
 * Java  (Servlet API + JDBC)
 * ========================================================================== */

const JAVA_DICTIONARY: TaintDictionary = {
  /*
   * SPRING REQUEST BINDINGS - the sources that were missing while the benchmark
   * said recall was 76.4%.
   *
   * Scanning OWASP WebGoat, an application made ENTIRELY of labelled
   * vulnerabilities, produced 126 findings and zero flow-verified. Elasticsearch
   * (3,999 Java files): also zero. The reason turned out to be countable:
   * WebGoat contains 161 `@RequestParam` and 4 `getParameter()`, while
   * BenchmarkJava - the thing producing the 76.4% - is raw servlet
   * getParameter/getHeader from end to end.
   *
   * So the recall figure was honest about a dialect almost nobody writes any
   * more, and every modern Spring application received no data-flow analysis at
   * all. A benchmark is only evidence about the code the benchmark contains.
   *
   * @ModelAttribute is deliberately absent: it binds a whole command object,
   * and its FIELDS are what carry the request data, which needs object-state
   * tracking this tracer does not have. Listing it would imply coverage of a
   * shape that would go nowhere.
   */
  parameterSources: [
    {
      pattern: /@RequestParam\b/,
      description: 'a Spring @RequestParam binding - the query string or form field',
    },
    { pattern: /@PathVariable\b/, description: 'a Spring @PathVariable binding - part of the URL path' },
    { pattern: /@RequestHeader\b/, description: 'a Spring @RequestHeader binding - an HTTP request header' },
    { pattern: /@CookieValue\b/, description: 'a Spring @CookieValue binding - a cookie the client sent' },
    { pattern: /@RequestBody\b/, description: 'a Spring @RequestBody binding - the whole request body' },
    { pattern: /@RequestPart\b/, description: 'a Spring @RequestPart binding - one part of a multipart upload' },
    /*
     * JAX-RS - the Jakarta standard, and therefore Jersey, RESTEasy, Dropwizard
     * and Quarkus all at once. Same mechanism as Spring: the framework binds the
     * request value to the parameter before the body runs, so the annotation on
     * the declaration is the only evidence in the file.
     *
     * Six lines, four frameworks. Worth doing immediately, because the moment
     * the capability text listed JAX-RS as recognised, not having it would have
     * made the report a false statement about its own engine.
     */
    { pattern: /@QueryParam\b/, description: 'a JAX-RS @QueryParam binding - the query string' },
    { pattern: /@PathParam\b/, description: 'a JAX-RS @PathParam binding - part of the URL path' },
    { pattern: /@HeaderParam\b/, description: 'a JAX-RS @HeaderParam binding - an HTTP request header' },
    { pattern: /@FormParam\b/, description: 'a JAX-RS @FormParam binding - a submitted form field' },
    { pattern: /@CookieParam\b/, description: 'a JAX-RS @CookieParam binding - a cookie the client sent' },
    { pattern: /@MatrixParam\b/, description: 'a JAX-RS @MatrixParam binding - a URL matrix parameter' },
  ],

  // StringBuilder/StringBuffer, the Collections API, and servlet response
  // writers - the three ways Java code carries a value without assigning it.
  mutators: ['append', 'insert', 'add', 'addAll', 'put', 'putAll', 'push', 'offer', 'write', 'print', 'println', 'setAttribute', 'addHeader', 'setHeader', 'command', 'directory', 'environment'],
  // `append` and `insert` are StringBuilder concatenation - the builder IS its
  // contents, so they keep their proof however many times they run. `command`
  // sets the whole list at once rather than filing one item among many.
  elementMutators: ['add', 'addAll', 'put', 'putAll', 'push', 'offer'],
  // A servlet request is not its attribute map, and a response is not its
  // header map. See safe/keyed-container.java - Jenkins was reported for
  // `req.getContextPath()` because a setAttribute() elsewhere in the method had
  // dirtied the whole request object.
  keyedMutators: ['setAttribute', 'addHeader', 'setHeader'],
  keyedReaders: ['getAttribute', 'getHeader', 'getAttributeNames', 'getHeaders', 'getHeaderNames'],
  receiverSinks: [
    {
      methods: ['start'],
      kind: 'command',
      description: 'a process launched from a command list built earlier',
    },
  ],

  sources: [
    {
      /*
       * THE PARAMETER NAME IS ALSO THE ATTACKER'S, and the list read only the
       * ways of getting what they SENT, never the way of getting what they
       * CALLED IT.
       *
       *     GET /page?<script>alert(1)</script>=anything
       *
       * Forty-six BenchmarkJava cases iterate getParameterNames(), keep one
       * name, and print it - and every one was missed. getHeaderNames is the
       * same shape for the same reason: the client picks its own header names.
       *
       * WHERE THIS STOPS. Attribute names are chosen by the application's own
       * setAttribute calls; the context path, servlet path, method and protocol
       * are chosen by the container. A name ending in "Names" is not the test -
       * WHO CHOOSES IT is the test, and vulnerable/server-side-names.java holds
       * the ones that must never be traced as attacker data.
       */
      pattern:
        /\b(request|req|httpRequest|servletRequest)\.get(ParameterNames|HeaderNames|Parameter|ParameterValues|ParameterMap|Header|Headers|QueryString|Cookies|InputStream|Reader|RequestURI|RequestURL|PathInfo|RemoteUser)\s*\(/,
      description: 'HTTP servlet request data',
    },
    {
      pattern:
        /\bgetParameterNames\s*\(|\bgetHeaderNames\s*\(|\bgetParameter\s*\(|\bgetParameterValues\s*\(|\bgetParameterMap\s*\(|\bgetHeaders?\s*\(|\bgetQueryString\s*\(|\bgetCookies\s*\(|\bgetRequestURI\s*\(|\bgetPathInfo\s*\(/,
      description: 'an HTTP request parameter or header',
    },
    {
      pattern: /\bnew\s+Scanner\s*\(\s*System\.in\s*\)|\bSystem\.in\b/,
      description: 'console input',
    },
  ],

  callSinks: [
    {
      kind: 'sql',
      // Names that mean a database and nothing else. Safe bare.
      methods: [
        'executeQuery', 'executeUpdate', 'prepareStatement', 'prepareCall',
        'createNativeQuery', 'createSQLQuery', 'addBatch',
        'queryForObject', 'queryForList', 'queryForRowSet',
      ],
      argIndexes: [0],
      contentCheck: 'sql',
      description: 'a JDBC/JPA database query',
    },
    {
      kind: 'sql',
      /*
       * `execute` AND `createQuery` NEED A RECEIVER, and this is the sixth time
       * this project has learned that lesson about a different method name.
       *
       * Teaching Spring bindings to the tracer immediately produced three new
       * flow-verified SQL injections in WebGoat's PATH TRAVERSAL lesson -
       * including in `ProfileUploadFix` and `ProfileUploadRemoveUserInput`,
       * which are the lesson's CORRECTED variants. The sink was
       *
       *     super.execute(file, fullName, username)
       *
       * `execute` is one of the most common method names in Java and belongs to
       * Runnable, to every command object, and to half the abstract base classes
       * ever written. The new sources did not create this bug; they revealed one
       * that had been unreachable because nothing tainted ever got that far.
       *
       * `super` and `this` are excluded outright: a call to your own base class
       * is not a database, whatever it is called.
       */
      methods: ['execute', 'createQuery'],
      receiverPattern: /statement|stmt|conn|connection|jdbc|template|session|entityManager|em\b|db\b|database|query|cursor|dao|repo/i,
      argIndexes: [0],
      contentCheck: 'sql',
      description: 'a JDBC/JPA database query',
    },
    {
      kind: 'command',
      methods: ['exec'],
      /*
       * `Runtime.getRuntime().exec(cmd)` is the shell. `parser.exec()`,
       * `matcher.exec()` and every command-object `exec()` in Java are not, and
       * `exec` is short enough that plenty of APIs reach for it.
       *
       * A receiver naming the runtime is the whole signal. BenchmarkJava's
       * cmdi cases all spell it `Runtime.getRuntime().exec`, so this is checked
       * against 1,210 scored cases rather than argued about.
       */
      receiverPattern: /runtime/i, // Runtime.getRuntime().exec(...)
      /*
       * POSITION 0 IS THE COMMAND. POSITION 1 IS THE ENVIRONMENT, AND IT IS
       * ALSO A SINK.
       *
       *     Runtime.exec(String[] cmdarray, String[] envp, File dir)
       *                            ^0             ^1        ^2
       *
       * Roughly fifty BenchmarkJava cases put the attacker's value in `envp`
       * and a constant in `cmdarray`. The trace followed the value correctly
       * and then stopped, because this entry read argument 0 only.
       *
       * An attacker who controls the environment of a spawned process controls
       * LD_PRELOAD, PATH and IFS - command execution by a slightly longer
       * route - so OWASP scores those cases as real and this now agrees.
       *
       * Position 2, the working directory, is deliberately excluded. Control
       * there changes WHERE a program runs rather than WHAT runs; including it
       * would be widening on a hunch instead of on what the parameter means.
       * Nothing about the SQL sinks changes: their argIndexes: [0] is what
       * stops `stmt.execute(query, params)` - correctly parameterised code -
       * being reported as injection, which is the worse failure of the two.
       */
      argIndexes: [0, 1],
      description: 'a shell command via Runtime.exec (argument 0 is the command, 1 the environment it runs in)',
    },
    {
      kind: 'command',
      methods: ['ProcessBuilder'], // new ProcessBuilder(...)
      argIndexes: 'all',
      description: 'a process launched via ProcessBuilder',
    },
    {
      kind: 'xss',
      // `format` and `printf` are new here, and the receiver test is what makes
      // them safe to add: `String.format(fmt, dirty)` builds a string and is
      // not a sink, while `response.getWriter().format(fmt, dirty)` writes it
      // to the page and is.
      methods: ['print', 'println', 'write', 'printf', 'format', 'append'],
      // Every argument. `write(param, 0, length)` puts the payload first, but
      // `printf(locale, fmt, dirty)` puts it third, and watching only position
      // 0 misses the value that actually carries the attack.
      argIndexes: 'all',
      // What replaced contentCheck: 'html'. See receiverPattern in types.ts -
      // this one change is the difference between 204 missed real bugs and one
      // avoided false one.
      /*
       * `System.out` IS NOT A RESPONSE BODY, and `\bout\b` said it was.
       *
       * Scanning Keycloak - 4,000 Java files - produced six flow-verified XSS
       * findings and four were `System.out.println(...)` reported as "reaches
       * an HTTP response body written without escaping". A console, described
       * as a web page, at high severity, with a traced path claiming proof.
       *
       * Third time in this exact shape: process.stdout.write read as
       * document.write, fmt.Fprintf(buf) read as page output, now this. The
       * scoping sweep did not catch it because the sink IS scoped - the
       * receiver pattern simply had the wrong contents. A test that asks
       * "is there a constraint?" cannot see a constraint that is wrong, so
       * there is now a second test that asks whether each pattern matches a
       * console, and it is what found this line.
       */
      receiverPattern: /getWriter|getOutputStream|\b(pw|writer|resp|response)\b|(?<!System\.)\bout\b/i,
      description: 'an HTTP response body written without escaping',
    },
  ],

  assignSinks: [],

  sanitizers: [
    {
      /*
       * FRAMEWORK ESCAPERS, which is a list that can never be finished.
       *
       * Scanning Jenkins produced two FLOW-VERIFIED XSS findings on lines that
       * read `Functions.htmlAttributeEscape(redirectUrl)`. Jenkins escapes with
       * its own helper; this list knew `escapeHtml` and `htmlEscape` and not
       * that one, so a proof was published over code doing the right thing.
       *
       * Escapers are per-framework in exactly the way SOURCES turned out to be.
       * The signature rule now also matches them by shape - a name that says
       * escape/encode/sanitize AND names a markup context - and the named
       * entries here are the precise, intentional core it falls back from.
       * Jenkins, Struts and ESAPI spellings are added because they were met.
       */
      names: [
        'escapeHtml', 'escapeHtml3', 'escapeHtml4', 'htmlEscape', 'encodeForHTML', 'escapeXml',
        'htmlAttributeEscape', 'htmlAttributeEscapeString', 'escapeEcmaScript', 'escapeJavaScript',
        'encodeForHTMLAttribute', 'encodeForJavaScript', 'escapeXml10', 'escapeXml11',
      ],
      kinds: ['xss'],
      description: 'HTML escaping (Commons Text / Spring / ESAPI / Jenkins)',
    },
    { names: ['escapeSql'], kinds: ['sql'], description: 'SQL escaping' },
    {
      names: ['parseInt', 'parseLong', 'parseDouble', 'parseFloat', 'parseShort'],
      kinds: ['sql', 'command', 'xss'],
      description: 'conversion to a number',
    },
  ],

  propagators: {
    names: [
      'toString', 'trim', 'strip', 'concat', 'substring', 'replace', 'replaceAll',
      'format', 'append', 'toLowerCase', 'toUpperCase', 'join', 'split',
      'intern', 'valueOf', 'getBytes', 'repeat',
      // URL decoding does not clean anything - it makes an encoded payload
      // ACTIVE again, so it is a propagator, never a sanitiser.
      'decode', 'encode',
      // Reading a value out of an enumeration/iterator/collection of dirty data.
      'nextElement', 'nextToken', 'next', 'readLine', 'get', 'getValue',
    ],
  },
};

/* ========================================================================== *
 * Go  (net/http + database/sql)
 * ========================================================================== */

const GO_DICTIONARY: TaintDictionary = {
  mutators: ['WriteString', 'Write', 'WriteByte', 'WriteRune'],

  sources: [
    {
      pattern: /\b(r|req|request)\.(URL|Form|PostForm|MultipartForm|Header|Body|Host|RemoteAddr)\b/,
      description: 'an incoming *http.Request',
    },
    {
      pattern: /\b(r|req|request)\.(FormValue|PostFormValue|Referer|UserAgent|Cookie)\s*\(/,
      description: 'an HTTP request value read from the request',
    },
    { pattern: /\bmux\.Vars\s*\(/, description: 'gorilla/mux route variables' },
    {
      // Gin, Echo, Fiber and Chi all hand the handler a context object and all
      // spell the getters slightly differently: Gin has Param/Query/PostForm,
      // Echo has QueryParam/FormValue, Fiber has Params/Query/Body. Matching the
      // union costs nothing and the capability text now names Echo, so it has to
      // actually reach it.
      pattern: /\b(c|ctx)\.(Param|Params|Query|QueryParam|PostForm|FormValue|DefaultQuery|GetHeader|Body)\s*\(/,
      description: 'Gin/Echo request parameters',
    },
    { pattern: /\bos\.Args\b/, description: 'command-line arguments' },
  ],

  callSinks: [
    {
      kind: 'sql',
      methods: [
        'Query', 'QueryRow', 'QueryContext', 'QueryRowContext',
        'Exec', 'ExecContext', 'Prepare', 'PrepareContext', 'NamedExec', 'MustExec',
      ],
      // Matched against the receiver's NAME or its declared type, so both
      // `db.Query(...)` and `var store *sql.DB; store.Query(...)` are seen.
      receiverPattern: /\bdb\b|conn|\btx\b|stmt|sqlx|database|pool|sql\.DB|sql\.Tx/i,
      argIndexes: [0], // db.Query("... $1", id) - the rest are bound parameters
      contentCheck: 'sql',
      description: 'a database/sql query',
    },
    {
      kind: 'command',
      methods: ['Command', 'CommandContext'],
      argIndexes: 'all',
      // exec.Command("ping", host) is genuinely safe - no shell parses it. Only
      // a shell PROGRAM makes this dangerous.
      requiresShellOption: /["'`](sh|bash|zsh|cmd\.exe|powershell)["'`]/,
      description: 'a shell command via os/exec',
    },
    {
      kind: 'xss',
      methods: ['HTML', 'HTMLAttr', 'JS', 'JSStr', 'URL'],
      /*
       * These are conversions into html/template's trusted string types, and
       * they only mean that on the template package. Bare, `URL(...)` and
       * `JS(...)` are two of the most reusable identifiers in Go - a URL
       * builder, a JS minifier, somebody's helper.
       */
      receiverPattern: /template/i,
      argIndexes: [0],
      description: 'a html/template conversion that switches auto-escaping OFF',
    },
    {
      kind: 'xss',
      // The writer IS the receiver here: `w.Write(...)`, `w.WriteString(...)`.
      // `Write` belongs to every buffer, file, hash, socket and gzip stream in
      // Go, so the declared type does the work - `http.ResponseWriter` is a
      // page, `bytes.Buffer` is not.
      methods: ['Write', 'WriteString'],
      receiverPattern: /^w$|writer|\brw\b|resp|response|ResponseWriter/i,
      argIndexes: 'all',
      contentCheck: 'html',
      description: 'the HTTP response body',
    },
    {
      kind: 'xss',
      /*
       * THE LAST INSTANCE OF THE SCOPING CLASS, and the only one a receiver
       * rule could not reach.
       *
       * `fmt.Fprintf(w, format, args...)` writes to `w`. The receiver is `fmt`.
       * Widening the receiver pattern to keep these firing is what kept
       * `fmt.Fprintf(out, "%s: %s\\n", name, value)` in a gitea TEST MOCK
       * reported as cross-site scripting through an entire scoping sweep.
       *
       * So the destination is checked where it actually is - argument zero -
       * and argument zero is excluded from the payload check, because the
       * writer is where the output goes, not what is written.
       */
      methods: ['Fprintf', 'Fprint', 'Fprintln'],
      writerArgPattern: /^w$|writer|\brw\b|resp|response|ResponseWriter/i,
      argIndexes: 'all',
      contentCheck: 'html',
      description: 'the HTTP response body',
    },
  ],

  assignSinks: [],

  sanitizers: [
    {
      names: ['Atoi', 'ParseInt', 'ParseUint', 'ParseFloat', 'ParseBool'],
      kinds: ['sql', 'command', 'xss'],
      description: 'strconv conversion to a number',
    },
    {
      names: ['HTMLEscapeString', 'HTMLEscape', 'EscapeString', 'JSEscapeString'],
      kinds: ['xss'],
      description: 'HTML escaping',
    },
    { names: ['QuoteIdentifier'], kinds: ['sql'], description: 'SQL identifier quoting' },
  ],

  propagators: {
    names: [
      'Sprintf', 'Sprint', 'Sprintln', 'Join', 'TrimSpace', 'Trim', 'TrimPrefix',
      'TrimSuffix', 'ToLower', 'ToUpper', 'Replace', 'ReplaceAll', 'Split',
      'Fields', 'Repeat', 'String', 'Title', 'Get',
    ],
  },
};

/* ========================================================================== *
 * Registry
 * ========================================================================== */


/**
 * PHP.
 *
 * PHP is the language this whole tool class was invented for: the superglobals
 * are attacker input by definition, and the classic sinks take a string.
 *
 * What makes PHP different from the other four here is that the SOURCE is
 * unambiguous. `req.query.id` in JavaScript is a shape we guess at; `$_GET` is
 * attacker-controlled by specification, with no framework convention to read
 * and no chance of a false source. That is why PHP flow-verification is
 * unusually reliable - the uncertainty in the other languages lives at the
 * source, and here there is none.
 */
const PHP_DICTIONARY: TaintDictionary = {
  mutators: ['push', 'append', 'add', 'write', 'bindValue', 'bindParam'],
  // bindValue/bindParam stay out: a bound parameter is not read back out of the
  // statement as one of several items.
  elementMutators: ['push', 'append', 'add'],

  sources: [
    {
      pattern: /\$_(GET|POST|REQUEST|COOKIE|FILES)\b/,
      description: 'an HTTP request superglobal, which is attacker-controlled by definition',
    },
    {
      pattern: /\$_SERVER\s*\[\s*['"](QUERY_STRING|HTTP_[A-Z_]+|REQUEST_URI|PATH_INFO|argv)['"]/,
      description: 'a request-derived $_SERVER entry (headers, URI, query string)',
    },
    {
      pattern: /\bfile_get_contents\s*\(\s*['"]php:\/\/input['"]/,
      description: 'the raw HTTP request body',
    },
    {
      pattern: /\$request->(get|input|query|post|all|json|cookie|header)\b/,
      description: 'a Symfony/Laravel request accessor',
    },
  ],

  callSinks: [
    {
      kind: 'sql',
      // The `mysqli_*` / `pg_*` / `db_query` names below are unambiguous
      // functions. `query`, `exec`, `prepare` and `statement` are method names
      // anything can have, so the receiver has to look like a database handle -
      // or be absent, which is how the procedural functions are called.
      bareOnly: true,
      allowedReceivers: [
        'pdo', 'db', 'conn', 'connection', 'mysqli', 'link', 'dbh',
        'database', 'wpdb', 'capsule', 'stmt', 'statement', 'client', 'driver', 'this',
      ],
      methods: [
        'query', 'exec', 'prepare', 'unprepared', 'statement',
        'mysqli_query', 'mysqli_real_query', 'mysqli_multi_query', 'mysqli_prepare',
        'pg_query', 'mysql_query', 'sqlsrv_query', 'db_query',
      ],
      // mysqli_query($conn, $sql) puts the query SECOND; $pdo->query($sql) puts
      // it first. Watching both positions covers the procedural and the
      // object-oriented API without a separate entry for each.
      argIndexes: [0, 1],
      contentCheck: 'sql',
      description: 'a database query',
    },
    {
      kind: 'command',
      methods: ['system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open', 'pcntl_exec'],
      /*
       * These are PHP FUNCTIONS, so they are only themselves when called bare.
       * `$deployer->exec($cmd)` is somebody's method that happens to share the
       * name with the language's shell primitive - the same collision that made
       * a regular expression's `.exec()` a critical shell-command finding in
       * gitea's browser code.
       */
      bareOnly: true,
      argIndexes: [0],
      description: 'a shell command',
    },
    {
      kind: 'ssrf',
      // file_get_contents doubles as a file reader. A hit is either SSRF or
      // path traversal, and both deserve the same second look.
      methods: ['file_get_contents', 'fopen', 'curl_init', 'curl_setopt', 'readfile'],
      argIndexes: 'all',
      description: 'an outbound fetch, so the server retrieves whatever this names',
    },
    {
      kind: 'code',
      methods: ['eval', 'assert', 'create_function'],
      bareOnly: true,
      argIndexes: [0],
      description: 'the PHP interpreter, which runs the string as program code',
    },
    {
      kind: 'deserialization',
      methods: ['unserialize'],
      argIndexes: [0],
      // The hardened form is the same call with a second argument. Reporting it
      // would punish the fix.
      unlessOption: /allowed_classes/,
      description: 'unserialize(), which rebuilds objects the bytes name',
    },
    {
      kind: 'xss',
      methods: ['printf', 'vprintf', 'print_r', 'var_dump'],
      // ALL arguments, not just the first. printf's argument 0 is the format
      // string and every argument after it is the data being printed into the
      // page - watching only position 0 misses the value that actually carries
      // the payload, which is the normal shape: printf("<p>%s</p>", $bio).
      argIndexes: 'all',
      description: 'output written straight to the response body',
    },
  ],

  // `echo $x;` is captured by the shape layer as an assignment whose target is
  // the `echo` keyword, so the taint engine sees it the same way it sees
  // `el.innerHTML = x` in JavaScript. See ASSIGNMENT_QUERIES.php.
  assignSinks: [
    {
      kind: 'xss',
      properties: ['echo', 'print'],
      description: 'output written straight to the response body by echo/print',
    },
    {
      kind: 'xss',
      /*
       * THE PAGE BUFFER - and the reason PHP XSS recall was zero.
       *
       * The first recall measurement outside Java scored 9 of DVWA's 9 XSS
       * cases as MISSED, every one of them this shape:
       *
       *     $html .= '<pre>Hello ' . $_GET['name'] . '</pre>';
       *
       * DVWA never echoes at the point of the bug. It accumulates the page into
       * `$html` and prints it from a template in a DIFFERENT FILE - and PHP has
       * no cross-file tracing, so following it there is not an option either.
       * This is not a DVWA quirk; building output into a buffer and emitting it
       * once is ordinary PHP.
       *
       * WHAT THIS IS EVIDENCE OF, honestly. A variable named like page output,
       * accumulating a string whose literal parts contain HTML tags. That is
       * weaker than seeing `echo` - the name is a convention, not a proof - and
       * it is the same class of assumption the engine already makes when it
       * treats a `req.query`-shaped expression as a real request. The
       * looksLikeHtml gate is what keeps it from firing on every accumulator:
       * `$sql .= $where` builds a query, not a page.
       */
      properties: ['html', 'output', 'page', 'content', 'body', 'buffer', 'markup', 'out'],
      contentCheck: 'html',
      description: 'a page buffer that is printed later, often from another file',
    },
  ],

  sanitizers: [
    {
      names: ['htmlspecialchars', 'htmlentities', 'strip_tags', 'html_entity_decode_safe'],
      kinds: ['xss'],
      description: 'HTML escaping (htmlspecialchars / htmlentities)',
    },
    {
      /*
       * WORDPRESS'S ESCAPING API, WHICH IS MOST OF THE PHP ON THE INTERNET.
       *
       * WordPress does not call htmlspecialchars directly; it wraps it. A scan
       * of 2,119 WordPress files produced 2,971 XSS findings and 2,547 of them
       * were `echo esc_html( $x )` - the correct, documented way to output
       * anything in WordPress, reported as the bug it prevents.
       *
       * 223 of them were FLOW-VERIFIED, which is the part that mattered. The
       * tracer found a real source, followed it correctly, and stopped inside
       * `esc_html( $result->get_error_message() )` calling the flow proven. A
       * guess that lands on escaped code is noise; a proof that lands on it is
       * a false statement, and the sanitiser was in the argument list being
       * read at the time.
       *
       * KNOWN IMPRECISION, stated rather than implied: these are CONTEXT
       * escapers. esc_html is correct in element text and wrong inside a
       * <script>; esc_js is the reverse. We accept any of them for any XSS
       * sink, so using the wrong one for the context is not detected. That is a
       * narrower bug than the one this fixes, and pretending otherwise by
       * leaving all 2,547 in place would not have found it either.
       */
      names: [
        'esc_html', 'esc_attr', 'esc_url', 'esc_url_raw', 'esc_js', 'esc_textarea', 'esc_xml',
        'esc_html__', 'esc_html_e', 'esc_html_x', 'esc_attr__', 'esc_attr_e', 'esc_attr_x',
        'wp_kses', 'wp_kses_post', 'wp_kses_data', 'tag_escape', 'sanitize_html_class',
        'sanitize_text_field', 'sanitize_textarea_field', 'sanitize_title', 'sanitize_email',
        'sanitize_key', 'sanitize_user', 'wp_json_encode', 'absint',
      ],
      kinds: ['xss'],
      description: "WordPress escaping (esc_html / esc_attr / esc_url / wp_kses)",
    },
    {
      // Native PHP encoders that cannot emit a bare `<`, plus the one-letter
      // helper Laravel and Twig both spell `e()`.
      names: ['urlencode', 'rawurlencode', 'json_encode', 'e', 'number_format'],
      kinds: ['xss'],
      description: 'URL/JSON encoding, which cannot produce a raw tag',
    },
    {
      names: ['escapeshellarg', 'escapeshellcmd'],
      kinds: ['command'],
      description: 'shell argument quoting (escapeshellarg)',
    },
    {
      names: ['intval', 'floatval', 'intdiv'],
      kinds: ['sql', 'command', 'xss'],
      description: 'conversion to a number',
    },
    {
      names: ['real_escape_string', 'mysqli_real_escape_string', 'pg_escape_literal', 'quote'],
      kinds: ['sql'],
      // Deliberately called escaping, not parameterisation. It IS weaker than a
      // prepared statement and gets the wrong answer under some charsets, but a
      // traced value that passes through it is not the same finding as one that
      // does not - so we stop the trace and say which one we saw.
      description: 'database string escaping (weaker than a prepared statement, but applied)',
    },
  ],

  propagators: {
    names: [
      'strval', 'trim', 'ltrim', 'rtrim', 'strtolower', 'strtoupper', 'ucfirst',
      'str_replace', 'substr', 'sprintf', 'implode', 'explode', 'json_encode',
      'urlencode', 'rawurlencode', 'str_pad', 'nl2br',
      'base64_decode', 'base64_encode', 'gzuncompress', 'gzinflate',
    ],
  },
};

/* ========================================================================== *
 * C
 *
 * THE SHORTEST SOURCE LIST IN THIS FILE, AND THE MOST RELIABLE ONE.
 *
 * Every other language here is a list of FRAMEWORK accessors, and the honesty
 * note on each one says the same thing: we recognise `req.query` by its shape
 * and cannot prove `req` is really a request. That approximation is why the
 * Java entry has to name Spring and JAX-RS separately, and why elasticsearch's
 * house-built RestRequest is invisible to all of them.
 *
 * C has no frameworks. Its sources are the operating system, and they have not
 * changed since the 1970s: the command line, the environment, standard input,
 * a file descriptor, a socket. There is no Express-versus-Koa problem to have.
 * `argv` is argv in every C program ever written.
 *
 * The sinks are equally old and equally unambiguous. `system()` is a shell,
 * always - it has no options object, no parameterised form, and nothing safe
 * to be confused with. The scoping problems that dominate the JS and Java sink
 * tables (is this `exec` a shell or a regular expression? is this `query` a
 * database or a Map?) simply do not arise.
 *
 * WHAT IS NOT HERE, and it is the important half: memory safety. Buffer
 * overflows, use-after-free, double-free and integer overflow are what C is
 * actually famous for, and this engine models none of them, because deciding
 * any of them needs sizes, allocation lifetimes and pointer aliasing rather
 * than values. The `overflow` sink below is narrower than its name suggests -
 * see the comment on it.
 * ========================================================================== */

/** Shared by C and C++: the libc surface is identical in both. */
const C_SOURCES: readonly SourceSpec[] = [
  {
    pattern: /\bargv\s*\[|\*\s*argv\b|\bargv\b/,
    description: 'a command-line argument, which the caller of this program chooses',
  },
  {
    pattern: /\bgetenv\s*\(/,
    description:
      'an environment variable - attacker-controlled whenever the attacker controls the ' +
      'parent process, which is the normal case for CGI programs and setuid binaries',
  },
  {
    pattern: /\b(fgets|gets|scanf|fscanf|sscanf|getline|getchar|fgetc)\s*\(/,
    description: 'standard input',
  },
  {
    pattern: /\b(read|recv|recvfrom|recvmsg|fread)\s*\(/,
    description: 'bytes read from a file descriptor or a socket',
  },
];

/**
 * The printf family, and WHICH argument is the format in each.
 *
 * This table is the whole format-string rule. Getting an index wrong here does
 * not merely miss a bug, it reports the FIX as the bug: `printf("%s", name)`
 * is the correct form, and a rule that scanned every argument would flag it.
 * The dangerous call and the safe call are the same function with an argument
 * added - exactly the prepared-statement shape from the SQL rules.
 */
const C_FORMAT_SINKS: readonly CallSinkSpec[] = [
  {
    kind: 'format',
    methods: ['printf', 'vprintf'],
    argIndexes: [0],
    description: 'a format string, where %n writes to memory the attacker chooses',
  },
  {
    kind: 'format',
    methods: ['fprintf', 'sprintf', 'vfprintf', 'vsprintf', 'dprintf', 'asprintf', 'syslog'],
    argIndexes: [1],
    description: 'a format string, where %n writes to memory the attacker chooses',
  },
  {
    kind: 'format',
    methods: ['snprintf', 'vsnprintf'],
    argIndexes: [2],
    description: 'a format string, where %n writes to memory the attacker chooses',
  },
];

/**
 * Copies with no length parameter.
 *
 * READ THE KIND NAME AS WRITTEN: `overflow` here means "reaches a copy with no
 * length bound", not "overflows". The destination's size is not modelled, so a
 * strcpy into a genuinely large enough buffer is a FALSE POSITIVE of this
 * rule - declared, not discovered. It is still worth reporting because these
 * functions have no upper bound by construction: they write until they meet a
 * NUL byte and the attacker picks where that is.
 *
 * The bounded siblings - strncpy, snprintf, strlcpy - are deliberately absent,
 * and c-format-constant.c asserts they stay quiet.
 */
const C_OVERFLOW_SINKS: readonly CallSinkSpec[] = [
  {
    kind: 'overflow',
    methods: ['strcpy', 'strcat', 'stpcpy'],
    argIndexes: [1],
    description: 'a copy with no length bound, which writes until it meets a NUL byte',
  },
  {
    // Argument 0 is the destination and argument 1 is the format; anything
    // after that is a value being written out through a %s with no width.
    kind: 'overflow',
    methods: ['sprintf', 'vsprintf'],
    argIndexes: [2, 3, 4, 5, 6],
    description: 'a copy with no length bound, which writes until it meets a NUL byte',
  },
];

const C_DICTIONARY: TaintDictionary = {
  sources: C_SOURCES,

  callSinks: [
    {
      kind: 'command',
      methods: ['system', 'popen'],
      argIndexes: [0],
      description: 'a shell, which runs the string as a command line',
    },
    {
      // exec* takes an argument VECTOR, so a semicolon in an argument is just a
      // semicolon - UNLESS the program being run is itself a shell, which turns
      // the next argument back into a command line.
      kind: 'command',
      methods: ['execl', 'execlp', 'execv', 'execvp', 'execle', 'execve'],
      argIndexes: 'all',
      requiresShellOption: /["'](\/bin\/)?(sh|bash|zsh|ksh|dash)["']/,
      description: 'a shell invoked through exec',
    },
    ...C_FORMAT_SINKS,
    ...C_OVERFLOW_SINKS,
    {
      kind: 'sql',
      methods: [
        'mysql_query', 'mysql_real_query', 'PQexec', 'sqlite3_exec',
        'sqlite3_get_table', 'SQLExecDirect',
      ],
      // PQexec(conn, sql) and sqlite3_exec(db, sql, ...) both put the handle
      // first, so the statement is argument one. mysql_query is the same shape.
      argIndexes: [1],
      description: 'a database query',
    },
  ],

  assignSinks: [],

  /*
   * C's sanitiser list is SHORT AND HONEST, and the shortness is the point.
   *
   * The bounded copy functions genuinely stop an unbounded write, so they clear
   * `overflow`. They do nothing whatsoever about a shell: snprintf into a
   * command buffer produces a perfectly well-sized command line that still runs
   * whatever the attacker put in it. Kind-scoping is what keeps those separate,
   * and it matters more here than anywhere else in this file, because the C
   * habit of "fixing" a system() call by switching sprintf to snprintf is
   * extremely common and fixes nothing.
   *
   * There is no standard C function that makes a string safe for a shell.
   * None. That is why the command sink has no sanitiser at all - the fix is to
   * stop using a shell, not to clean the string.
   */
  sanitizers: [
    {
      names: ['strncpy', 'strncat', 'strlcpy', 'strlcat', 'snprintf', 'vsnprintf'],
      kinds: ['overflow'],
      description: 'a bounded copy - the write cannot run past the length given',
    },
    {
      names: ['sqlite3_bind_text', 'sqlite3_bind_int', 'mysql_stmt_bind_param', 'PQexecParams'],
      kinds: ['sql'],
      description: 'a bound parameter - the value is data, never part of the statement',
    },
  ],

  propagators: {
    names: [
      'strdup', 'strndup', 'basename', 'dirname', 'realpath', 'strtok', 'strchr',
      'strrchr', 'strstr', 'memcpy', 'memmove', 'atoi', 'atol', 'strtol',
    ],
  },

  /*
   * THE LINE THAT MAKES C WORK AT ALL. See checkOutParamMutation in tracer.ts.
   *
   *     sprintf(cmd, "ping %s", argv[1]);   ->  cmd is tainted
   *     system(cmd);                        ->  reported
   *
   * Without this the two lines are unrelated and every command injection in
   * the language reads as clean. Note snprintf and strncpy appear both here
   * and as sanitisers: they BOUND the write (so `overflow` is cleared) while
   * still carrying the attacker's bytes into the destination (so `command` is
   * not). The kind-scoped sanitiser model is what lets one function do both.
   */
  outParamMutators: [
    'sprintf', 'snprintf', 'vsprintf', 'vsnprintf', 'strcpy', 'strncpy',
    'strcat', 'strncat', 'strlcpy', 'strlcat', 'memcpy', 'memmove', 'sscanf',
  ],

  /*
   * The destination index is written out per function because it genuinely
   * differs, and guessing zero would be wrong more often than right:
   *
   *     fgets(buf, n, stream)      buf is 0
   *     scanf("%s", buf)           buf is 1 - the format comes first
   *     read(fd, buf, n)           buf is 1 - the descriptor comes first
   *     fscanf(f, "%s", buf)       buf is 2
   */
  outParamSources: [
    {
      names: ['fgets', 'gets', 'getline', 'getdelim'],
      destination: 0,
      description: 'standard input or an open stream',
    },
    { names: ['scanf'], destination: 1, description: 'standard input' },
    { names: ['fscanf', 'sscanf'], destination: 2, description: 'a stream or a string' },
    {
      names: ['read', 'recv', 'fread'],
      destination: 1,
      description: 'a file descriptor or a socket',
    },
  ],
};

/* ========================================================================== *
 * C++
 *
 * Every C entry applies - C++ inherits the whole libc surface and people still
 * use it. What is added is the three things that are genuinely different:
 * namespace-qualified calls (`std::system`), method calls on objects
 * (`db.query(sql)`), and std::string, which brings `+` concatenation back and
 * so makes the string-building analysis relevant in a way it is not in C.
 * ========================================================================== */

const CPP_DICTIONARY: TaintDictionary = {
  ...C_DICTIONARY,

  /*
   * C HAS NO METHODS, SO IT DECLARES NO MUTATORS. C++ INHERITED THAT EMPTY
   * LIST AND SHOULD NOT HAVE.
   *
   * Every other language here declares mutators - the methods that dirty the
   * object they are called ON, rather than returning a dirty value. C++ had
   * none, so this was silent:
   *
   *     std::string cmd = "gzip ";
   *     cmd.append(argv[1]);     // nothing recorded cmd as dirty
   *     std::system(cmd.c_str());
   *
   * `append` was already a PROPAGATOR, which is a different direction: it
   * carries taint from the receiver out to the result, so `dirty.append(" -v")`
   * traced and `clean.append(dirty)` did not. Being listed in one direction
   * looked from the outside like being handled.
   *
   * STRING METHODS ONLY, AND DELIBERATELY SO. push_back, emplace_back and the
   * container form of insert are missing on purpose: they write ELEMENTS, and
   * an element write needs a matching `elementMutators` entry or the
   * containerGuess rule cannot do its job - a container written many times and
   * read back once would come out claiming a proof it has not got. Modelling
   * C++ containers means modelling both lists together, and that is its own
   * piece of work rather than a line added here. Until then, taint into a
   * std::vector is a documented miss and not a quiet one.
   */
  mutators: ['append', 'assign', 'replace'],

  sources: [
    ...C_SOURCES,
    {
      pattern: /\bstd::cin\b|\bgetline\s*\(\s*std::cin/,
      description: 'standard input, read through the C++ stream API',
    },
  ],

  callSinks: [
    ...C_DICTIONARY.callSinks,
    {
      // Receiver-scoped, for the same reason the JS `query` sink is: `query` on
      // a database handle is SQL, and `query` on anything else is somebody's
      // search helper. Without the receiver check this is the VS Code
      // RegExp.exec mistake waiting to happen again.
      kind: 'sql',
      methods: ['query', 'execute', 'exec', 'prepare'],
      receiverPattern: /db|conn|connection|session|stmt|sql|database|mysql|postgres|sqlite|pqxx|soci/i,
      argIndexes: [0],
      contentCheck: 'sql',
      description: 'a database query',
    },
  ],

  propagators: {
    names: [
      ...C_DICTIONARY.propagators.names,
      // std::string's accessors hand the bytes straight back out. c_str() in
      // particular is how a tainted std::string reaches system(), so without it
      // every C++ command injection in cmdi.cpp would stop one hop short.
      'c_str', 'data', 'substr', 'to_string', 'string', 'append', 'assign',
    ],
  },
};

export const TAINT_DICTIONARIES: Partial<Record<LanguageId, TaintDictionary>> = {
  javascript: JS_DICTIONARY,
  typescript: JS_DICTIONARY,
  python: PYTHON_DICTIONARY,
  java: JAVA_DICTIONARY,
  go: GO_DICTIONARY,
  php: PHP_DICTIONARY,
  c: C_DICTIONARY,
  cpp: CPP_DICTIONARY,
};

export const TAINT_LANGUAGES = Object.keys(TAINT_DICTIONARIES) as LanguageId[];

/** Per-language honesty notes, printed in the coverage section of every scan. */
export const TAINT_COVERAGE_NOTES: Record<LanguageId, string> = {
  c:
    'IMPLEMENTED: the operating system IS the framework here, so the sources are argv, getenv, stdin (fgets/scanf/getline) and socket reads - a shorter and far more reliable list than any framework language, because argv is argv in every C program ever written. Sinks: shells (system, popen, and exec* only when the program being run is itself a shell), format strings (the printf family, where a tainted FORMAT argument is CWE-134), copies with no length bound (strcpy, strcat, sprintf), and the C database APIs (mysql_query, PQexec, sqlite3_exec). The output-parameter idiom is modelled - sprintf(cmd, "...", dirty) taints cmd - which is the shape every real C command injection is written in. NOT COVERED, and this is the important half: MEMORY SAFETY. Buffer overflows, use-after-free, double-free and integer overflow are what C is famous for and this engine models none of them, because deciding any of them needs sizes, allocation lifetimes and pointer aliasing rather than values. An unbounded-copy finding claims only that attacker data reached a function that writes until it meets a NUL byte; it does NOT claim the destination is too small, so a strcpy into a genuinely large buffer is a declared false positive. THE PREPROCESSOR IS NOT RUN: #include is not followed, every #ifdef branch is parsed as though taken, and a macro hiding a sink (#define RUN(x) system(x)) is invisible. Cross-file tracing is OFF for the C family - #include brings in declarations rather than definitions, and same-directory matching would be unsafe because `static` gives a C function file scope and every large project has a dozen different static init() definitions in one folder.',
  cpp:
    'IMPLEMENTED: everything listed for C, plus namespace-qualified calls (std::system), receiver-scoped database methods (db.query(sql)), and std::string - whose c_str(), substr() and operator+ carry taint, which is how a tainted string actually reaches system() in C++ code. NOT COVERED: every C limitation applies unchanged, and additionally templates are parsed but never instantiated, so a sink reached only through a specialisation is missed, and operator overloading is not resolved - a custom operator<< that runs a command reads as an ordinary stream write. The .h extension is analysed as C++ rather than C: the grammars are not symmetric (measured, the C++ grammar parses C with zero errors while the C grammar produces eleven on C++), so the superset is used, which costs a pure-C project a cosmetic mislabel in the per-language counts instead of costing a C++ header every std:: sink in it.',
  javascript:
    'IMPLEMENTED: Express/Koa/Lambda request objects, browser location and storage. Follows values into other functions, and into other files where a relative import resolves. NOT covered: re-exports, dynamic imports and build-tool path aliases.',
  typescript:
    'IMPLEMENTED: the JavaScript dictionary, plus the type syntax that sits between a source and a sink - annotated bindings, `as`, `<T>` angle-bracket assertions, `!`, `satisfies`, generic call boundaries, enum-keyed reads, abstract and decorated methods, and .tsx with React. This used to read "identical to JavaScript" and that was an assertion, not a measurement: TypeScript has its own grammar, every construct above is a node the JavaScript lowerer never sees, and and until ts-only-syntax.ts was written every TypeScript finding in the fixture suite was signature-based, so not one of them had ever been traced. When it was finally tested, one had been broken since the day TypeScript was added - `<string>x` put its type where `as` puts its value, so the tracer read the word `string` and called the value clean. NOT COVERED: object interiors, which is not a TypeScript limitation but is where TypeScript code meets it most often - a value that enters an object literal and leaves through a destructured prop or an interface-typed field loses its proof and is reported signature-based rather than flow-verified. A React prop is exactly that shape, so component boundaries downgrade. Type-only constructs carry nothing and are never treated as data. Decorators are read as syntax: a NestJS @Body() parameter is not yet recognised as a source, so a decorated controller is traced only from whatever source it reads itself.',
  python:
    'IMPLEMENTED: Flask/Django/DRF request objects, sys.argv, input(). Follows values across functions, and across modules where a relative import resolves. A view that RETURNS an HTML string is treated as a sink, since in Flask/Django the return value is the response body - we do not verify the function is a route handler. Constant conditions are evaluated, so a value that only ever reaches a branch decided at compile time is not claimed as proven - and until constant-branch.py was written, NONE of that worked in Python. The three shapes it needs - `A if C else B`, `a > b` and `not x` - name none of their parts in the Python grammar, unlike every other grammar here, so every Python comparison read as undecidable and `not True` read as true. NOT covered: @app.route-bound path parameters are not recognised as sources; and a CHAINED comparison (1 < x < 5) is not folded, because a chain is a list of operands rather than a pair - it reads as undecidable, the branch is assumed live, and the value is carried, which costs a false positive rather than a miss.',
  java:
    'IMPLEMENTED: Servlet request getters (getParameter, getParameterValues, getHeader, getQueryString, getCookies and friends), JDBC/JPA query sinks, Runtime.exec and ProcessBuilder, and response writers - print/println/write/printf/format/append are sinks when the RECEIVER is a servlet writer, which is what separates response.getWriter().format(fmt, dirty) from String.format(fmt, dirty). Array initialisers carry taint, so Object[] a = {"x", dirty} stays dirty. Spring (@RequestParam, @PathVariable, @RequestBody and friends) and JAX-RS (@QueryParam, @PathParam and friends) annotated parameters are sources. A keyed write - req.setAttribute(name, dirty), resp.setHeader(name, dirty) - dirties that named store and NOT the rest of the object, so req.getContextPath() stays clean; reads out of the store are key-INSENSITIVE, so getAttribute() under any name comes back tainted. NOT covered: a writer stored under an unrecognised variable name is missed because the receiver is matched by its text, and the keyed-store rule is Java-only - a JS Map.set() or a Python dict update still dirties the whole container.',
  php:
    'IMPLEMENTED: $_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES superglobals, request-derived $_SERVER entries, PDO and mysqli query sinks, shell functions, and echo. Follows values across functions WITHIN one file. NOT covered: cross-file tracing is off for PHP entirely - require/include are statements and Composer autoloading resolves classes with no import line to read, so a call into another file ends the trace. Blade and Twig templates are not parsed. A value checked by a VALIDATION GUARD - is_numeric, ctype_digit, ctype_alnum and siblings - is treated as safe inside the branch that check guards, and only there; guards that prove nothing about the character set (strlen, isset, empty, preg_match) are not counted. Constant conditions are evaluated, and PHP needed three grammar-specific repairs before that was true here: the middle operand of `a ? b : c` is unnamed, the elvis form `a ?: b` has no middle operand at all, an `if` calls its then-block `body` rather than `consequence`, and a `$variable` is a wrapper node rather than a bare identifier. The `if` one is worth naming because it broke in ONE DIRECTION - a condition that folded true correctly dropped the dead else, a condition that folded false kept the dead then - which is the kind of half-working that no test notices.',
  go: 'IMPLEMENTED: net/http request values, gorilla/mux and Gin params, database/sql sinks, template.HTML escape hatches. NOT covered: multi-value assignments (a, b := f()) bind only when the two sides line up, multi-value assignments (a, b := f()) bind EVERY name on the left to the same taint, so the engine over-claims which of the returned names is dirty rather than losing the value. Aliased imports were previously listed here as a general miss and that was too broad: the taint sinks match on the method name, so `sh "os/exec"` and `runner "os/exec"` are both traced. The alias limitation is real only where a rule matches on the receiver PACKAGE text - weak-hash - and that rule states it itself.',
};
