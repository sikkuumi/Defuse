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
import type { TaintDictionary } from './types.js';

/* ========================================================================== *
 * JavaScript / TypeScript
 * ========================================================================== */

const JS_DICTIONARY: TaintDictionary = {
  mutators: ['push', 'unshift', 'splice', 'add', 'set', 'append', 'write', 'writeln'],

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
      // ONLY argument 0. See the note on argIndexes in types.ts - this is what
      // stops us reporting the correct, parameterised form as a vulnerability.
      argIndexes: [0],
      contentCheck: 'sql',
      description: 'a database query',
    },
    {
      kind: 'command',
      methods: ['exec', 'execSync'],
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
      kind: 'xss',
      methods: ['write', 'writeln'],
      argIndexes: 'all',
      description: 'document.write, which parses its argument as HTML',
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
      methods: ['execute', 'executemany', 'executescript', 'raw', 'text'],
      argIndexes: [0], // cursor.execute(sql, params) - params are safe by design
      contentCheck: 'sql',
      description: 'a database query',
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
      argIndexes: [0],
      requiresShellOption: /shell\s*=\s*True/,
      description: 'a shell command (shell=True is set on this call)',
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
  // StringBuilder/StringBuffer, the Collections API, and servlet response
  // writers - the three ways Java code carries a value without assigning it.
  mutators: ['append', 'insert', 'add', 'addAll', 'put', 'putAll', 'push', 'offer', 'write', 'print', 'println', 'setAttribute', 'addHeader', 'setHeader', 'command', 'directory', 'environment'],
  receiverSinks: [
    {
      methods: ['start'],
      kind: 'command',
      description: 'a process launched from a command list built earlier',
    },
  ],

  sources: [
    {
      pattern:
        /\b(request|req|httpRequest|servletRequest)\.get(Parameter|ParameterValues|ParameterMap|Header|Headers|QueryString|Cookies|InputStream|Reader|RequestURI|RequestURL|PathInfo|RemoteUser)\s*\(/,
      description: 'HTTP servlet request data',
    },
    {
      pattern:
        /\bgetParameter\s*\(|\bgetParameterValues\s*\(|\bgetParameterMap\s*\(|\bgetHeaders?\s*\(|\bgetQueryString\s*\(|\bgetCookies\s*\(|\bgetRequestURI\s*\(|\bgetPathInfo\s*\(/,
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
      methods: [
        'executeQuery', 'executeUpdate', 'execute', 'prepareStatement', 'prepareCall',
        'createQuery', 'createNativeQuery', 'createSQLQuery', 'addBatch',
        'queryForObject', 'queryForList', 'queryForRowSet',
      ],
      argIndexes: [0],
      contentCheck: 'sql',
      description: 'a JDBC/JPA database query',
    },
    {
      kind: 'command',
      methods: ['exec'], // Runtime.getRuntime().exec(...)
      argIndexes: [0],
      description: 'a shell command via Runtime.exec',
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
      receiverPattern: /getWriter|getOutputStream|\b(out|pw|writer|resp|response)\b/i,
      description: 'an HTTP response body written without escaping',
    },
  ],

  assignSinks: [],

  sanitizers: [
    {
      names: ['escapeHtml', 'escapeHtml3', 'escapeHtml4', 'htmlEscape', 'encodeForHTML', 'escapeXml'],
      kinds: ['xss'],
      description: 'HTML escaping (Commons Text / Spring / ESAPI)',
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
      pattern: /\b(c|ctx)\.(Param|Query|PostForm|DefaultQuery|GetHeader)\s*\(/,
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
      argIndexes: [0],
      description: 'a html/template conversion that switches auto-escaping OFF',
    },
    {
      kind: 'xss',
      methods: ['Write', 'WriteString', 'Fprintf', 'Fprint', 'Fprintln'],
      argIndexes: 'all',
      contentCheck: 'html',
      description: 'an HTTP response body written without escaping',
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
      argIndexes: [0],
      description: 'a shell command',
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
  ],

  sanitizers: [
    {
      names: ['htmlspecialchars', 'htmlentities', 'strip_tags', 'html_entity_decode_safe'],
      kinds: ['xss'],
      description: 'HTML escaping (htmlspecialchars / htmlentities)',
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

export const TAINT_DICTIONARIES: Partial<Record<LanguageId, TaintDictionary>> = {
  javascript: JS_DICTIONARY,
  typescript: JS_DICTIONARY,
  python: PYTHON_DICTIONARY,
  java: JAVA_DICTIONARY,
  go: GO_DICTIONARY,
  php: PHP_DICTIONARY,
};

export const TAINT_LANGUAGES = Object.keys(TAINT_DICTIONARIES) as LanguageId[];

/** Per-language honesty notes, printed in the coverage section of every scan. */
export const TAINT_COVERAGE_NOTES: Record<LanguageId, string> = {
  javascript:
    'IMPLEMENTED: Express/Koa/Lambda request objects, browser location and storage. Follows values into other functions, and into other files where a relative import resolves. NOT covered: re-exports, dynamic imports and build-tool path aliases.',
  typescript: 'IMPLEMENTED: identical to JavaScript, including .tsx.',
  python:
    'IMPLEMENTED: Flask/Django/DRF request objects, sys.argv, input(). Follows values across functions, and across modules where a relative import resolves. A view that RETURNS an HTML string is treated as a sink, since in Flask/Django the return value is the response body - we do not verify the function is a route handler. NOT covered: @app.route-bound path parameters are not recognised as sources.',
  java:
    'IMPLEMENTED: Servlet request getters (getParameter, getParameterValues, getHeader, getQueryString, getCookies and friends), JDBC/JPA query sinks, Runtime.exec and ProcessBuilder, and response writers - print/println/write/printf/format/append are sinks when the RECEIVER is a servlet writer, which is what separates response.getWriter().format(fmt, dirty) from String.format(fmt, dirty). Array initialisers carry taint, so Object[] a = {"x", dirty} stays dirty. NOT covered: Spring @RequestParam-annotated parameters are not recognised as sources, and a writer stored under an unrecognised variable name is missed because the receiver is matched by its text.',
  php:
    'IMPLEMENTED: $_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES superglobals, request-derived $_SERVER entries, PDO and mysqli query sinks, shell functions, and echo. Follows values across functions WITHIN one file. NOT covered: cross-file tracing is off for PHP entirely - require/include are statements and Composer autoloading resolves classes with no import line to read, so a call into another file ends the trace. Blade and Twig templates are not parsed.',
  go: 'IMPLEMENTED: net/http request values, gorilla/mux and Gin params, database/sql sinks, template.HTML escape hatches. NOT covered: multi-value assignments (a, b := f()) bind only when the two sides line up, and a package imported under an alias is matched by the alias, not the real package.',
};
