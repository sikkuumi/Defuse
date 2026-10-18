/**
 * A RESPONSE THAT SAYS IT IS NOT A PAGE.
 * =====================================
 *
 * `HttpResponse(request.body, content_type="text/plain")` puts request data in
 * the response - and a browser shows text/plain, CSV and JSON as text. It parses
 * no markup and runs no script (Django also sends X-Content-Type-Options:
 * nosniff by default, so the type is not second-guessed). Scanning Django
 * reported exactly this as a flow-verified XSS.
 *
 * Shared by the data-flow sink (taint/dictionaries.ts) and the signature rule
 * (rules/xss.ts), so the two cannot disagree about what a page is.
 *
 * Only a literal `content_type=` keyword in the call is read. A positional
 * content type, or one held in a variable, still reports. SVG and XML are not
 * on the list: both can carry script (tests/fixtures/vulnerable/
 * django-responses.py).
 */
export const DECLARED_NOT_HTML =
  /\bcontent_type\s*=\s*(["'])\s*(?:text\/plain|text\/csv|application\/json)\s*(?:;[^"']*)?\1/;
