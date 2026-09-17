/**
 * SERVER-SIDE REQUEST FORGERY - SSRF  (CWE-918, OWASP A01:2025 - Broken Access Control)
 *
 * WHAT THE BUG IS, in plain language:
 * Your server fetches a URL that the user chose. That sounds harmless - it is
 * just an HTTP request - until you remember WHERE your server is standing.
 *
 *     const data = await fetch(req.query.target);
 *
 * The attacker's browser cannot reach your database, your admin panel on
 * port 8080, or `169.254.169.254` - the cloud metadata endpoint that hands out
 * your instance's credentials to anything inside the network. Your server can
 * reach all three. So the attacker stops trying to get in, and asks your server
 * to go and fetch it for them. The firewall sees a request from a trusted
 * machine and lets it through.
 *
 * THE FIX is an allowlist of hosts, not a blocklist. Blocklists lose, always:
 * `localhost` has `127.0.0.1`, `127.1`, `0.0.0.0`, `[::1]`, `2130706433`, a
 * DNS name that resolves to loopback, and a redirect from a public host to a
 * private one. Decide the small set of hosts you MEANT to talk to, resolve the
 * URL, and check membership - then fetch.
 *
 * ============================================================================
 * WHY THIS RULE HAS NO SIGNATURE PASS
 * ============================================================================
 * Every one of the other rules can say something useful from shape alone: a
 * query built by concatenation is suspicious whatever flows into it. This one
 * cannot. "This code makes an HTTP request" is not a finding - it is what
 * servers do all day, and a signature pass here would report every API client,
 * every webhook, every health check in the codebase.
 *
 * The finding only exists when the URL is attacker-chosen, and that is a
 * data-flow question, not a pattern. So `check()` deliberately returns null
 * always, and every SSRF finding this tool produces is flow-verified with a
 * printed path. It is the first rule where "we cannot say anything without the
 * tracer" is the honest answer rather than a limitation to apologise for.
 */

import { type Rule, type RuleHit } from './contract.js';

export const ssrfRule: Rule = {
  id: 'ssrf',
  name: 'Server fetches a URL the user chose',
  cwe: 'CWE-918',
  owasp: 'A01:2025 Broken Access Control',
  severity: 'high',
  explanation:
    'Your server sits inside the network. It can reach the database, the admin ' +
    'panel, and the cloud metadata endpoint that hands out instance credentials - ' +
    'and the attacker\'s browser cannot. When the URL your server fetches is chosen ' +
    'by a request, the attacker stops trying to get past the firewall and simply ' +
    'asks your server to fetch the thing for them. The fix is an allowlist of hosts ' +
    'you meant to talk to, checked after resolving the URL. A blocklist loses: ' +
    'localhost is also 127.1, 0.0.0.0, [::1], 2130706433, a DNS name pointing at ' +
    'loopback, and a redirect from a public host to a private one.',
  limitations:
    'FLOW-VERIFIED ONLY: this rule has no pattern pass, because "makes an HTTP ' +
    'request" describes almost every server and would report every API client in ' +
    'the codebase. A finding here always carries a traced path from a request value ' +
    'to the fetch. DELIBERATE GAP: we cannot see a host allowlist. Code that ' +
    'correctly resolves the URL and checks the hostname against a fixed set is ' +
    'still reported, because recognising a correct allowlist means understanding ' +
    'what the check compares and what it does on failure - which is beyond what ' +
    'this engine models. Treat an SSRF finding as "confirm the host check", not as ' +
    '"this is definitely exploitable". A REDIRECT from an allowed host to an ' +
    'internal one is invisible to any static tool, allowlist or not.',
  shapes: ['call'],
  support: {
    javascript: {
      status: 'implemented',
      note: 'Data-flow only. Covers http/https get and request, fetch, axios, got, node-fetch and request. NOT covered: a URL assembled inside an options object (fetch({url: dirty})) - we read the URL argument positionally.',
    },
    typescript: {
      status: 'implemented',
      note: 'Data-flow only. Identical to JavaScript.',
    },
    python: {
      status: 'implemented',
      note: 'Data-flow only. Covers requests (get/post/put/delete/head/request), urllib.request.urlopen and httpx. NOT covered: aiohttp sessions, where the URL is passed to a method on a session object we do not model.',
    },
    java: {
      status: 'partial',
      note: 'PARTIAL, data-flow only: new URL(x) and HttpClient/RestTemplate calls. NOT covered: the very common two-step form where the URL object is built on one line and opened on another, because the tracer follows variables rather than object state.',
    },
    php: {
      status: 'implemented',
      note: 'Data-flow only. Covers file_get_contents, fopen, curl_setopt with CURLOPT_URL, and curl_init with a URL argument. Note that file_get_contents doubles as a file reader, so a finding here may be path traversal wearing a URL\'s clothes - both are worth the same second look.',
    },
    go: {
      status: 'implemented',
      note: 'Data-flow only. Covers http.Get, http.Post, http.Head, http.NewRequest and client methods of the same names.',
    },
    c: {
      status: 'not-implemented',
      note:
        'libcurl is how C makes outbound requests - curl_easy_setopt(handle, CURLOPT_URL, url) - and it is NOT modelled: the URL is one argument of a variadic setter whose meaning depends on the option constant next to it, which this engine does not read. Server-side request forgery written with libcurl is missed entirely.',
    },
    cpp: {
      status: 'not-implemented',
      note:
        'Not implemented. C++ code reaches the network through libcurl (not modelled - the URL is one argument of a variadic setter), or through a framework HTTP client such as cpp-httplib or Boost.Beast, none of which are in the sink tables.',
    },
  },
  /*
   * Deliberately silent. See the header: there is no honest pattern for this
   * bug, only a flow. The taint engine emits every finding for this rule id.
   */
  check(): RuleHit | null {
    return null;
  },
};
