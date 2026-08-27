/**
 * HARDCODED CREDENTIALS  (CWE-798, OWASP A07:2025 - Authentication
 * Authentication Failures; also A05 Security Misconfiguration)
 *
 * WHAT THE BUG IS, in plain language:
 * A password, API key or private key written directly into source code is a
 * secret that has already partly escaped. It is in your git history forever
 * (deleting the line does not remove it - `git log -p` still has it), it is on
 * every laptop that ever cloned the repo, it is in your CI logs and your
 * backups, and every contractor who read the code knows it. You also cannot
 * rotate it without a code change and a deploy.
 *
 * This is the least glamorous vulnerability class and, empirically, one of the
 * most exploited: attackers scan public repositories for key formats
 * continuously, and a leaked cloud key can become a bill or a breach in minutes.
 *
 * THE FIX:
 * Keep secrets outside the code - environment variables, a secrets manager
 * (Vault, AWS Secrets Manager, Doppler), or a config file that is gitignored.
 * The code should read a NAME, never a VALUE. And if a secret was ever
 * committed, rotate it; scrubbing history is not enough, because you cannot
 * un-copy something.
 *
 * HOW THIS RULE DECIDES - three signals, deliberately separate:
 *   1. KNOWN FORMAT     - the text matches a real vendor's key shape
 *                         (AKIA..., ghp_..., sk_live_...). Very strong.
 *   2. SUSPICIOUS NAME  - the variable is called `password`, `apiKey`,
 *                         `secret`... and holds a literal string. Strong.
 *   3. HIGH ENTROPY     - a long, random-looking literal with no meaningful
 *                         name. Weak - this is the one that produces false
 *                         positives, so it gets lower severity and the finding
 *                         says explicitly that it is an entropy guess.
 * Reporting all three at the same confidence would be exactly the dishonesty
 * this project rejects, so they carry different severities and different
 * reasoning text.
 */

import type { Node } from 'web-tree-sitter';
import type { LanguageId } from '../parse/languages.js';
import { asAssignment, asCall, type Rule, type RuleHit } from './contract.js';
import {
  isLikelyPlaceholder,
  isStringLiteral,
  isTestPath,
  looksLikeToken,
  matchKnownSecret,
  shannonEntropy,
  unquote,
} from './lib/strings.js';

/** Variable/field names that suggest the value is a credential. */
const SECRET_NAME = new RegExp(
  [
    'pass(word|wd|phrase)?',
    'secret',
    'token',
    'api[_-]?key',
    'apikey',
    'access[_-]?key',
    'secret[_-]?key',
    'private[_-]?key',
    'client[_-]?secret',
    'encryption[_-]?key',
    'signing[_-]?key',
    // The lookahead matters: without it, "auth" matches inside "author",
    // "authorize" and Gin's "AuthUserKey". Found by scanning real repositories.
    'auth[_-]?(token|key|header|secret)?(?![A-Za-z])',
    'credential',
    'bearer',
    'jwt[_-]?secret',
    'session[_-]?secret',
    'connection[_-]?string',
    'conn[_-]?str',
    'dsn',
  ].join('|'),
  'i',
);

/**
 * Names that MATCH the pattern above but are not secrets: they hold the name of
 * a secret, its location, or a boolean about it. Checked first.
 */
const NOT_A_SECRET =
  /(_?(name|field|label|header|type|env|var|path|file|url|uri|prompt|placeholder|hash|algo|algorithm|regex|pattern|length|expiry|ttl|enabled|required)$)|^(has|is|use|should|allow|require)/i;

/** Entropy threshold above which a long literal starts looking machine-generated. */
const ENTROPY_THRESHOLD = 4.0;
const MIN_ENTROPY_LENGTH = 24;

interface LiteralValue {
  readonly node: Node;
  readonly text: string;
}

function literalOf(node: Node, language: LanguageId): LiteralValue | null {
  if (!isStringLiteral(node, language)) return null;
  const text = unquote((node.text ?? '').trim());
  return { node, text };
}

export const hardcodedSecretRule: Rule = {
  id: 'hardcoded-secret',
  name: 'Credential written directly into source code',
  cwe: 'CWE-798',
  owasp: 'A07:2025 Authentication Failures',
  severity: 'high',
  explanation:
    'A password or API key written into source code lives in git history forever, on ' +
    'every machine that cloned the repo, and in every CI log. It cannot be rotated ' +
    'without a deploy, and public repositories are scanned for key formats ' +
    'continuously. Secrets belong in environment variables or a secrets manager; the ' +
    'code should reference a name, never a value.',
  limitations:
    'UNVERIFIED (signature-based): we matched a name pattern, a known vendor key format, ' +
    'or a randomness score. We cannot tell a real production key from a test fixture, ' +
    'a rotated-and-dead key, or a deliberately fake example. Entropy-only hits in ' +
    'particular are a guess about how random text looks, nothing more. ' +
    'DELIBERATE GAP: values matching a vendor format but ending in EXAMPLE, or with ' +
    'the random portion filled by 0000/1234567890, are treated as published ' +
    'documentation placeholders (AWS prints AKIAIOSFODNN7EXAMPLE in its own docs) and ' +
    'are NOT reported. A real key that happens to end in EXAMPLE would be missed.',
  shapes: ['assignment', 'call'],
  support: {
    javascript: {
      status: 'implemented',
      note: 'Covers variable declarations, assignments and object-literal entries ({ apiKey: "..." }).',
    },
    typescript: {
      status: 'implemented',
      note: 'Additionally covers class property definitions (`private token = "..."`).',
    },
    python: {
      status: 'implemented',
      note: 'Covers assignments, dict literals and keyword arguments (connect(password="...")).',
    },
    java: {
      status: 'implemented',
      note: 'Covers field and local variable initialisers, including `static final String`. Values read from .properties files are not analysed - this tool parses code, not config.',
    },
    go: {
      status: 'implemented',
      note: 'Covers :=, var, const and struct literal fields (Config{ApiKey: "..."}).',
    },
    php: {
      status: 'implemented',
      note: 'Covers $var = "..." and class property declarations. NOT covered: define(\'API_KEY\', \'...\') and const declarations, which are a different shape - a documented gap, not a silent one.',
    },
  },
  check(shape, ctx): RuleHit | null {
    const language = ctx.language;

    /**
     * Test and example files get a severity downgrade, not a free pass.
     * Measured on five real repositories, 167 of 179 raw findings were in test
     * trees. Dropping them silently would be dishonest (a committed key is
     * committed wherever it lives) and reporting them as HIGH buries the real
     * ones. So: keep the finding, lower the severity, say why in the reasoning.
     */
    const inTests = isTestPath(ctx.file.path);
    const testNote = inTests
      ? ' NOTE: this file looks like a test, fixture or example, so the value is probably ' +
        'a stand-in rather than a live credential - severity lowered for that reason. It is ' +
        'still committed to git history, and fixtures do get copy-pasted into production.'
      : '';
    const downgrade = (severity: 'critical' | 'high' | 'medium'): 'critical' | 'high' | 'medium' | 'low' =>
      inTests ? (severity === 'critical' ? 'medium' : 'low') : severity;

    /* ---- Any string literal argument that matches a known vendor format ----
     * e.g. client.init("AKIAIOSFODNN7EXAMPLE"). No variable name to go on, but
     * the shape of the value alone is conclusive enough to report.          */
    const call = asCall(shape);
    if (call) {
      for (const arg of call.args) {
        const literal = literalOf(arg, language);
        if (!literal) continue;
        const known = matchKnownSecret(literal.text);
        if (!known) continue;
        return {
          node: arg,
          severity: downgrade('critical'),
          message: `${known.label} passed literally to ${call.calleeText}()`,
          reasoning:
            `The string passed to \`${call.calleeText}()\` matches the published format of ` +
            `a ${known.label}. Vendor key formats are distinctive enough that automated ` +
            `scrapers search public code for exactly this pattern. Treat this key as ` +
            `already compromised and rotate it, then move it to an environment variable.` +
            testNote,
        };
      }
      return null;
    }

    const assignment = asAssignment(shape);
    if (!assignment) return null;

    const literal = literalOf(assignment.value, language);
    if (!literal) return null; // `password = getSecret()` is the correct pattern.

    const value = literal.text;
    const name = assignment.targetName;

    /* ---- Signal 1: a known vendor key format. Strongest. ---- */
    const known = matchKnownSecret(value);
    if (known) {
      return {
        node: assignment.node,
        severity: downgrade('critical'),
        message: `${known.label} hardcoded in \`${name}\``,
        reasoning:
          `The literal assigned to \`${name}\` matches the published format of a ` +
          `${known.label}. This is not a name-based guess - the value itself is ` +
          `structurally identifiable as a credential. Rotate it (assume it is already ` +
          `public if this repo has ever been shared) and load it from the environment.` +
          testNote,
      };
    }

    if (isLikelyPlaceholder(value)) return null;

    /* ---- Signal 2: the variable name says "credential". ---- */
    if (SECRET_NAME.test(name) && !NOT_A_SECRET.test(name)) {
      if (value.length < 4) return null; // "", "x" - not a real secret
      return {
        node: assignment.node,
        severity: downgrade('high'),
        message: `Credential-looking value hardcoded in \`${name}\``,
        reasoning:
          `\`${name}\` matches the naming pattern for a credential and is assigned a ` +
          `fixed string literal (${value.length} characters) rather than being read from ` +
          `the environment or a secrets manager. Anything committed here is in git ` +
          `history permanently, even if the line is deleted later.` + testNote,
      };
    }

    /* ---- Signal 3: entropy only. Weakest - and labelled as such. ---- */
    // The structural gate comes FIRST: entropy alone cannot tell a key from a
    // MIME type. See looksLikeToken() for the measurements that motivated this.
    if (value.length >= MIN_ENTROPY_LENGTH && looksLikeToken(value)) {
      const entropy = shannonEntropy(value);
      if (entropy >= ENTROPY_THRESHOLD) {
        return {
          node: assignment.node,
          severity: downgrade('medium'),
          message: `High-entropy literal assigned to \`${name}\` (possible secret)`,
          reasoning:
            `The value assigned to \`${name}\` is ${value.length} characters long with a ` +
            `Shannon entropy of ${entropy.toFixed(2)} bits/character. Ordinary English text ` +
            `scores around 2.5-3.5; generated keys and tokens usually score above 4. ` +
            `THIS IS A RANDOMNESS HEURISTIC, NOT AN IDENTIFICATION - a hash, a UUID, a ` +
            `base64 test fixture or a minified blob will score the same. Severity is ` +
            `deliberately lower than a name or format match for that reason.` + testNote,
          limitations:
            'UNVERIFIED (signature-based, entropy heuristic): this finding rests ONLY on how ' +
            'random the text looks. There is no name evidence and no format evidence. ' +
            'Expect false positives and treat it as "worth a glance", not "a secret".',
        };
      }
    }

    return null;
  },
};
