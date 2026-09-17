/**
 * WEAK / BROKEN CRYPTOGRAPHIC HASH  (CWE-327, CWE-328,
 * OWASP A04:2025 - Cryptographic Failures)
 *
 * WHAT A HASH IS, in plain language:
 * A hash function turns any input into a fixed-length fingerprint. Two
 * properties are supposed to hold: you cannot work backwards from the
 * fingerprint to the input, and you cannot find two different inputs with the
 * same fingerprint (a "collision").
 *
 * MD5 and SHA-1 no longer have the second property. Collisions in MD5 are
 * trivial today - seconds on a laptop. SHA-1 collisions were demonstrated in
 * 2017 and have only got cheaper. Anything that relies on "this fingerprint
 * uniquely identifies this content" - signatures, integrity checks, tokens -
 * is broken when built on them.
 *
 * PASSWORDS ARE A SEPARATE PROBLEM, and a worse one:
 * MD5 and SHA-1 are FAST, and for password storage fast is the flaw. A modern
 * GPU tries billions of MD5 guesses per second, so a stolen table of MD5
 * password hashes is effectively a table of passwords. Password hashing needs a
 * function designed to be SLOW and memory-hungry - bcrypt, scrypt, or Argon2 -
 * with a unique random salt per password.
 *
 * WHAT TO USE INSTEAD:
 *   integrity / fingerprints -> SHA-256 or SHA-3
 *   passwords                -> Argon2id, scrypt, or bcrypt
 *   message authentication   -> HMAC-SHA256
 *
 * HONESTY NOTE, and it is a real one:
 * MD5 is still perfectly reasonable for NON-security work - cache keys, ETags,
 * sharding, deduplication, "has this file changed". A scanner cannot tell why
 * you called it. So this rule is severity MEDIUM, not high, and every finding
 * says out loud that purpose is unknown. Flagging a cache key as a critical
 * vulnerability is how security tools train people to ignore them.
 */

import type { LanguageId } from '../parse/languages.js';
import { asCall, type Rule, type RuleHit } from './contract.js';
import { unquote } from './lib/strings.js';

/** Constructors whose NAME alone identifies the algorithm. */
const DIRECT_WEAK_CALLS: Record<LanguageId, readonly string[]> = {
  javascript: [],
  typescript: [],
  python: ['md5', 'sha1'], // hashlib.md5(...)
  java: ['md5Hex', 'sha1Hex', 'md5', 'sha1'], // Apache DigestUtils
  go: ['New', 'Sum', 'New224'], // md5.New(), sha1.Sum() - receiver tells us which
  php: ['md5', 'sha1', 'md5_file', 'sha1_file', 'crc32'],
  /*
   * OpenSSL's one-shot and streaming APIs, which is how virtually all C code
   * hashes anything. MD5(), SHA1() and their _Init/_Update/_Final triples name
   * the algorithm in the symbol, so the name alone is the whole signal - no
   * receiver scoping needed, unlike Go's `md5.New()`.
   */
  c: ['MD5', 'SHA1', 'MD5_Init', 'SHA1_Init', 'MD4', 'MD4_Init', 'CC_MD5', 'CC_SHA1'],
  cpp: ['MD5', 'SHA1', 'MD5_Init', 'SHA1_Init', 'MD4', 'MD4_Init', 'CC_MD5', 'CC_SHA1'],
};

/** Calls that take the algorithm as a STRING argument. */
const ALGORITHM_ARG_CALLS: Record<LanguageId, readonly string[]> = {
  javascript: ['createHash', 'createHmac'],
  typescript: ['createHash', 'createHmac'],
  python: ['new'], // hashlib.new("md5")
  java: ['getInstance'], // MessageDigest.getInstance("MD5")
  go: [],
  php: ['hash', 'hash_file', 'hash_init'], // hash("md5", $x)
  // EVP_get_digestbyname("md5") is the string-argument form in OpenSSL.
  c: ['EVP_get_digestbyname', 'EVP_MD_fetch'],
  cpp: ['EVP_get_digestbyname', 'EVP_MD_fetch'],
};

const WEAK_ALGORITHMS = /^(md[245]|sha-?1|md5-sess|ripemd128?)$/i;

/** Receivers that identify a weak package, e.g. Go's `md5.New()`. */
const WEAK_RECEIVERS = /^(md5|sha1)$/i;

const PASSWORDISH = /pass(word|wd)?|pwd|credential|login|auth/i;

export const weakHashRule: Rule = {
  id: 'weak-hash',
  name: 'Broken or unsuitable hash algorithm',
  cwe: 'CWE-327',
  owasp: 'A04:2025 Cryptographic Failures',
  severity: 'medium',
  explanation:
    'MD5 and SHA-1 are broken for security use: finding two inputs with the same ' +
    'fingerprint is cheap today, so they cannot be trusted for signatures or integrity. ' +
    'They are also far too fast for password storage, where a GPU can try billions of ' +
    'guesses per second. Use SHA-256 for integrity, HMAC-SHA256 for authentication, ' +
    'and Argon2id/scrypt/bcrypt for passwords.',
  limitations:
    'UNVERIFIED (signature-based): we identified the algorithm from the call, not the ' +
    'purpose. MD5 used for a cache key, an ETag or deduplication is FINE and this ' +
    'finding is then a false positive. We cannot see what the digest is USED for. The ' +
    'taint engine follows attacker input forwards into sinks; answering "what happens to ' +
    'this hash afterwards" is the opposite direction and is not implemented.',
  shapes: ['call'],
  support: {
    javascript: {
      status: 'implemented',
      note: "Node crypto.createHash('md5'|'sha1') and createHmac. Third-party libraries with their own APIs (crypto-js, blueimp-md5) are not covered.",
    },
    typescript: { status: 'implemented', note: 'Identical to JavaScript.' },
    python: {
      status: 'implemented',
      note: 'hashlib.md5/sha1 and hashlib.new("md5"). The `usedforsecurity=False` keyword (Python 3.9+) is NOT yet honoured - a documented false-positive source we intend to fix.',
    },
    java: {
      status: 'implemented',
      note: 'MessageDigest.getInstance("MD5"/"SHA-1") and Apache Commons DigestUtils.md5Hex/sha1Hex. Algorithm names built from a variable are not resolved.',
    },
    go: {
      status: 'partial',
      note: 'PARTIAL: matched by receiver package name (md5.New, sha1.Sum). If the package is imported under an alias (`import h "crypto/md5"`) we will miss it, because we match on the receiver text rather than on resolved imports.',
    },
    php: {
      status: 'implemented',
      note: 'Covers md5(), sha1(), their _file variants, crc32(), and hash("md5", ...). PHP names the algorithm in the function itself far more often than the others do, which makes this the most reliable weak-hash coverage in the tool.',
    },
    c: {
      status: 'implemented',
      note:
        'OpenSSL\'s one-shot and streaming APIs, which is how nearly all C code hashes: MD5, SHA1, MD4 and their _Init variants, plus Apple\'s CC_MD5/CC_SHA1 and the string-argument form EVP_get_digestbyname("md5"). The algorithm is named in the symbol itself, so no receiver scoping is needed - which makes this more reliable in C than the Go coverage, where the package name is the only clue.',
    },
    cpp: {
      status: 'implemented',
      note:
        'Every C entry applies unchanged, since C++ inherits the whole libc surface and real code still uses it. Namespace-qualified calls (std::system) and method calls on objects are recognised in addition.',
    },
  },
  check(shape, ctx): RuleHit | null {
    const call = asCall(shape);
    if (!call) return null;
    const language = ctx.language;

    const report = (algorithm: string, evidence: string): RuleHit => {
      const wholeCall = call.node.text ?? '';
      const looksLikePasswordUse = PASSWORDISH.test(wholeCall);
      return {
        node: call.node,
        severity: looksLikePasswordUse ? 'high' : 'medium',
        message: `${algorithm.toUpperCase()} used via ${call.calleeText}()`,
        reasoning:
          `${evidence} ${algorithm.toUpperCase()} is a broken hash for security purposes: ` +
          `producing two different inputs with the same digest is cheap on ordinary ` +
          `hardware, and the function is fast enough that guessing inputs is cheap too. ` +
          (looksLikePasswordUse
            ? `The surrounding code mentions a password or credential, which makes this a ` +
              `likely password-hashing use - the worst case. Use Argon2id, scrypt or bcrypt.`
            : `We cannot tell what this digest is for. If it is a cache key or a checksum ` +
              `this is harmless; if it protects anything, move to SHA-256 or HMAC-SHA256.`),
      };
    };

    /* ---- Algorithm named in a string argument: createHash("md5") ---- */
    if (ALGORITHM_ARG_CALLS[language].includes(call.calleeName)) {
      for (const arg of call.args) {
        const text = unquote((arg.text ?? '').trim());
        if (WEAK_ALGORITHMS.test(text)) {
          return report(
            text,
            `\`${call.calleeText}("${text}")\` selects the algorithm by name.`,
          );
        }
      }
      return null;
    }

    /* ---- Algorithm implied by the function or package name ---- */
    if (DIRECT_WEAK_CALLS[language].includes(call.calleeName)) {
      // Go: md5.New() - the receiver is the package. Python: hashlib.md5().
      if (WEAK_RECEIVERS.test(call.receiverText)) {
        return report(
          call.receiverText,
          `\`${call.calleeText}()\` comes from the ${call.receiverText} package.`,
        );
      }
      if (WEAK_ALGORITHMS.test(call.calleeName)) {
        return report(call.calleeName, `\`${call.calleeText}()\` names the algorithm directly.`);
      }
      // DigestUtils.md5Hex / sha1Hex
      const stripped = call.calleeName.replace(/(Hex|Base64|Digest)$/i, '');
      if (WEAK_ALGORITHMS.test(stripped)) {
        return report(stripped, `\`${call.calleeText}()\` names the algorithm directly.`);
      }
    }

    return null;
  },
};
