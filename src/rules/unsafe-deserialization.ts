/**
 * UNSAFE DESERIALIZATION  (CWE-502, OWASP A08:2025 - Software or Data Integrity Failures)
 *
 * WHAT THE BUG IS, in plain language:
 * Serialising turns an object in memory into bytes you can store or send.
 * Deserialising turns those bytes back into an object. The danger is in the
 * word OBJECT: the bytes do not just carry data, they carry the NAME OF THE
 * CLASS to rebuild, and rebuilding a class runs that class's code.
 *
 *     $session = unserialize($_COOKIE['session']);
 *
 * The attacker controls the cookie, so the attacker chooses which classes get
 * constructed and with which fields. They then look through your code (and
 * your libraries) for a class with a `__destruct`, `__wakeup` or `readObject`
 * method that does something useful - deletes a file, writes a file, runs a
 * command - and hand you an object designed to trigger it. Chaining a few of
 * these together is called a POP CHAIN or a gadget chain, and the usual end
 * result is remote code execution. No memory corruption, no exploit skill: the
 * language does exactly what it was told.
 *
 * WHY THIS RULE IS DIFFERENT FROM THE OTHER INJECTION RULES:
 * There is no "escaping" fix. You cannot sanitise attacker bytes into safe
 * bytes, because the danger is the structure, not the characters. The real
 * fixes are:
 *
 *   - Use a DATA format instead of an OBJECT format. `json_decode`,
 *     `JSON.parse` and `json.loads` produce plain values and cannot construct
 *     your classes. This is the right answer almost every time.
 *   - If you must deserialise objects, restrict which classes are allowed
 *     (`unserialize($x, ['allowed_classes' => false])`, `yaml.safe_load`,
 *     a `MessageFormat` allowlist) - and this rule recognises those and stays
 *     quiet, because reporting the hardened form would punish the fix.
 *   - Sign the payload so you can tell it is yours before you open it.
 *
 * WHY IT TOOK A NEW SINK KIND:
 * The engine's three existing kinds - sql, command, xss - all describe a
 * string being read as instructions. This one is bytes being read as an
 * object graph, so a SQL escaper or an HTML escaper means nothing here. Sink
 * kinds are scoped for exactly this reason: `htmlspecialchars` on the way to
 * `unserialize` clears nothing, and the engine has to know that.
 */

import type { LanguageId } from '../parse/languages.js';
import { asCall, type Rule, type RuleHit } from './contract.js';

/**
 * Functions that turn bytes into OBJECTS.
 *
 * Deliberately excludes every JSON parser. `json_decode`, `JSON.parse` and
 * `json.loads` return plain arrays, strings and numbers - they cannot name a
 * class, so they cannot start a gadget chain. Listing them would bury the real
 * findings under the single most common safe call in every codebase.
 */
const DESERIALIZERS: Record<LanguageId, readonly string[]> = {
  // node-serialize and funcster revive functions from their payloads. The
  // built-in JSON parser does not and is deliberately absent.
  javascript: ['unserialize', 'deserialize'],
  typescript: ['unserialize', 'deserialize'],
  // pickle and marshal execute constructor code by design; yaml.load does too
  // unless a safe Loader is named, which `unlessOption` checks for.
  python: ['loads', 'load', 'Unpickler'],
  // readObject is the classic Java gadget-chain entry point.
  java: ['readObject', 'readUnshared', 'readResolve'],
  php: ['unserialize'],
  // Go's encoding/gob decodes into a type YOU name, so an attacker cannot
  // choose the class to construct. That removes the gadget-chain shape this
  // rule is about, which is why the list is empty rather than guessed at.
  go: [],
  // C has no object graph to revive, so the gadget-chain bug this rule is
  // about cannot exist at all. Parsing untrusted binary in C IS dangerous, but
  // for a completely different reason - it is where the memory-safety bugs
  // live - and that is declared out of scope rather than half-covered here.
  c: [],
  cpp: [],
};

/**
 * Receivers that make an otherwise-ambiguous method name unambiguous.
 *
 * `load` and `loads` are far too common to report on the name alone - every
 * config reader in Python has one. Requiring a known-dangerous module in front
 * of them is what separates `pickle.loads(data)` from `settings.loads(data)`.
 */
const REQUIRED_RECEIVERS: Record<LanguageId, readonly string[]> = {
  javascript: ['serialize', 'node-serialize', 'funcster'],
  typescript: ['serialize', 'node-serialize', 'funcster'],
  python: ['pickle', 'cPickle', 'dill', 'marshal', 'yaml', 'shelve', 'jsonpickle'],
  java: ['ois', 'objectInputStream', 'in', 'input', 'stream', 'decoder'],
  php: [],
  go: [],
  c: [],
  cpp: [],
};

/**
 * Deserialisers whose payload arrives through the RECEIVER, not an argument.
 * `ois.readObject()` reads from a stream that was loaded a line earlier, so
 * there is no argument to inspect and the receiver check is the whole test.
 */
const ZERO_ARGUMENT_READERS: ReadonlySet<string> = new Set([
  'readObject',
  'readUnshared',
  'readResolve',
]);

/** Calls that are safe BECAUSE of an argument, and must not be reported. */
const SAFE_FORMS: Record<LanguageId, RegExp | null> = {
  javascript: null,
  typescript: null,
  // yaml.load(x, Loader=SafeLoader) and yaml.safe_load are the hardened forms.
  python: /\b(SafeLoader|CSafeLoader|BaseLoader|safe_load)\b/,
  java: null,
  // unserialize($x, ['allowed_classes' => false]) cannot construct your classes.
  php: /allowed_classes/,
  // Nothing to make safe, because nothing above is listed as dangerous.
  c: null,
  cpp: null,
  go: null,
};

/**
 * Does the receiver in front of this call identify a dangerous deserialiser?
 * A language with no required receivers answers yes for everything, because
 * its function names (`unserialize`, `readObject`) are already unambiguous.
 */
function receiverQualifies(language: LanguageId, receiverText: string): boolean {
  const required = REQUIRED_RECEIVERS[language];
  if (required.length === 0) return true;
  const last = receiverText.split(/[.\s(]/).filter(Boolean).pop() ?? receiverText;
  return required.some((name) => last === name || receiverText.includes(name));
}

export const unsafeDeserializationRule: Rule = {
  id: 'unsafe-deserialization',
  name: 'Untrusted bytes rebuilt into an object',
  cwe: 'CWE-502',
  owasp: 'A08:2025 Software or Data Integrity Failures',
  severity: 'critical',
  explanation:
    'Deserialising does not just read data - it names a class and rebuilds it, ' +
    'which runs that class\'s code. Whoever controls the bytes therefore chooses ' +
    'which objects your program constructs, and can chain together classes whose ' +
    'destructors or wake-up methods do something useful to them. The usual end of ' +
    'that chain is remote code execution. There is no escaping fix, because the ' +
    'danger is the structure rather than the characters: use a data format such as ' +
    'JSON, restrict which classes may be constructed, or sign the payload.',
  limitations:
    'UNVERIFIED (signature-based): we identified a call that rebuilds objects from ' +
    'bytes and confirmed its argument is not a fixed literal. We did NOT confirm the ' +
    'bytes are attacker-controlled - the data-flow pass is what upgrades this to ' +
    'flow-verified, and it is worth waiting for, because deserialising your own ' +
    'trusted data is ordinary and safe. Hardened forms are recognised and NOT ' +
    'reported: unserialize with allowed_classes, and yaml with a Safe/Base Loader. ' +
    'DELIBERATE GAP: that check reads the visible text of the call, so a Loader or ' +
    'an options array assembled in another variable is missed and the finding still ' +
    'fires. JSON parsers are deliberately excluded entirely - json_decode, JSON.parse ' +
    'and json.loads return plain values and cannot name a class to construct. ' +
    'Go is NOT covered: encoding/gob decodes into a type the PROGRAM names, so an ' +
    'attacker cannot choose the class, and the gadget-chain shape does not arise.',
  shapes: ['call'],
  support: {
    javascript: {
      status: 'partial',
      note: 'PARTIAL: node-serialize and funcster only, and only when called on a recognisable receiver. JSON.parse is deliberately excluded - it cannot construct a class. Most JavaScript deserialization risk lives in libraries with their own APIs that this does not model.',
    },
    typescript: {
      status: 'partial',
      note: 'PARTIAL: identical to JavaScript.',
    },
    python: {
      status: 'implemented',
      note: 'Covers pickle/cPickle/dill/marshal loads and load, yaml.load, shelve and jsonpickle, matched by module receiver so an ordinary settings.load() is not reported. yaml.load with a Safe/Base Loader is recognised as the hardened form and stays quiet.',
    },
    java: {
      status: 'partial',
      note: 'PARTIAL: ObjectInputStream.readObject/readUnshared, matched on a stream-looking receiver name. A stream stored under an unusual variable name is missed. XMLDecoder and SnakeYAML are NOT covered.',
    },
    php: {
      status: 'implemented',
      note: 'Covers unserialize(), the language\'s classic POP-chain entry point. unserialize($x, [\'allowed_classes\' => false]) is recognised as the hardened form and is not reported. json_decode is deliberately excluded.',
    },
    go: {
      status: 'not-implemented',
      note: 'NOT IMPLEMENTED: encoding/gob and encoding/json both decode into a type the program names, so an attacker cannot choose which class gets constructed. The gadget-chain shape this rule detects does not exist in Go, and a rule that fired here would be noise rather than coverage.',
    },
    c: {
      status: 'not-implemented',
      note:
        'C has no object graph to revive, so the gadget-chain weakness this rule detects cannot exist. Parsing untrusted binary in C IS dangerous, but for memory-safety reasons that are declared out of scope rather than half-covered here.',
    },
    cpp: {
      status: 'not-implemented',
      note:
        'Not implemented. C++ serialisation libraries - Boost.Serialization, cereal, protobuf - do reconstruct typed object graphs, and none of them is modelled here, so a gadget chain through Boost.Serialization is missed.',
    },
  },
  check(shape, ctx): RuleHit | null {
    const language = ctx.language;
    const call = asCall(shape);
    if (!call) return null;

    const names = DESERIALIZERS[language];
    if (!names.includes(call.calleeName)) return null;
    if (!receiverQualifies(language, call.receiverText)) return null;

    // The hardened form is the same call plus a restriction. Seeing the
    // restriction means this is the fix, and reporting a fix teaches people
    // that fixing does not help.
    const safeForm = SAFE_FORMS[language];
    if (safeForm && safeForm.test(call.node.text ?? '')) return null;

    /*
     * SOME DESERIALISERS TAKE NO ARGUMENTS.
     *
     *     Map<String,String> grant = (Map<String,String>) ois.readObject();
     *
     * The bytes were handed to the STREAM, one line earlier; `readObject()`
     * just pulls the next object out of it. This rule required `args[0]` and
     * therefore stayed silent on the single most famous gadget-chain entry
     * point in Java - the exact call every CVE writeup about deserialization
     * is about.
     *
     * Found by a Gemini-written test file. The taint engine already had this
     * idea (`pb.command(list); pb.start()` - a sink whose payload was loaded
     * earlier); the signature rule did not.
     */
    const argument = call.args[0];
    if (!argument) {
      if (!ZERO_ARGUMENT_READERS.has(call.calleeName)) return null;
      return {
        node: call.node,
        message: `Untrusted bytes deserialised by ${call.calleeName}()`,
        reasoning:
          `\`${call.calleeName}()\` takes no arguments because the bytes were handed to ` +
          `\`${call.receiverText || 'the stream'}\` earlier - it pulls the next object out of ` +
          `that stream, and the bytes get to name the class it constructs. If the stream was ` +
          `built from anything a caller controls, this is the classic Java gadget-chain entry ` +
          `point. Validate and sign the payload before it reaches a stream, or use a data ` +
          `format that cannot name a class.`,
      };
    }

    /*
     * A ROUND TRIP IS NOT AN INPUT.
     *
     *     pickle.loads(pickle.dumps(base))
     *     json.loads(json.dumps(obj))
     *
     * Six of the sixteen deserialisation findings on a pandas scan were this,
     * all in tests. Deserialising is dangerous because the BYTES come from
     * somewhere else - a file, a socket, a cookie. Here they are produced two
     * characters to the right, by this process, from a value this process
     * already holds. There is no attacker position anywhere in the expression,
     * and no amount of tracing will find one.
     *
     * The serialiser has to be visible as the DIRECT argument. `data = dumps(x)`
     * on an earlier line then `loads(data)` still reports, because proving that
     * one is the same round trip is a data-flow question, and this rule is not
     * allowed to guess at data flow - that is what flow-verified means.
     */
    const argumentText = argument.text ?? '';
    if (/^\s*(?:[\w.]+\.)?(?:dumps?|serialize|pack|marshal|encode)\s*\(/.test(argumentText)) {
      return null;
    }

    // A fixed literal is your own data, not an attacker's. `unserialize('a:0:{}')`
    // is a constant and cannot be chosen by anyone.
    if (argument.type === 'string' || argument.type === 'encapsed_string') {
      const interpolates = argument.namedChildren.some(
        (c) => c !== null && c.type !== 'string_content' && c.type !== 'escape_sequence',
      );
      if (!interpolates) return null;
    }

    return {
      node: call.node,
      message: `Untrusted bytes deserialised by ${call.calleeName}()`,
      reasoning:
        `\`${call.calleeName}()\` rebuilds an object graph from bytes, which means the ` +
        `bytes get to name the classes your program constructs. If any class reachable ` +
        `from here has a destructor or wake-up method that touches the filesystem or ` +
        `runs a command, an attacker who controls this input can chain them into code ` +
        `execution. Escaping does not help - the danger is the structure, not the ` +
        `characters. Parse it as data (JSON) instead, or restrict which classes may be ` +
        `constructed.`,
    };
  },
};
