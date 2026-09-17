/**
 * OS COMMAND INJECTION  (CWE-78, OWASP A05:2025 - Injection)
 *
 * WHAT THE BUG IS, in plain language:
 * Some functions hand a string to the operating system's SHELL - the same
 * program that runs your terminal. The shell has its own punctuation with
 * special meaning: `;` ends a command and starts another, `|` pipes output,
 * `&&` chains, and backticks or `$( )` run a command and paste its output.
 *
 *     exec("ping -c 1 " + host)
 *
 * If `host` is `example.com; rm -rf /`, the shell sees TWO commands and runs
 * both. Same disease as SQL injection: data got mixed into instructions.
 *
 * THE FIX:
 * Don't use a shell. Every language has a way to launch a program with its
 * arguments as a LIST rather than a sentence - `execFile`/`spawn` without
 * `shell: true` in Node, `subprocess.run([...])` without `shell=True` in
 * Python, `exec.Command("ping", "-c", "1", host)` in Go. When arguments are a
 * list, `;` is just a character in a string. Nothing parses it.
 *
 * WHY THIS RULE IS FUSSIER THAN THE SQL ONE:
 * `spawn("ls", [dir])` is safe, `spawn("ls " + dir, {shell:true})` is not, and
 * they are the same function. Where the safety depends on an options object we
 * check for it textually and say so; where we cannot tell, we stay quiet rather
 * than guess. A scanner that cries wolf on every subprocess call gets muted,
 * and a muted scanner finds nothing.
 */

import type { Node } from 'web-tree-sitter';
import type { LanguageId } from '../parse/languages.js';
import { asCall, type Rule, type RuleHit } from './contract.js';
import { analyzeStringExpression } from './lib/strings.js';
import { partsAreGuarded } from './lib/guards.js';

/** Calls that ALWAYS go through a shell. Dynamic argument = report it. */
const SHELL_SINKS: Record<LanguageId, readonly string[]> = {
  javascript: ['exec', 'execSync'],
  typescript: ['exec', 'execSync'],
  python: ['system', 'popen', 'getoutput', 'getstatusoutput'],
  java: ['exec'], // Runtime.getRuntime().exec(String) splits naively - still injectable
  go: [],
  // Every one of these hands the string to /bin/sh. `exec` is PHP's own
  // function, unrelated to the JS/Java `exec` above - it shares the name only.
  php: ['system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open', 'pcntl_exec'],
  /*
   * C's shell calls, and the cleanest sink list in this table.
   *
   * There is no ambiguity to scope away here. `system()` runs /bin/sh, always,
   * and has done since the 1970s; it has no safe overload, no options object,
   * and no parameterised form to be confused with - which is exactly the thing
   * that makes the SQL and deserialisation lists so fiddly elsewhere.
   *
   * The `execlp`/`execvp` variants search PATH, and `execl`/`execv` do not,
   * but neither family uses a shell: they take an argument VECTOR, so a
   * semicolon in an argument is a semicolon, not a command separator. They are
   * the CORRECT fix for a system() call and are deliberately absent from this
   * list - see safe/c-format-constant.c, which asserts execv stays quiet.
   *
   * The one exception is execl with an explicit shell: `execlp("sh", "sh",
   * "-c", tainted, ...)`. That IS a shell, so `execlp` and `execvp` appear in
   * CONDITIONAL_SINKS below, gated on a shell program being visible.
   */
  c: ['system', 'popen'],
  cpp: ['system', 'popen'],
};

/**
 * Calls that MAY go through a shell depending on an option.
 * We only report these when the shell-enabling option is visible in the call.
 */
const CONDITIONAL_SINKS: Record<LanguageId, readonly string[]> = {
  javascript: ['spawn', 'spawnSync', 'execFile', 'execFileSync'],
  typescript: ['spawn', 'spawnSync', 'execFile', 'execFileSync'],
  python: ['run', 'call', 'check_call', 'check_output', 'Popen'],
  java: ['ProcessBuilder', 'start'],
  go: ['Command', 'CommandContext'],
  // PHP has no safe-by-default process API to make conditional, so this list is
  // empty and every shell call above is reported unconditionally.
  php: [],
  // exec* takes an argument vector and is SAFE - unless the program it runs is
  // itself a shell, which turns the next argument back into a command.
  c: ['execl', 'execlp', 'execv', 'execvp', 'execle', 'execve'],
  cpp: ['execl', 'execlp', 'execv', 'execvp', 'execle', 'execve'],
};

const SHELL_OPTION: Record<LanguageId, RegExp> = {
  javascript: /shell\s*:\s*true/,
  typescript: /shell\s*:\s*true/,
  python: /shell\s*=\s*True/,
  java: /\b(sh|bash|cmd\.exe|powershell)\b/,
  // Unused: PHP's CONDITIONAL_SINKS list is empty, so nothing consults this.
  // It exists because the type demands an entry for every language, and an
  // entry that never matches is more honest than one that pretends to.
  php: /(?!)/,
  // Only a shell PROGRAM makes exec.Command dangerous. `exec.Command("ping",
  // "-c", "1", host)` is genuinely safe, so matching on "-c" alone would be a
  // false positive on correct code.
  go: /["'`](sh|bash|zsh|cmd\.exe|powershell)["'`]/,
  // Same reasoning as Go: only a shell PROGRAM makes an exec* call injectable.
  // `execv("/bin/ping", args)` with a tainted arg is genuinely safe and must
  // stay quiet, so the program name is what this matches - not the "-c".
  c: /["'](\/bin\/)?(sh|bash|zsh|ksh|dash)["']/,
  cpp: /["'](\/bin\/)?(sh|bash|zsh|ksh|dash)["']/,
};

function nodeText(node: Node): string {
  return (node.text ?? '').replace(/\s+/g, ' ').trim();
}

export const commandInjectionRule: Rule = {
  id: 'command-injection',
  name: 'Shell command built from a dynamic string',
  cwe: 'CWE-78',
  owasp: 'A05:2025 Injection',
  severity: 'critical',
  explanation:
    'A shell reads punctuation like ; | && ` and $() as instructions. If a command ' +
    'string is glued together from pieces, anything spliced in can end your command ' +
    'and start a new one of the attacker\'s choosing, running as your process. ' +
    'The fix is to launch the program with its arguments as a list instead of a ' +
    'sentence, so no shell ever parses the input.',
  limitations:
    'UNVERIFIED (signature-based): we confirmed a shell-executing call receives a ' +
    'dynamically built string. We did NOT confirm the spliced value is attacker-' +
    'controlled, and for list-style APIs we judged shell usage from the visible text ' +
    'of the call only - an options object built elsewhere is invisible to us.',
  shapes: ['call'],
  support: {
    javascript: {
      status: 'implemented',
      note: 'child_process exec/execSync always reported; spawn/execFile reported only when `shell: true` appears in the call text. An options object assembled in another variable is missed, because we read the shell option from the visible text of the call.',
    },
    typescript: {
      status: 'implemented',
      note: 'Identical to JavaScript.',
    },
    python: {
      status: 'implemented',
      note: 'os.system/os.popen always reported; subprocess.* reported only when `shell=True` is visible in the call.',
    },
    java: {
      status: 'partial',
      note: 'PARTIAL: Runtime.exec(String) and ProcessBuilder are detected, but only when the command string is built at the call site. Java code commonly builds commands with StringBuilder across several statements; the signature pass cannot follow that, and the taint engine tracks variables rather than the interior of objects, so it does not either.',
    },
    go: {
      status: 'partial',
      note: 'PARTIAL: exec.Command is only reported when the call itself mentions a shell ("sh", "-c"). exec.Command("ping", host) is genuinely safe, so reporting every exec.Command would be noise - but that also means a shell wrapper built elsewhere is missed.',
    },
    php: {
      status: 'implemented',
      note: 'Covers system, exec, shell_exec, passthru, popen, proc_open and pcntl_exec. Unlike Go and Java there is no conditional case to weigh: every one of these hands the string to a shell, so a dynamic argument is always reported.',
    },
    c: {
      status: 'implemented',
      note:
        'system() and popen() hand the string to /bin/sh with no safe overload to be confused with, which makes this the least ambiguous sink list in the tool. exec* takes an argument VECTOR and is reported ONLY when the program being run is itself a shell - execv("/bin/ping", args) with a tainted argument is genuinely safe and stays quiet. The build-then-run idiom (sprintf into a buffer, then system) is followed through the buffer.',
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

    /*
     * A SHELL FUNCTION THAT WAS RENAMED IS STILL A SHELL FUNCTION.
     *
     *     import { exec } from "child_process";
     *     const execAsync = promisify(exec);
     *     await execAsync(command);
     *
     * That is CVE-2025-53107 - twenty-three vulnerable files - and this rule
     * found none of them, because the list holds `exec` and the call says
     * `execAsync`. The near-identical CVE-2025-59046 WAS caught, purely because
     * that author wrote `const exec = promisify(execCb)` and aliased back to a
     * name we already knew. Two CVEs, and the only difference was luck.
     *
     * `promisify` is the standard Node idiom for exactly these APIs, so the
     * aliased form is the normal one, not an exotic one. File-local only: an
     * alias exported from another module is still missed.
     */
    const aliasOf = (called: string): string | null => {
      const declaration = new RegExp(
        `\\b${called.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*=\\s*([^;\\n]+)`,
      ).exec(ctx.file.source);
      if (!declaration?.[1]) return null;
      const initialiser = declaration[1];
      if (!/\bpromisify\s*\(|require\s*\(|child_process/.test(initialiser)) return null;
      for (const known of [...SHELL_SINKS[language], ...CONDITIONAL_SINKS[language]]) {
        if (known !== called && new RegExp(`\\b${known}\\b`).test(initialiser)) return known;
      }
      return null;
    };
    const resolved =
      SHELL_SINKS[language].includes(call.calleeName) ||
      CONDITIONAL_SINKS[language].includes(call.calleeName)
        ? call.calleeName
        : (aliasOf(call.calleeName) ?? call.calleeName);

    const always = SHELL_SINKS[language].includes(resolved);
    const conditional = CONDITIONAL_SINKS[language].includes(resolved);
    if (!always && !conditional) return null;

    // For the conditional family, require visible evidence that a shell is used.
    const wholeCall = nodeText(call.node);
    if (conditional && !always && !SHELL_OPTION[language].test(wholeCall)) return null;

    for (const arg of call.args) {
      const built = analyzeStringExpression(arg, language);
      if (!built.isDynamic) continue;
      // A bare variable tells us nothing about a command; skip it rather than
      // report "you passed a variable to exec", which is not actionable.
      if (built.mechanism === 'opaque' && built.literalText.length === 0) continue;
      /*
       * A VALIDATION GUARD. Inside `if (is_numeric($octet[0]) && ...)` the value
       * provably holds no shell metacharacter - it is digits. This is DVWA's own
       * fix in exec/impossible.php, and reporting it was the seventh time this
       * project punished a corrected file, and the last one still showing in the
       * instrument panel. lib/guards.ts documents why the predicate list is tiny.
       */
      if (partsAreGuarded(arg, built.dynamicParts, language)) continue;

      return {
        node: arg,
        message: `Command passed to ${call.calleeText}() is built with ${built.mechanism}`,
        reasoning:
          `\`${call.calleeText}()\` executes its argument through a shell` +
          `${conditional && !always ? ' (a shell option is set in this call)' : ''}. ` +
          `The command string is not fixed - it was assembled via ${built.mechanism}, ` +
          `splicing in ${built.dynamicParts.slice(0, 3).map((p) => `\`${p}\``).join(', ') || 'a runtime value'}. ` +
          `Shell metacharacters (; | && \` $()) inside that value would be executed as ` +
          `separate commands.`,
      };
    }
    return null;
  },
};
