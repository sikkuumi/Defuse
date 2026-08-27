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
  },
  check(shape, ctx): RuleHit | null {
    const call = asCall(shape);
    if (!call) return null;
    const language = ctx.language;

    const always = SHELL_SINKS[language].includes(call.calleeName);
    const conditional = CONDITIONAL_SINKS[language].includes(call.calleeName);
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
