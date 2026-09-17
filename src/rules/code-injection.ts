/**
 * CODE INJECTION  (CWE-94 / CWE-95, OWASP A05:2025 - Injection)
 *
 * WHAT THE BUG IS, in plain language:
 * The other injection rules are about a string being read as instructions by
 * something ELSE - a database, a shell, a browser. This one is about a string
 * being read as instructions by YOUR OWN PROGRAM, in your own language, with
 * every privilege your process has.
 *
 *     const total = eval(req.body.preTax);
 *
 * The author wanted arithmetic. What they built is a remote code execution
 * endpoint: whatever the request body says, the server runs. No escaping helps,
 * because there is nothing to escape - the whole string IS the program.
 *
 * It is the shortest path from "user input" to "attacker owns the machine" in
 * any language that has it, and it is startlingly common in code that meant to
 * be clever about configuration, formulas, filters or plugins.
 *
 * THE FIX is always the same shape: stop evaluating, start parsing. A maths
 * expression wants an expression parser. A filter wants a fixed vocabulary of
 * allowed operations. A plugin wants a registry of known functions looked up by
 * name. All three are more code than `eval` and none of them can be talked into
 * running `rm -rf`.
 *
 * WHY IT NEEDED A NEW SINK KIND:
 * `command` is a shell; `code` is the interpreter you are already inside. A
 * shell-quoting sanitiser (`escapeshellarg`, `shlex.quote`) does nothing here,
 * and the engine has to know that, which is exactly what kind-scoping is for.
 *
 * WHY IT EXISTS AT ALL:
 * Three independent test files pointed at the same hole on the same day -
 * OWASP NodeGoat's `eval(req.body.preTax)`, a Python file's
 * `eval(expression, safe_globals)`, and a TypeScript app's
 * `new RegExp(req.query.filter)`. In every one the tracer had already found the
 * source and followed it; there was simply nothing at the far end to hand it
 * to. The engine could see these all along.
 *
 * WHAT THIS RULE DELIBERATELY DOES NOT COVER:
 * ReDoS - `new RegExp(userInput)` - is a real bug and was one of the three that
 * prompted this rule, but it is CWE-1333 and an AVAILABILITY problem: a
 * catastrophically backtracking pattern hangs the process, it does not run the
 * attacker's code. Filing it under CWE-94 would put the wrong number on a real
 * finding, so it is left out and named here rather than quietly folded in.
 */

import type { LanguageId } from '../parse/languages.js';
import { asCall, type Rule, type RuleHit } from './contract.js';
import { analyzeStringExpression } from './lib/strings.js';

/**
 * Calls that hand a string to the language's own interpreter.
 *
 * `setTimeout` and `setInterval` are NOT here, and the omission is deliberate.
 * They only execute a string argument - `setTimeout("alert(1)", 100)` - and the
 * overwhelmingly common form passes a FUNCTION. Reporting them on shape would
 * light up every debounce and every retry in every codebase. They are listed as
 * taint sinks instead, where the engine knows the value came from a request and
 * a request cannot deliver a function.
 */
const EVALUATORS: Record<LanguageId, readonly string[]> = {
  javascript: ['eval', 'Function', 'execScript', 'runInNewContext', 'runInThisContext'],
  typescript: ['eval', 'Function', 'execScript', 'runInNewContext', 'runInThisContext'],
  // `compile` produces a code object that only `exec` can run, but it is the
  // same decision one step earlier, and reporting it points at the real line.
  python: ['eval', 'exec', 'compile'],
  // `assert($x)` evaluates its argument as PHP when handed a string. It is a
  // debugging aid that became an RCE primitive, removed in PHP 8 - which means
  // the codebases that still use it are the old ones nobody is watching.
  php: ['eval', 'assert', 'create_function'],
  // ScriptEngine.eval("...") runs JavaScript inside the JVM.
  java: ['eval'],
  // Go has no eval. There is no interpreter at runtime to hand a string to, so
  // the shape this rule detects cannot occur, and an empty list is the honest
  // answer rather than a rule that never fires but implies coverage.
  go: [],
  // C has no interpreter to hand a string to. `dlopen`/`dlsym` load code, but
  // from a PATH rather than from a string, which is a different bug (untrusted
  // search path) and not one this rule models. Empty on purpose, and the
  // coverage matrix says so rather than leaving a blank.
  c: [],
  cpp: [],
};

/**
 * Evaluators that are BUILT-IN FUNCTIONS, and are therefore only themselves
 * when called with nothing in front of them.
 *
 * Scanning Django found 163 code-injection findings and 153 were this mistake:
 *
 *     compiler.compile(value)     Django's own SQL compiler        x82
 *     re.compile(pattern)         a regular expression             x21
 *     self.compile(node)          somebody's method                x20
 *     x.eval(...)                 somebody else's method           x25
 *
 * `compile`, `eval` and `exec` are builtins. `re.compile` shares three letters
 * with the dangerous one and nothing else. Matching the bare method name meant
 * every object in Python with a `.compile()` or `.eval()` method - and there are
 * a lot of them, because those are natural names for "turn this into a runnable
 * thing" in any DSL, ORM or template engine.
 *
 * Not on this list: vm.runInNewContext, which is a method and is supposed to
 * have `vm` in front of it, and Java's ScriptEngine.eval, which is handled by
 * JAVA_ENGINE below.
 */
const BARE_BUILTINS: ReadonlySet<string> = new Set([
  'eval',
  'exec',
  'compile',
  'execScript',
  'assert',
  'create_function',
  'Function',
]);

/**
 * Receivers that ARE evaluators, and so keep the finding despite BARE_BUILTINS.
 *
 * The bare-only rule was too blunt on its own: OWASP's dvna has
 *
 *     mathjs.eval(req.body.eqn)
 *
 * which is a genuine remote-code-execution sink - mathjs's `eval` has its own
 * CVEs - and it has a receiver, so the first version of this guard silently
 * dropped it. That is the exact trade this rule has to get right: `re.compile`
 * and `compiler.compile` are somebody's method, `mathjs.eval` and `window.eval`
 * are the interpreter. The difference is WHICH object, not whether there is one.
 */
const EVALUATOR_RECEIVERS: ReadonlySet<string> = new Set([
  'mathjs',
  'math',
  'vm',
  'safeEval',
  'eval5',
  'builtins',
  '__builtins__',
]);

/**
 * Receivers that are the GLOBAL OBJECT, and therefore only in JavaScript.
 *
 * `self` was the expensive one. In a browser - and especially in a web worker,
 * where it is the only name for the global scope - `self.eval(src)` IS the
 * interpreter, so it belonged on the allowlist. In Python `self` is the
 * instance, and `self.eval(expr)` is a method somebody wrote.
 *
 * Scanning pandas reported 42 code injections and seventeen were `self.eval` -
 * pandas' own `DataFrame.eval`, a public API that parses a restricted
 * expression grammar and cannot reach the interpreter. The allowlist was
 * correct; applying a JavaScript fact to Python was not. `window`, `global`
 * and `globalThis` move here for the same reason, even though no other language
 * happened to collide with them yet.
 */
const JS_GLOBAL_RECEIVERS: ReadonlySet<string> = new Set([
  'window',
  'global',
  'globalThis',
  'self',
]);

/**
 * Is this dangerous-looking name actually bound to something else in this file?
 *
 * pandas/core/computation/ops.py, with the import one line above the call:
 *
 *     from pandas.core.computation.eval import eval
 *     res = eval(self, local_dict=env, engine=engine, parser=parser)
 *
 * `eval`, `exec` and `compile` are only dangerous because of what the
 * interpreter binds those names to. An explicit import rebinds them, and this
 * scanner is holding the very file that says so. Reporting it anyway was
 * matching a name rather than a function.
 *
 * Deliberately narrow: only an explicit import of the same name counts. A
 * reassignment (`eval = my_evaluator`) or a `import *` that happens to shadow
 * it is NOT detected, and is a documented gap rather than a guess.
 */
function isImportedName(source: string, name: string): boolean {
  const n = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // from x.y import (a, eval, b)  /  from x import eval as e  /  import eval
  return (
    new RegExp(`^[ \\t]*from[ \\t]+[\\w.]+[ \\t]+import[ \\t]*\\(?[^\\n]*\\b${n}\\b`, 'm').test(
      source,
    ) || new RegExp(`^[ \\t]*import[ \\t]+${n}\\b`, 'm').test(source)
  );
}

/**
 * Receivers that make `eval` unambiguous in Java, where the bare name is far
 * too common. `engine.eval(script)` is the JSR-223 scripting API.
 */
const JAVA_ENGINE = /engine|script|nashorn|graal|interpreter/i;

export const codeInjectionRule: Rule = {
  id: 'code-injection',
  name: 'User input evaluated as program code',
  cwe: 'CWE-94',
  owasp: 'A05:2025 Injection',
  severity: 'critical',
  explanation:
    'Passing a string to eval (or exec, Function, assert) tells your own language ' +
    'to run it as a program, with every privilege the process has. If any part of ' +
    'that string came from a request, the request decides what your server does. ' +
    'There is nothing to escape here - the string IS the program - so the fix is ' +
    'always to stop evaluating and start parsing: an expression parser for maths, ' +
    'a fixed vocabulary for filters, a lookup table for plugins.',
  limitations:
    'UNVERIFIED (signature-based): we confirmed a value reaches an evaluator and ' +
    'that it is not a fixed literal. We did NOT confirm it is attacker-controlled - ' +
    'the data-flow pass is what upgrades this to flow-verified, and evaluating your ' +
    'own constant is harmless. DELIBERATE GAP: setTimeout and setInterval accept a ' +
    'string and run it, but almost always receive a function, so they are taint ' +
    'sinks only and are never reported on shape alone. ALSO NOT COVERED: ReDoS - ' +
    'new RegExp(userInput) - is a real bug but it is CWE-1333 and an availability ' +
    'problem rather than code execution, so filing it here would put the wrong ' +
    'identifier on a real finding. Go is not covered because it has no runtime ' +
    'evaluator for the shape to occur in.',
  shapes: ['call'],
  support: {
    javascript: {
      status: 'implemented',
      note: 'Covers eval, new Function, and the vm module\'s runInNewContext/runInThisContext. setTimeout/setInterval with a string are taint sinks only, because the common form passes a function and reporting on shape would flag every debounce in the codebase.',
    },
    typescript: {
      status: 'implemented',
      note: 'Identical to JavaScript.',
    },
    python: {
      status: 'implemented',
      note: 'Covers eval, exec and compile. NOT covered: __import__ with a built name, and the ast.literal_eval / eval confusion - literal_eval is safe and is deliberately absent.',
    },
    java: {
      status: 'partial',
      note: 'PARTIAL: ScriptEngine.eval only, and only on a receiver whose name looks like a script engine (engine, script, nashorn, graal). `eval` is a common method name in Java, so an engine stored under an unrelated name is missed rather than guessed at.',
    },
    php: {
      status: 'implemented',
      note: 'Covers eval, assert with a string argument, and create_function. assert() evaluating strings was removed in PHP 8, so a hit here also tells you the file predates that.',
    },
    go: {
      status: 'not-implemented',
      note: 'NOT IMPLEMENTED: Go has no runtime evaluator - no eval, no exec of source, no scripting engine in the standard library. The shape this rule detects cannot occur, so a Go entry would imply coverage of a risk that does not exist.',
    },
    c: {
      status: 'not-implemented',
      note:
        'C has no interpreter to hand a string to. dlopen/dlsym load code, but from a PATH rather than from a string - that is an untrusted-search-path weakness, which this rule does not model. Empty on purpose rather than half-filled.',
    },
    cpp: {
      status: 'not-implemented',
      note:
        'C++ has no interpreter to hand a string to either. Embedded scripting engines (Lua, V8, Python-C-API) genuinely do evaluate strings and are NOT modelled - a tainted string reaching luaL_dostring or v8::Script::Compile is missed entirely.',
    },
  },
  check(shape, ctx): RuleHit | null {
    const language = ctx.language;
    const call = asCall(shape);
    if (!call) return null;

    if (!EVALUATORS[language].includes(call.calleeName)) return null;

    // Java's `eval` needs a receiver that looks like a scripting engine.
    if (language === 'java' && !JAVA_ENGINE.test(call.receiverText)) return null;

    // Everywhere else, a builtin with something in front of it is somebody
    // else's method that happens to share the name.
    const isJs = language === 'javascript' || language === 'typescript';
    if (language !== 'java' && BARE_BUILTINS.has(call.calleeName) && call.receiverText !== '') {
      const owner = call.receiverText.split(/[.\s([]/).filter(Boolean).pop() ?? call.receiverText;
      const known = EVALUATOR_RECEIVERS.has(owner) || (isJs && JS_GLOBAL_RECEIVERS.has(owner));
      if (!known) return null;
    }

    // A builtin the file has explicitly imported over is not the builtin.
    if (BARE_BUILTINS.has(call.calleeName) && isImportedName(ctx.file.source, call.calleeName)) {
      return null;
    }

    // PHP's assert() is only dangerous with a STRING argument; assert($a > $b)
    // is an ordinary boolean check and is not evaluated as source.
    const argument = call.args[0];
    if (!argument) return null;
    if (language === 'php' && call.calleeName === 'assert') {
      if (argument.type !== 'string' && argument.type !== 'encapsed_string') {
        // A variable could still hold a string, so we do not drop it outright -
        // but a visible comparison is provably not source text.
        if (argument.type === 'binary_expression') return null;
      }
    }

    /*
     * `exec(compile(source, name, "exec"))` is ONE decision, and this rule saw
     * two: once for the `exec` and once for the `compile` inside it. Flask's
     * own config loader produced a duplicate pair on the same line.
     *
     * `compile` earns its place in the list because it is sometimes reached
     * alone, but when its result is being handed straight to an evaluator the
     * outer call is the honest place to report - it is where the code actually
     * runs, and one line of source should not become two findings.
     */
    if (call.calleeName === 'compile') {
      let ancestor = call.node.parent;
      for (let depth = 0; ancestor && depth < 4; depth++) {
        const text = ancestor.text ?? '';
        if (/\b(eval|exec)\s*\(/.test(text) && ancestor.type !== 'call' && ancestor.type !== 'call_expression') {
          ancestor = ancestor.parent;
          continue;
        }
        if (
          (ancestor.type === 'call' || ancestor.type === 'call_expression') &&
          /^\s*(eval|exec)\s*\(/.test(text)
        ) {
          return null;
        }
        ancestor = ancestor.parent;
      }
    }

    const built = analyzeStringExpression(argument, language);
    // `eval("1 + 1")` is a constant. Nobody can put anything inside it.
    if (!built.isDynamic) return null;

    return {
      node: call.node,
      message: `Value passed to ${call.calleeName}() is executed as ${language === 'php' ? 'PHP' : language} code`,
      reasoning:
        `\`${call.calleeName}()\` hands its argument to the interpreter this program is ` +
        `already running inside, so whatever the string says, the process does - with ` +
        `every permission it has. The value here is ${built.mechanism === 'opaque' ? 'a runtime value' : `built at runtime via ${built.mechanism}`}, ` +
        `so its text is not fixed at the time you are reading this line. Escaping cannot ` +
        `help, because the whole string is the program. Replace the evaluation with a ` +
        `parser for the thing you actually wanted: an expression evaluator for arithmetic, ` +
        `a fixed set of allowed operations for filters, a lookup table for plugin names.`,
    };
  },
};
