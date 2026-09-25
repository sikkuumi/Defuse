/*
 * THE TWO-LINE FORM OF THE MOST COMMON COMMAND INJECTION IN NODE.
 *
 * See build-then-run.py. `exec("ls " + name)` was reported and
 * `const cmd = "ls " + name; exec(cmd);` was not, because the rule read only
 * what sat inside exec's brackets.
 */
const { exec, execSync, spawn } = require('child_process');

function concatThenRun(name) {
  const cmd = 'ls ' + name;
  // EXPECT-SIGNATURE command-injection
  exec(cmd);
}

function templateThenRun(name) {
  const cmd = `ls -l ${name}`;
  // EXPECT-SIGNATURE command-injection
  execSync(cmd);
}

function extendedThenRun(term) {
  let cmd = 'grep -r ';
  cmd += term;
  // EXPECT-SIGNATURE command-injection
  exec(cmd);
}

/* ---------------------------------------------------------------- FENCES */

function fixed() {
  const cmd = 'uptime';
  exec(cmd);
}

function overwritten(name) {
  let cmd = 'ls ' + name;
  cmd = 'ls -l';
  exec(cmd);
}

function given(cmd) {
  exec(cmd);
}

// spawn without shell:true takes an argument vector - nothing is parsed.
function argumentVector(name) {
  const args = ['-l', name];
  spawn('ls', args);
}

module.exports = { concatThenRun, templateThenRun, extendedThenRun, fixed, overwritten, given, argumentVector };
