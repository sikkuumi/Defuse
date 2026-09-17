// FIXTURE: a shell function renamed through promisify.
//
// THIS IS CVE-2025-53107, and we found none of its twenty-three vulnerable
// files. The sink list holds `exec`; the call says `execAsync`.
//
//     import { exec } from "child_process";
//     const execAsync = promisify(exec);
//     await execAsync(command);
//
// The near-identical CVE-2025-59046 WAS caught - two lines of the same bug in
// the same language - and the only reason is that its author happened to write
// `const exec = promisify(execCb)`, aliasing back to a name already on the
// list. Two real CVEs, one caught, one missed, and the difference was luck.
//
// `promisify` is THE standard Node idiom for these APIs, so the aliased form is
// the normal one. Nothing about the danger changes when the label does.

const { exec: execCb } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(execCb);
const run = promisify(require('child_process').exec);

// EXPECT command-injection
async function checkout(branch) {
  return execAsync(`git checkout ${branch}`);
}

// EXPECT command-injection
async function clone(url) {
  return run(`git clone ${url}`);
}

// A fixed string is a fixed string whatever the function is called. Nobody can
// put anything inside a constant.
async function branches() {
  return execAsync('git branch');
}
