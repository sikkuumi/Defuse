// EXPECT-NONE
//
// `.exec()` ON A REGULAR EXPRESSION IS NOT A SHELL.
//
// This produced the worst finding this project has made: CRITICAL,
// FLOW-VERIFIED, in gitea's browser code, reading
//
//   "Attacker-controlled data from `window.location.pathname` reaches a shell
//    command"
//
// over `/([^/]+)\/([^/]+)/.exec(pathname)`. There is no shell. There is no
// server. There is a regular expression matching a URL path in a browser tab.
//
// Same defect as `document.write` on `process.stdout`, and as `Map.get` read as
// an outbound HTTP request: a sink list holding a short, common method name
// with nothing said about the receiver. `exec` is child_process's, and it is
// also RegExp.prototype's - and of the two, the regex one appears in almost
// every JavaScript file that parses anything.
//
// `exec` stays a BARE sink, because the destructured import is the normal way
// to reach the dangerous one:
//     const {exec} = require('child_process');  exec(cmd)
// so vulnerable/cmdi.js still fires. What is dropped is `<something>.exec(x)`
// where the something is not child_process.

const ISSUE_PATH = /([^/]+)\/([^/]+)\/(issues|pulls)\/([0-9]+)/;

// The taint source is present on purpose. Without it this file proves nothing:
// the finding was FLOW-VERIFIED, so it only appears once a tracked value
// actually arrives at the call, which is why a shape-only fixture stayed
// silent and a real scan did not.
export function parseIssuePath() {
	const pathname = window.location.pathname;
	const [, ownerName, repoName] = /([^/]+)\/([^/]+)/.exec(pathname) || [];
	return {ownerName, repoName};
}

export function parseIssue(path: string) {
	const match = ISSUE_PATH.exec(path);
	return match ? {owner: match[1], repo: match[2]} : null;
}

export function parseWith(pattern: string) {
	return new RegExp(pattern).exec(window.location.search);
}

export function parseStored() {
	return ISSUE_PATH.exec(window.location.hash);
}
