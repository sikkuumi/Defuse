// EXPECT-NONE
//
// A TERMINAL IS NOT A BROWSER.
//
// Scanning all 3,816 files of VS Code produced fourteen flow-verified findings.
// NINE of them were this file's shapes, each reported as
//
//     "reaches document.write, which parses its argument as HTML"
//
// over `process.stdout.write(...)` in a Node command-line script. There was no
// document, no browser, and no HTML anywhere in those files. The sink list said
// `methods: ['write', 'writeln']` with no receiver constraint, so every object
// in JavaScript with a `.write()` method - streams, sockets, files, hashes,
// loggers - was a cross-site-scripting sink.
//
// Two things were wrong and only one of them was the false positive. The other
// was the sentence: the description hard-coded "document.write" and printed it
// whatever the receiver actually said, so the report asserted the existence of
// a call that was not in the file. A finding labelled flow-verified is claiming
// proof, and a claim of proof that names the wrong sink is worse than no
// finding at all.
//
// The taint tracing was, once again, entirely correct. `process.argv` IS
// attacker-influenced in the sense the tracer means, and it really did reach
// these calls. The far end was the part that was wrong.

import { createWriteStream } from 'node:fs';
import { createHash } from 'node:crypto';

const args = process.argv.slice(2);
const target = args[0] ?? 'default';

// 1. The standard output stream. This is a terminal, or a pipe into another
//    program. Nothing here parses HTML.
process.stdout.write(`Scanning: ${target}\n`);
process.stdout.write(`Fixtures: ${args.join(', ')}\n\n`);

// 2. The standard error stream - same thing, different file descriptor.
process.stderr.write(`warning: ${target} not found\n`);

// 3. A file on disk.
const log = createWriteStream('run.log');
log.write(`started with ${target}\n`);

// 4. A hash. `write` here is bytes in, digest out.
const digest = createHash('sha256');
digest.write(target);

// 5. A logger somebody built. The receiver is unknown to us, which is exactly
//    why matching a bare `write` was never going to work - "unknown receiver"
//    is the common case, not the exception.
const logger = { write: (line: string) => line.length };
logger.write(`argv=${args.length}`);

// STILL REPORTED, and deliberately not in this file: `document.write(dirty)`,
// `doc.write(dirty)` and `res.write('<p>' + dirty + '</p>')`. Those live in
// tests/fixtures/vulnerable/xss.js, which is the other half of this test - if
// the guard added here also silences those, this fixture passing means nothing.
