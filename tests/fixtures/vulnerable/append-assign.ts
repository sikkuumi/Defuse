/*
 * `+=` EXTENDS A VALUE. FOR A LONG TIME IT REPLACED IT.
 *
 * See append-assign.js for the full story. TypeScript is not a copy of the
 * JavaScript case for the reason this suite keeps rediscovering: it has its
 * own grammar, and "TypeScript behaves like JavaScript" has already been
 * falsified once here - an angle-bracket cast was a wall taint could not cross
 * from the day the language was added, purely because the two spellings of a
 * cast put the value on opposite sides of the node.
 *
 * So the claim is tested rather than inherited, and the compound assignment is
 * exercised alongside a type annotation and an `as` cast, which are the two
 * things most likely to be sitting on the same line in real TypeScript.
 */
import { exec } from 'child_process';

interface Req {
  query: Record<string, string>;
}

export function trailingConstant(req: Req): void {
  let cmd: string = 'ls ';
  cmd += req.query.dir;
  cmd += ' -l';
  // EXPECT-FLOW command-injection
  exec(cmd);
}

export function throughACastAndAnAppend(req: Req): void {
  let cmd = 'grep -F ';
  cmd += req.query.term as string;
  cmd += ' /var/log/app.log';
  // EXPECT-FLOW command-injection
  exec(cmd);
}

/* The over-fix guard: a real overwrite must still clear the value. */
export function realReassignmentStillClears(req: Req): void {
  let cmd = 'ls ';
  cmd += req.query.dir;
  cmd = 'ls -l';
  exec(cmd);
}
