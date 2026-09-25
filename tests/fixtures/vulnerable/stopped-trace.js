/*
 * DELEGATION IN JAVASCRIPT: A METHOD FORWARDING TO A SAME-NAMED METHOD.
 *
 * See stopped-trace.py for the whole story. `run` calls `this.shell.run`, the
 * tracer resolves calls by name, finds the method it is already inside, stops
 * - and until this fix, declared the value clean at the stop.
 */
const { exec } = require('child_process');

class Runner {
  run(cmd) {
    return this.shell.run(cmd);
  }
}

function handler(req) {
  const r = new Runner();
  // EXPECT-FLOW command-injection
  exec(r.run(req.query.cmd));
}

module.exports = { handler };
