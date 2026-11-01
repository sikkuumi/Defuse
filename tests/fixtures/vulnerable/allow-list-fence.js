// FIXTURE: the fence around safe/allow-list-guards.js. Each check looks like
// an allow-list and is not one here, so every line must still be reported.
const { exec } = require('child_process');

// `m` makes ^ and $ match at every line: "1\nid" has a line of digits.
function multiLine(req) {
  const h = req.query.h;
  if (/^\d+$/m.test(h)) {
    // EXPECT-FLOW command-injection
    exec('ping ' + h);
  }
}

// The check passed means LEAVE. Afterwards the value is anything but digits.
function leavesOnTheGoodSide(req) {
  const h = req.query.h;
  if (/^\d+$/.test(h)) {
    return;
  }
  // EXPECT-FLOW command-injection
  exec('ping ' + h);
}

// Either check passing is enough to get in, and only one of them is a check.
function eitherCheck(req) {
  const h = req.query.h;
  if (/^\d+$/.test(h) || req.query.force) {
    // EXPECT-FLOW command-injection
    exec('ping ' + h);
  }
}

// The callback runs later, after `n` has been given a new value.
function closureRunsLater(req) {
  let n = req.query.n;
  if (Number.isInteger(n)) {
    setTimeout(() => {
      // EXPECT command-injection
      exec('kill ' + n);
    }, 1000);
  }
  n = req.query.other;
}

module.exports = { multiLine, leavesOnTheGoodSide, eitherCheck, closureRunsLater };
