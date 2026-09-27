/*
 * The JavaScript half of FolderSoundnessProbe.java - an adversarial probe's
 * programs, each a real injection the constant folder hid before this was fixed.
 */
const db = require('./db');

function parenAssign(req) {
  const param = req.query.p;
  let n = 0;
  (n) = param.length;
  const bar = n > 5 ? param : 'safe';
  // EXPECT sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

function arrayDestructure(req) {
  const param = req.query.p;
  let n = 0;
  [n] = [param.length];
  const bar = n > 5 ? param : 'safe';
  // EXPECT sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

function objectDestructure(req) {
  const param = req.query.p;
  let limit = 0;
  ({ limit } = req.query);
  const bar = limit > 5 ? param : 'safe';
  // EXPECT sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

function argumentsAlias(req, n) {
  const param = req.query.p;
  var n = 0;
  arguments[1] = param.length;
  const bar = n > 5 ? param : 'safe';
  // EXPECT sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

function withScope(req) {
  const param = req.query.p;
  let n = 0;
  with (req.query) {
    const bar = n > 5 ? param : 'safe';
    // EXPECT sql-injection
    db.query("SELECT * FROM t WHERE x = '" + bar + "'");
  }
}

function evalWrite(req) {
  const param = req.query.p;
  var n = 0;
  eval('n = 7');
  const bar = n > 5 ? param : 'safe';
  // EXPECT sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

function legacyOctal(req) {
  const param = req.query.p;
  var n = 010;
  const bar = n < 9 ? param : 'safe';
  // EXPECT sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

function division(req) {
  const param = req.query.p;
  const half = 7 / 2;
  const bar = half > 3 ? param : 'safe';
  // EXPECT sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

function divisionSwitch(req) {
  const param = req.query.p;
  const mode = 7 / 2;
  let bar;
  switch (mode) {
    case 3:
      bar = 'safe';
      break;
    default:
      bar = param;
  }
  // EXPECT sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}

module.exports = { parenAssign, arrayDestructure, objectDestructure, argumentsAlias, withScope, evalWrite, legacyOctal, division, divisionSwitch };
