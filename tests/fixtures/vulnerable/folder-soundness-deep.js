// A second write at the end of a 25-branch else-if chain: past the depth the
// write search used to stop at, and read as "no second write".
const db = require('./db');
function chain(req) {
  const param = req.query.p;
  const op = req.query.op;
  let n = 0;
  if (op === 'op0') {
    console.log('op0');
  } else if (op === 'op1') {
    console.log('op1');
  } else if (op === 'op2') {
    console.log('op2');
  } else if (op === 'op3') {
    console.log('op3');
  } else if (op === 'op4') {
    console.log('op4');
  } else if (op === 'op5') {
    console.log('op5');
  } else if (op === 'op6') {
    console.log('op6');
  } else if (op === 'op7') {
    console.log('op7');
  } else if (op === 'op8') {
    console.log('op8');
  } else if (op === 'op9') {
    console.log('op9');
  } else if (op === 'op10') {
    console.log('op10');
  } else if (op === 'op11') {
    console.log('op11');
  } else if (op === 'op12') {
    console.log('op12');
  } else if (op === 'op13') {
    console.log('op13');
  } else if (op === 'op14') {
    console.log('op14');
  } else if (op === 'op15') {
    console.log('op15');
  } else if (op === 'op16') {
    console.log('op16');
  } else if (op === 'op17') {
    console.log('op17');
  } else if (op === 'op18') {
    console.log('op18');
  } else if (op === 'op19') {
    console.log('op19');
  } else if (op === 'op20') {
    console.log('op20');
  } else if (op === 'op21') {
    console.log('op21');
  } else if (op === 'op22') {
    console.log('op22');
  } else if (op === 'op23') {
    console.log('op23');
  } else if (op === 'op24') {
    console.log('op24');
  } else {
    n = param.length;
  }
  const bar = n > 5 ? param : 'safe';
  // EXPECT sql-injection
  db.query("SELECT * FROM t WHERE x = '" + bar + "'");
}
module.exports = { chain };
