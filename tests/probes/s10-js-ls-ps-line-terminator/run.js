// s10-js-ls-ps-line-terminator: A lone carriage return or U+2028 ends the comment for JavaScript, so the write after it runs.
// s10: U+2028 ends a // comment in JavaScript, so `t = lookup("x");` is a real statement.
function list(db) {
  let t = 1 > 0 ? "users" : "accounts";
  // normalise   t = lookup("x");
  // EXPECT sql-injection
  return db.query("SELECT * FROM " + t);
}
// and a CR variant
function list2(db) {
  let t = 1 > 0 ? "users" : "accounts";
  // normalise  t = lookup("x");
  // EXPECT sql-injection
  return db.query("SELECT * FROM " + t);
}
