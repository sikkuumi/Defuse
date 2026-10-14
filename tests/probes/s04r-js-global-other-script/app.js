// s04r-js-global-other-script: As s04, with a compile-time condition so the withdrawal leaves a receipt.
// s04r: `table` is a page global set by config.js from the URL; it is only reset to "users" when `reset` is true.
function list(db, reset) {
  if (reset) {
    table = 1 > 0 ? "users" : "accounts";
  }
  // EXPECT sql-injection
  return db.query("SELECT * FROM " + table);
}
