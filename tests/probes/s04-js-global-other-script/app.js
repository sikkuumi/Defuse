// s04-js-global-other-script: `table` is a global declared by another script; this file only ever writes a literal to it.
// s04: `table` is a page global set by config.js from the URL; it is only reset to "users" when `reset` is true.
function list(db, reset) {
  if (reset) {
    table = "users";
  }
  // EXPECT sql-injection
  return db.query("SELECT * FROM " + table);
}
