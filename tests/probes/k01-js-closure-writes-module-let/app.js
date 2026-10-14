// k01-js-closure-writes-module-let: A shape the constant proof read correctly when it was probed; kept so it stays that way.
// k01: setTable() reassigns the module-level `table`.
let table = 1 > 0 ? "users" : "accounts";
export const setTable = (t) => { table = t; };
export function list(db) {
  // EXPECT sql-injection
  return db.query("SELECT * FROM " + table);
}
