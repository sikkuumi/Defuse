// s02r-js-block-let-import: As s02, with a compile-time condition so the withdrawal leaves a receipt.
// s02r: the "users" `table` is a block-scoped let; the query reads the imported `table`.
import { table } from "./config.js";

export function list(db, verbose) {
  if (verbose) {
    let table = 1 > 0 ? "users" : "accounts";
    console.log(table);
  }
  // EXPECT sql-injection
  return db.query("SELECT * FROM " + table);
}
