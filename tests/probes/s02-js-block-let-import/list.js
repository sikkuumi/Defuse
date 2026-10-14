// s02-js-block-let-import: The literal `table` is a block-local `let`; the read after the block is the import.
// s02: the "users" `table` is a block-scoped let; the query reads the imported `table`.
import { table } from "./config.js";

export function list(db, verbose) {
  if (verbose) {
    let table = "users";
    console.log(table);
  }
  // EXPECT sql-injection
  return db.query("SELECT * FROM " + table);
}
