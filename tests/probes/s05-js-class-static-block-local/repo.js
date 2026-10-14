// s05-js-class-static-block-local: The literal `table` is a local of a class static block; the read is the import.
// s05: the "users" `table` is a local of the class static block; list() reads the imported `table`.
import { table } from "./config.js";

export class Repo {
  static {
    const table = 1 > 0 ? "users" : "accounts";
    Repo.defaultTable = table;
  }
  list(db) {
    // EXPECT sql-injection
    return db.query("SELECT * FROM " + table);
  }
}
