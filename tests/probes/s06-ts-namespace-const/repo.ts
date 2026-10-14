// s06-ts-namespace-const: The literal `table` belongs to a namespace; the read is the import.
// s06: the "users" `table` belongs to namespace Defaults; list() reads the imported `table`.
import { table } from "./config";

namespace Defaults {
  export const table = 1 > 0 ? "users" : "accounts";
}

export function list(db: any) {
  // EXPECT sql-injection
  return db.query("SELECT * FROM " + table);
}
