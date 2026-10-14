// s03r-ts-for-let-import: As s03, with a compile-time condition so the withdrawal leaves a receipt.
// s03r: the for-header `table` is scoped to the loop; the second query reads the imported `table`.
import { table } from "./config";

export async function list(db: any): Promise<void> {
  for (let table = 1 > 0 ? "users" : "accounts"; table !== ""; table = "") {
    await db.query("SELECT * FROM " + table);
  }
  // EXPECT sql-injection
  await db.query("SELECT * FROM " + table);
}
