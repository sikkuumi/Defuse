// s03-ts-for-let-import: The literal `table` is the for loop's own `let`; the read after the loop is the import.
// s03: the for-header `table` is scoped to the loop; the second query reads the imported `table`.
import { table } from "./config";

export async function list(db: any): Promise<void> {
  for (let table = "users"; table !== ""; table = "") {
    await db.query("SELECT * FROM " + table);
  }
  // EXPECT sql-injection
  await db.query("SELECT * FROM " + table);
}
