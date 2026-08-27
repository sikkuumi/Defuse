// FIXTURE: SQL injection, TypeScript.
interface Conn { execute(sql: string): Promise<unknown>; }

export async function findOrder(conn: Conn, orderId: string): Promise<unknown> {
  // EXPECT sql-injection
  return conn.execute(`SELECT * FROM orders WHERE order_id = '${orderId}'`);
}
