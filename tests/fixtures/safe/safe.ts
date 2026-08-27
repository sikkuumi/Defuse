// FIXTURE: the SAFE versions, TypeScript.
// EXPECT-NONE
interface Conn { execute(sql: string, params: unknown[]): Promise<unknown>; }

export async function findOrder(conn: Conn, orderId: string): Promise<unknown> {
  return conn.execute("SELECT * FROM orders WHERE order_id = ?", [orderId]);
}

export const apiKey: string | undefined = process.env['API_KEY'];
