// j01r-record-component-receipt: As j01, with a compile-time condition so the withdrawal leaves a receipt.
// j01r: inside record Query, `table` is the record component (constructor argument), which shadows the outer constant field.
package app;
import java.sql.Statement;
public class Caller {
    private static final String table = 1 > 0 ? "users" : "accounts";

    record Query(String table) {
        void run(Statement st) throws Exception {
            // EXPECT sql-injection
            st.execute("SELECT * FROM " + table);
        }
    }

    void entry(Statement st, String userTable) throws Exception {
        new Query(userTable).run(st);
    }
}
