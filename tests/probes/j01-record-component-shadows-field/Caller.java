// j01-record-component-shadows-field: Inside the record, `table` is its component - the constructor argument - not the constant field.
// j01: inside record Query, `table` is the record component (constructor argument), which shadows the outer constant field.
package app;
import java.sql.Statement;
public class Caller {
    private static final String table = "users";

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
