/*
 * A FIELD IS NOT A LOCAL: ANY METHOD CAN WRITE IT, AND SOMETIMES ANY CLASS.
 *
 * The constant proof reads a name's writes in the method that reads it and in
 * the scopes around it - but not inside OTHER methods, because a sibling's own
 * local of the same name has nothing to do with this one (const-interp.py). A
 * field is nobody's local. The first two reads below were called constant,
 * and their findings withdrawn in silence, until strings.ts searched the other
 * methods too. The tracer does not carry a value through a field from one
 * method to another, so the pattern rule is the only thing that speaks here.
 */
import javax.servlet.http.*;

public class OuterWriteFence extends HttpServlet {

    private static String table = "users";
    public static String column = "name";
    private String order = "id";

    // Written again by a sibling method.
    void setTable(HttpServletRequest request) {
        table = request.getParameter("t");
    }

    void listTable(java.sql.Statement stmt) throws Exception {
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM " + table);
    }

    // Public and not final: nothing in this file writes it, but any class can.
    void listColumn(java.sql.Statement stmt) throws Exception {
        // EXPECT sql-injection
        stmt.execute("SELECT " + column + " FROM users");
    }

    // Written through `this.` in a sibling method. A write to `this.order` was
    // already one the proof refused to read past; it stays here as a fence.
    void setOrder(HttpServletRequest request) {
        this.order = request.getParameter("o");
    }

    void listOrdered(java.sql.Statement stmt) throws Exception {
        // EXPECT sql-injection
        stmt.execute("SELECT * FROM users ORDER BY " + order);
    }
}
