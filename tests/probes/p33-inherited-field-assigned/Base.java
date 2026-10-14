package app;
public class Base {
    protected String table;

    protected void refresh() {
        table = lookup("t");
    }
}
