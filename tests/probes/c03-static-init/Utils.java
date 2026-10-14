package app;
public class Utils {
    private static String prefix = "sh -c ";
    static { prefix = lookup("shell"); }
    public static String forShell(String a) {
        return prefix + a;
    }
}
