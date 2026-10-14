package app;
public class Utils {
    private static String prefix;

    public static void setPrefix(String p) {
        prefix = p;
    }

    public static String forShell(String a) {
        if (prefix == null) {
            String prefix = "sh -c ";
            return prefix + a;
        }
        return prefix + a;
    }
}
