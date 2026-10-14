package app;
public class Utils {
    private static String prefix = "sh -c ";
    static class Loader { static void load() { Utils.prefix = lookup("shell"); } }
    public static String forShell(String a) {
        return prefix + a;
    }
}
