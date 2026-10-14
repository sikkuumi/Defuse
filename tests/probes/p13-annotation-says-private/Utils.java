package app;
public class Utils {
    @SuppressWarnings("private")
    public static String prefix = "sh -c ";

    public static String forShell(String a) {
        return prefix + a;
    }
}
