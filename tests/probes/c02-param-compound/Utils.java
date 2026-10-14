package app;
public class Utils {
    public static String forShell(String a) {
        a += lookup("suffix");
        return "sh -c " + a;
    }
}
