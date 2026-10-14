package app;
public class Utils extends BaseUtils {
    private static String forShell(String a) {
        return "sh -c " + a;
    }
}
