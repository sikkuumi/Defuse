package app;
public class Utils extends BaseUtils {
    public static String forShell(Object a) {
        return "sh -c " + a;
    }
}
