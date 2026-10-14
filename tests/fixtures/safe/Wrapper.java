/*
 * The class that `Wrapper.Inner.m(...)` in StaticHelperCommand.java really
 * names: Wrapper, in the same package as the caller, with a nested Inner whose
 * m() returns a value from `lookup`, defined nowhere in the scan. No sink here;
 * in safe/, any finding is a failure.
 */
public class Wrapper {
    public static class Inner {
        public static String m(String a) {
            return lookup(a);
        }
    }
}
