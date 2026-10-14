/*
 * A class Inner in a package named Wrapper. Packages are lower-case by
 * convention, not by rule, so this is legal - and it is NOT what
 * `Wrapper.Inner.m(...)` in StaticHelperCommand.java calls: there, Wrapper is
 * a class (safe/Wrapper.java), and a class in scope outranks a package of the
 * same name. No sink here; in safe/, any finding is a failure.
 */
package Wrapper;

public class Inner {
    public static String m(String a) {
        return a + " ";
    }
}
