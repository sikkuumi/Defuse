/*
 * A Quoter in the unnamed package - the same package as StaticHelperCommand.java.
 * Its wrap() is literals around its parameter. It is NOT the Quoter that file
 * calls: that file imports fixtures.other.Quoter (safe/Quoter.java), and in
 * Java a single-type import beats a class of the same name in your own package.
 */
public class Quoter {
    public static String wrap(String a) {
        return "'" + a + "'";
    }
}
