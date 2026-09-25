/*
 * The decoy for ReceiverTypeCaller.java: an unrelated class that happens to
 * declare a method of the same name, and returns a constant. It is not a
 * Fragment, so no call on a Fragment can reach it.
 */
public class ReceiverTypeDecoy {
    public String renderFragment(String s) {
        return "<b>fixed</b>";
    }
}
