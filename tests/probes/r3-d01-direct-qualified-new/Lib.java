package app;

public class Lib {
    public class X {                       // an INNER class of Lib, also called X
        public String m() { return Store.lookup("p"); }
    }
}
