package app;
public class Sub extends Caller {
    @Override
    protected String build(String a) { return lookup(a); }
}
