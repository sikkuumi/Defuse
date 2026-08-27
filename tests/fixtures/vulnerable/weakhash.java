// FIXTURE: broken hash algorithms, Java.
import java.security.MessageDigest;

public class Hasher {
    public MessageDigest weak() throws Exception {
        // EXPECT weak-hash
        return MessageDigest.getInstance("MD5");
    }
}
