import java.io.*;
import java.util.*;

/**
 * The most famous gadget-chain entry point in Java, and this rule was silent on
 * it because `readObject()` takes NO ARGUMENTS - the bytes went into the stream
 * a line earlier, so there was no argument to inspect and the check bailed out.
 *
 * Found by a Gemini-written test file, not by the benchmark. The taint engine
 * already understood this shape (`pb.command(list); pb.start()`); the signature
 * rule did not, which is what happens when two passes are written apart.
 */
public class StreamReader {
  public void elevate(byte[] serializedAuthGrant) throws Exception {
    try (ByteArrayInputStream bais = new ByteArrayInputStream(serializedAuthGrant);
         ObjectInputStream ois = new ObjectInputStream(bais)) {
      // EXPECT unsafe-deserialization
      Map<String, String> grant = (Map<String, String>) ois.readObject();
      System.out.println(grant.size());
    }
  }
}
