// EXPECT-NONE
//
// A CONSTANT THAT NAMES A THING IS NOT A CONSTANT THAT HOLDS IT.
//
// Keycloak - 4,000 Java files, an identity server, the most credential-dense
// codebase imaginable - produced 152 hardcoded-secret findings. This block is
// most of them, and the shape is unmistakable once seen:
//
//     PRIVATE_KEY_KEY = "privateKey"
//
// The constant's VALUE is a camelCase rendering of the constant's own NAME. It
// is the string used to look the real key up in a config map. Mattermost's
// TypeScript showed the identical shape in snake_case - MANAGE_OAUTH =
// "manage_oauth" - which is what made it a class rather than a Keycloak quirk.
//
// The test is cheap and safe: a credential is never a restatement of the name
// it is stored under. `password = "Tr0ub4dor3xK"` and `SECRET_KEY = "config"`
// share no words with their names and both still report - see
// vulnerable/secrets.java.

package fixtures;

public class ConfigKeys {
    // Every one of these is a map key, not a key.
    public static final String PRIVATE_KEY_KEY = "privateKey";
    public static final String ECDSA_PRIVATE_KEY_KEY = "ecdsaPrivateKey";
    public static final String ECDH_PRIVATE_KEY_KEY = "ecdhPrivateKey";
    public static final String EDDSA_PRIVATE_KEY_KEY = "eddsaPrivateKey";
    public static final String KEYSTORE_PASSWORD_KEY = "keystorePassword";
    public static final String KEY_PASSWORD_KEY = "keyPassword";
    public static final String SECRET_SIZE_KEY = "secretSize";
    public static final String CLIENT_SECRET_KEY = "clientSecret";

    // A PEM DELIMITER IS NOT A PEM KEY.
    //
    // The known-format matcher looks for "-----BEGIN ... PRIVATE KEY-----",
    // which is correct when a key follows it and wrong when the string IS the
    // delimiter and nothing else. Keycloak defines both halves as constants so
    // it can assemble and parse PEM files - there is no key material here.
    public static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    public static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
}
