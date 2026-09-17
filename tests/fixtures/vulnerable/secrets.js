// FIXTURE: hardcoded credentials, JavaScript.
// All values below are FAKE and non-functional - they exist only to match a format.

// VALUE CHANGED, and the reason belongs in the file rather than a commit message.
// This line used to read "hunter2-not-a-real-password". When the placeholder
// rule learned that a value naming its own credential type is a stand-in, that
// string stopped reporting - and it was RIGHT to stop, because a value that
// says "not a real password" is not a real password. The fixture had been
// asserting that the scanner should report an obvious placeholder. The
// placeholder form now lives in safe/vscode-secret-noise.ts where it belongs;
// this line carries a value shaped like something a person would actually set.
// EXPECT hardcoded-secret
const dbPassword = "Tr0ub4dor3xK";

// Shaped like a real AWS key id (AKIA + 16 upper/digits) but generated for this
// fixture. It used to be AKIAIOSFODNN7EXAMPLE - the string AWS prints in its own
// documentation, and therefore exactly the thing the scanner must NOT report.
// See safe/awsdocs-example.js: asserting the opposite here was baking a false
// positive into the test suite as a requirement.
// EXPECT hardcoded-secret
const awsAccessKeyId = "AKIA4KTQVBN2WZRJH7PL";

const config = {
  // EXPECT hardcoded-secret
  apiKey: "sk_live_FAKEFAKEFAKEFAKEFAKE00",
  region: "eu-west-1",
};

module.exports = { dbPassword, awsAccessKeyId, config };
