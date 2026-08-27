// FIXTURE: hardcoded credentials, JavaScript.
// All values below are FAKE and non-functional - they exist only to match a format.

// EXPECT hardcoded-secret
const dbPassword = "hunter2-not-a-real-password";

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
