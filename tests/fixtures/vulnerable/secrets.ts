
// ---- The falsification half of safe/calcom-secret-noise.ts. ----
//
// That file teaches two ways a value can be proven not to be a credential. Both
// are silencing rules on the noisiest rule in the engine, so the shapes they
// must NOT touch are written down here.

// A DICEWARE PASSPHRASE. Four words and a space between each, which is exactly
// the shape rule 2 must not mistake for an error message. It carries no English
// function word, and it is a real credential.
// EXPECT hardcoded-secret
const backupPassphrase = "correct horse battery staple";

// The word `example` has to be the PROPERTY NAME to count as documentation.
// A property that merely mentions it is an ordinary assignment.
// EXPECT hardcoded-secret
const exampleApiKey = "sk_live_51H8xQ2KZvEXAMPLEnotarealkey00";

// A real secret next to a documented one. The `example` key is silenced; the
// `secret` key beside it is not, which is the Jenkins lesson applied here - a
// proof covering one value must never vouch for its neighbour.
export const mixedSchema = {
  example: "clsx38nbl0001vkhlwin9fmt0",
  // EXPECT hardcoded-secret
  clientSecret: "cal_prod_9f3a7b2e1d8c6045aa91bb33ce77df20",
};

// FROM THE CORPUS, NOT FROM MY IMAGINATION. Express ships this in
// examples/cookie-sessions/index.js, and the first version of looksLikeProse
// silenced it because "is" is an English function word. A human-chosen
// passphrase reads exactly like prose; only the NAME tells you which is which.
// EXPECT hardcoded-secret
const sessionSecret = "manny is cool";
