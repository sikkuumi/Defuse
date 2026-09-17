// EXPECT-NONE
//
// 138 SECRETS ON CAL.COM, AND 70% OF THE WHOLE SCAN.
//
// Scanning cal.com - 3,941 TypeScript files, the largest TS codebase this tool
// has been pointed at - produced 196 findings, of which 138 were
// hardcoded-secret. One rule was 70% of the report, which is the shape a
// scanner takes on right before somebody stops reading it.
//
// Most of that was a test-path gap, fixed in isTestPath (see the note there:
// `.e2e.ts` is a filename SUFFIX, not a directory, and `tests?` does not match
// `packages/testing/`). That took the cluster from 138 to 21.
//
// This file holds two smaller classes left standing afterwards, both of which
// are values that are not credentials at all.

// ---- 1. A PROPERTY LITERALLY NAMED `example` IS DOCUMENTATION ----
//
// cal.com's OpenAPI schema files declare response shapes for its public API:
//
//     packages/platform/types/oauth-clients/outputs/oauth-client.output.ts
//
// The values are high-entropy on purpose, because a documentation example of
// an ID or a JWT has to look like the real thing to be useful. The property
// name is the tell, and it is unambiguous - `example` is the OpenAPI keyword.
// This is the same reasoning as isVendorDocExample: published sample data is
// published precisely so it can be copied.
export const oauthClientSchema = {
  clientId: {
    type: 'string',
    example: 'clsx38nbl0001vkhlwin9fmt0',
  },
  accessToken: {
    type: 'string',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoib2F1dGgtY2xpZW50In0.fake',
  },
  examples: ['clsx38nbl0001vkhlwin9fmt0'],
};

// ---- 2. A SECRET IS NOT A SENTENCE ----
//
// From packages/features/oauth/services/OAuthService.ts:
//
//     encryption_key_missing: "CALENDSO_ENCRYPTION_KEY is not set"
//
// The NAME matches the credential pattern - it contains `key`. The VALUE is an
// error message. A name-based guess is allowed to be wrong; what it is not
// allowed to do is ignore a value that could not possibly be a credential, and
// nothing that reads as an English sentence is one.
export const errorMessages = {
  encryption_key_missing: 'CALENDSO_ENCRYPTION_KEY is not set',
  api_key_invalid: 'The API key you provided is not valid for this workspace',
  token_expired: 'Your session token has expired, please sign in again',
  password_too_short: 'Password must be at least 8 characters long',
};

// THE TRAP, and the reason rule 2 counts words rather than banning spaces:
// PASSPHRASES CONTAIN SPACES AND ARE REAL SECRETS.
//
//     password = "correct horse battery staple"
//
// A blanket "a value with a space is not a credential" would silence every
// diceware passphrase in existence - a silence, on the one rule that is 70% of
// this report. So the test is prose-shaped: several words AND an English
// function word (is, the, must, your, please, not) that a passphrase generator
// would never emit. See vulnerable/secrets.ts for the passphrase that must
// still fire.
