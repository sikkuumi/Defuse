// EXPECT-NONE
//
// PUBLISHED DOCUMENTATION EXAMPLES ARE NOT CREDENTIALS.
//
// `AKIAIOSFODNN7EXAMPLE` is not a leaked AWS key. It is the string AWS itself
// prints throughout its own documentation, chosen to match the key FORMAT while
// being guaranteed never to authenticate anything. The same is true of the
// secret key below, which AWS pairs with it in every example it publishes.
//
// The scanner found one of these in this project's own UI demo panel and
// reported "AWS access key id hardcoded" - critical severity, rotate this key.
// There was no key and nothing to rotate. That is not a noisy true positive
// with the severity dialled too high, it is a false statement, and the whole
// argument for this tool is that it does not make those.
//
// The allowlist behind this is narrow on purpose: a value must match a vendor
// key format AND end in EXAMPLE (AWS's own convention) or have its random
// portion filled with obvious placeholder runs. The odds of a real key landing
// there by chance are about one in a trillion. The gap is written into the
// rule's `limitations` text so a reader knows it exists.

const docsExample = {
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
};

// The filler-digit convention vendors use in quickstarts, same reasoning.
const quickstart = {
  stripe: 'sk_test_0000000000000000000000',
  aws: 'AKIA000000000000EXAM',
};

module.exports = { docsExample, quickstart };

// `credentials` matches the credential naming pattern, and these are fixed
// values from the fetch specification. Found on a self-scan, inside a vendored
// parser runtime, reported twice as a hardcoded credential.
export function load(url) {
  return fetch(url, { credentials: 'same-origin', mode: 'cors', redirect: 'follow' });
}
