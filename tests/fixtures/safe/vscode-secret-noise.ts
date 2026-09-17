// EXPECT-NONE
//
// WHAT 191 "SECRETS" IN VS CODE ACTUALLY WERE.
//
// A full scan of Microsoft's VS Code - 3,816 files - reported 221 findings, and
// 191 of them were hardcoded-secret. Not one was a credential. Reading them in
// bulk sorted them into two shapes, and each shape is a sentence the rule could
// have said to itself and didn't.

/*
 * SHAPE 1: THE VALUE NAMES THE KIND OF CREDENTIAL IT STANDS IN FOR.
 *
 * Sixty-eight findings on `token`/`accessToken`, fourteen on
 * `clientSecret`/`apiKey`, all from one test file, all this shape. A real
 * secret does not contain the word "secret". When a lowercase hyphenated value
 * ends in the very noun its variable name uses, it is a stand-in written by a
 * human to be readable in a test failure - the opposite of a generated key.
 *
 * This is narrower than "reject short lowercase words", which was tried once
 * before and had to be reverted: it dropped `password = 'configpass'` and
 * `SECRET_KEY = 'config'`, which are weak credentials but are credentials. Both
 * of those are single words with no separator and no credential noun inside
 * them, so both still report. The separator and the self-naming are the signal.
 */
const auth = {
	accessToken: 'exact-token',
	refreshToken: 'wrong-token',
	clientSecret: 'notion-client-secret',
	apiKey: 'new-api-key',
	connectionToken: 'test-token',
	secretValue: 'old-api-key',
	// This one arrived from the other direction. It was the asserted POSITIVE in
	// vulnerable/secrets.js, .go and .java - three fixtures insisting the scanner
	// must report it - and adding the rule above turned all three red. The suite
	// was right to fail and the assertion was wrong: a string that says "not a
	// real password" is not a real password, and reporting it would be a false
	// positive in any repository that contained it. Kept here so the behaviour
	// stays tested rather than merely deleted.
	dbPassword: 'hunter2-not-a-real-password',
};

/*
 * SHAPE 2: A CAMELCASE IDENTIFIER IS NOT A HIGH-ENTROPY SECRET.
 *
 * Thirty-five findings, every one a settings key, command id, experiment name
 * or storage key. They reached the ENTROPY path - the weakest of the three
 * signals, and the one that admits in its own reasoning text that it is "a
 * randomness heuristic, not an identification". Shannon entropy cannot tell
 * `didNotEnableEditSessionsWhenPrompted` from a base64 key, but shape can:
 * credentials contain digits or punctuation, and this is twenty-nine letters
 * and nothing else.
 *
 * Restricted to the entropy path on purpose. `password = 'ReallyStrongPhrase'`
 * is also pure camelCase and is also a bad credential - it goes down the NAME
 * path instead, where this guard does not apply, and it still reports as high.
 * The same string assigned to `label` correctly says nothing. Checked both ways
 * before this file was written, because a guard that silences the name path too
 * would make this fixture pass for the wrong reason.
 */
const settings = {
	key: 'enablePreviewFromQuickOpen',
	name: 'ChatToolsEligibleForAutoApproval',
	id: 'promptCodingAgentActionOverlay',
	type: 'historyItemChangeViewModel',
	outcome: 'didNotEnableEditSessionsWhenPrompted',
	contextKey: 'inWorkspaceSymbolsPicker',
};

export { auth, settings };
