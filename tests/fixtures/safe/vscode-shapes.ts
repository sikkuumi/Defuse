// EXPECT-NONE
//
// THREE FALSE POSITIVES FROM SCANNING MICROSOFT'S VS CODE, KEPT AS A FLOOR.
//
// A 28-file scan of `vscode/src/vs/server` produced eleven findings. Three were
// wrong, and each was wrong in a way that would come back the moment somebody
// widened a list without thinking about what else lives in that list. So the
// shapes live here, where widening the list fails the suite instead.

/*
 * 1. THE SINK LIST THAT WASN'T SCOPED.
 *
 * The tracer followed `req.url` through eighteen hops - a URL parse, a
 * searchParams lookup, an array index, two method calls, a substring, a
 * template - and every hop was correct. Then it handed the value to:
 *
 *     this._consumers.get(consumer)
 *
 * and called it a flow-verified SSRF. That is a Map. The deserialization and
 * code-injection rules had both been given careful receiver rules; SSRF had
 * been handed a bare method list containing `get`, `post` and `request` - three
 * of the most common method names that exist. Eighteen correct hops delivered
 * to the wrong door is still the wrong answer, and labelling it "flow-verified"
 * makes it a worse answer than a signature-based guess would have been.
 *
 * `http.get`, `axios.get` and bare `fetch` still fire; see the vulnerable
 * ssrf.js fixture, which is the other half of this test.
 */
const consumers = new Map<string, number>();
const sessions: Record<string, number> = {};

export function track(request: { query: { consumer: string } }): number {
	const consumer = request.query.consumer;
	const current = consumers.get(consumer) ?? 0;
	consumers.set(consumer, current + 1);
	return sessions[consumer] ?? current;
}

/*
 * 2. A SUBRESOURCE INTEGRITY HASH IS A PUBLIC FACT, NOT A SECRET.
 *
 * `sha256-` prefixed base64 is high-entropy by construction and sits next to a
 * variable name with "SHA" in it, so the name-based path read it as a key. It
 * is the opposite of a key: it is published so that BROWSERS can check it, and
 * it appears verbatim in the HTML it protects.
 */
export const webWorkerIframeScriptSHA = 'sha256-2Q+j4hfT09+1+imS46J2YlkCtHWQt0/BE79PXjJ0ZJ8=';

/*
 * 3. THE NAME OF AN ENVIRONMENT VARIABLE IS NOT THE VALUE OF ONE.
 *
 * Every codebase that reads config from the environment first has to write the
 * variable's name down somewhere, and the convention for that name is
 * SCREAMING_SNAKE_CASE. Assigning that name to a constant called
 * "...ConnectionToken" put the word "token" beside a long opaque-looking string
 * and the secret rule bit. The string is a label; the secret is whatever the
 * environment puts in it, which is not in the file.
 */
export const connectionTokenEnvVar = 'VSCODE_AGENT_HOST_BRIDGE_CONNECTION_TOKEN';
export const connectionToken = process.env[connectionTokenEnvVar];
