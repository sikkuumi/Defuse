import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { buildTargets, type Target, type UrlConfig } from './targets.js';
import type { Finding } from '../core/finding.js';

/**
 * STEP TWO OF THE DAST ADD-ON: hand the targets to ZAP, put each verdict next to
 * the finding it came from.
 *
 * targets.ts turned Defuse's proven (flow-verified) findings into a list of
 * addresses to probe. This file drives OWASP ZAP's active scanner against each
 * one, restricted to the single ZAP rule that matches the finding's category,
 * and reports ONE verdict per target:
 *
 *   confirmed       ZAP reproduced the bug at that URL with its own payloads.
 *   not-confirmed   ZAP ran the rule and raised nothing. THE FINDING STANDS.
 *   could-not-test  ZAP never got to render a verdict (input isn't a request
 *                   parameter, the scan errored, or it timed out).
 *
 * The honesty rule from finding.ts carries over: not-confirmed is NOT cleared.
 * A dynamic scanner that can't reach a code path proves nothing about it, so a
 * finding Defuse traced by data flow keeps its status unless ZAP positively
 * reproduces it. ZAP only ever ADDS confidence; it never subtracts a finding.
 *
 * Every target appears in the output exactly once. The run asserts
 * results.length === targets.length so nothing is dropped silently.
 */

type Verdict = 'confirmed' | 'not-confirmed' | 'could-not-test';

interface Result {
    id: string;
    rule: string;
    zapRule: string;
    url: string;
    from: string;
    param: string;
    zap: Verdict;
    detail: string;
}

interface Outcome {
    zap: Verdict;
    detail: string;
}

// ZAP's one-call active scan needs the whole request, not just the param, because
// the scanner replays it and only mutates the one field. DVWA hides each bug behind
// its submit button (Submit=Submit), so without that in the seed the vulnerable
// branch never runs. `trigger` carries those extra seed fields; it is calibration
// the generic model can't see, so it lives in the config, not here.
interface Config extends UrlConfig {
    trigger?: string;
}

// Which HTTP methods carry the tainted input. $_REQUEST is GET or POST, and a page
// often guards one while reading the other ($_REQUEST['ip'] behind an isset($_POST['Submit'])),
// so a REQUEST source has to be tried both ways. A COOKIE source is not a request
// parameter this harness can mutate (the Cookie header is pinned for auth), so it is
// reported could-not-test, never not-confirmed.
function methods(from: string): ('GET' | 'POST')[] {
    if (from === 'POST') return ['POST'];
    if (from === 'GET') return ['GET'];
    if (from === 'REQUEST') return ['GET', 'POST'];
    return [];
}

// One scan covers every target that attacks the same spot the same way.
export function groupKey(t: Target): string {
    return [t.zapRule, t.from, t.url, t.param, t.cookie].join('|');
}

// confirmed iff ZAP raised at least one alert of the finding's own rule.
export function classify(zapRule: string, alertPluginIds: string[]): Verdict {
    return alertPluginIds.includes(zapRule) ? 'confirmed' : 'not-confirmed';
}

// Put each ZAP outcome next to its target by id. A target with no outcome (a
// group that never ran) becomes could-not-test, never a dropped row.
export function joinResults(targets: Target[], byKey: Map<string, Outcome>): Result[] {
    return targets.map((t) => {
        const outcome = byKey.get(groupKey(t)) ?? { zap: 'could-not-test' as const, detail: 'no scan ran for this target' };
        return { id: t.id, rule: t.rule, zapRule: t.zapRule, url: t.url, from: t.from, param: t.param, ...outcome };
    });
}

const ZAP = process.env.ZAP ?? 'http://localhost:8080';
const AUTH = process.env.DAST_COOKIE ?? ''; // e.g. "PHPSESSID=abc"; combined with each target's security cookie
const POLL_MS = 3000;
const SCAN_TIMEOUT_MS = Number(process.env.DAST_SCAN_TIMEOUT_MS ?? 300_000);
const RULE_DESC = 'defuse-dast-cookie';

async function zap(apiPath: string, params: Record<string, string> = {}): Promise<Record<string, unknown>> {
    const url = new URL(`/JSON/${apiPath}/`, ZAP);
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    const res = await fetch(url);
    const body = (await res.json()) as Record<string, unknown>;
    if (typeof body.code === 'string' && typeof body.message === 'string') {
        throw new Error(`ZAP ${apiPath}: ${body.message} (${body.code})`);
    }
    return body;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function setCookie(cookie: string): Promise<void> {
    await zap('replacer/action/removeRule', { description: RULE_DESC }).catch(() => undefined);
    if (cookie === '') return;
    await zap('replacer/action/addRule', {
        description: RULE_DESC,
        enabled: 'true',
        matchType: 'REQ_HEADER',
        matchString: 'Cookie',
        matchRegex: 'false',
        replacement: cookie,
    });
}

// One method against one target. confirmed / not-confirmed come from ZAP; a thrown
// ZAP error becomes could-not-test.
async function scanOnce(t: Target, verb: 'GET' | 'POST', trigger: string): Promise<Outcome> {
    try {
        const cookie = [AUTH, t.cookie].filter(Boolean).join('; ');
        await setCookie(cookie);
        const seedParams = [`${t.param}=test`, trigger].filter(Boolean).join('&');

        // Seed the request so the URL is in ZAP's tree (the scan errors otherwise) and so
        // the vulnerable branch actually runs before the scanner starts mutating the param.
        let scanUrl = t.url;
        let postData = '';
        if (verb === 'GET') {
            scanUrl = `${t.url}?${seedParams}`;
            await zap('core/action/accessUrl', { url: scanUrl, followRedirects: 'false' });
        } else {
            postData = seedParams;
            const { pathname, host } = new URL(t.url);
            const req =
                `POST ${pathname} HTTP/1.1\r\n` +
                `Host: ${host}\r\n` +
                (cookie ? `Cookie: ${cookie}\r\n` : '') +
                `Content-Type: application/x-www-form-urlencoded\r\n` +
                `Content-Length: ${Buffer.byteLength(postData)}\r\n\r\n${postData}`;
            await zap('core/action/sendRequest', { request: req, followRedirects: 'false' });
        }

        // Only the finding's own rule runs. The policy is global state, so groups go
        // one at a time. ponytail: sequential scans, parallelise per-rule policies if it's ever too slow.
        await zap('ascan/action/disableAllScanners', { scanPolicyName: '' });
        await zap('ascan/action/enableScanners', { ids: t.zapRule, scanPolicyName: '' });

        const started = await zap('ascan/action/scan', {
            url: scanUrl,
            method: verb,
            postData,
            recurse: 'false',
            inScopeOnly: 'false',
        });
        const scanId = String(started.scan);

        const deadline = Date.now() + SCAN_TIMEOUT_MS;
        for (;;) {
            const status = String((await zap('ascan/view/status', { scanId })).status);
            if (status === '100') break;
            if (Date.now() > deadline) {
                await zap('ascan/action/stop', { scanId }).catch(() => undefined);
                return { zap: 'could-not-test', detail: `scan timed out after ${SCAN_TIMEOUT_MS / 1000}s` };
            }
            await sleep(POLL_MS);
        }

        const alertIds = (await zap('ascan/view/alertsIds', { scanId })).alertsIds as string[];
        const pluginIds: string[] = [];
        for (const id of alertIds) {
            const alert = (await zap('core/view/alert', { id })).alert as { pluginId?: string | number } | undefined;
            if (alert?.pluginId !== undefined) pluginIds.push(String(alert.pluginId));
        }
        const verdict = classify(t.zapRule, pluginIds);
        const hits = pluginIds.filter((p) => p === t.zapRule).length;
        return {
            zap: verdict,
            detail: verdict === 'confirmed' ? `ZAP rule ${t.zapRule} raised ${hits} alert(s) via ${verb}` : `ZAP rule ${t.zapRule} ran via ${verb} and raised none`,
        };
    } catch (e) {
        return { zap: 'could-not-test', detail: `${verb}: ${(e as Error).message}` };
    }
}

// A target may need more than one method (REQUEST). confirmed wins; otherwise
// not-confirmed if any method actually ran; could-not-test only if none could.
async function scanGroup(t: Target, trigger: string): Promise<Outcome> {
    const verbs = methods(t.from);
    if (verbs.length === 0) {
        return { zap: 'could-not-test', detail: `input comes from a ${t.from.toLowerCase()}, not a request parameter this scan can mutate` };
    }
    const outcomes: Outcome[] = [];
    for (const verb of verbs) {
        const outcome = await scanOnce(t, verb, trigger);
        if (outcome.zap === 'confirmed') return outcome;
        outcomes.push(outcome);
    }
    return outcomes.find((o) => o.zap === 'not-confirmed') ?? outcomes[0]!;
}

async function main(): Promise<void> {
    const [reportPath, configPath] = process.argv.slice(2);
    if (reportPath === undefined || configPath === undefined) {
        console.error('usage: DAST_COOKIE=PHPSESSID=... node dist/src/dast/zap.js report.json urls.json');
        process.exit(1);
    }
    const report = JSON.parse(readFileSync(reportPath, 'utf8')) as { findings: Finding[] };
    const config = JSON.parse(readFileSync(configPath, 'utf8')) as Config;
    const { targets, skipped, noUrl } = buildTargets(report, config);
    const trigger = config.trigger ?? '';

    // One scan per group; its outcome fills every target in the group.
    const byKey = new Map<string, Outcome>();
    let done = 0;
    for (const t of targets) {
        const key = groupKey(t);
        if (byKey.has(key)) continue;
        process.stderr.write(`[${++done}] ${t.rule} ${t.from} ${t.url} (${t.param}) ... `);
        const outcome = await scanGroup(t, trigger);
        byKey.set(key, outcome);
        process.stderr.write(`${outcome.zap}\n`);
    }

    const results = joinResults(targets, byKey);
    if (results.length !== targets.length) {
        throw new Error(`dropped targets: ${targets.length} in, ${results.length} out`);
    }

    console.log(JSON.stringify(results, null, 2));

    const n = (v: Verdict): number => results.filter((r) => r.zap === v).length;
    console.error(
        `\n${results.length} findings tested: ${n('confirmed')} confirmed, ${n('not-confirmed')} not confirmed, ${n('could-not-test')} could not test.` +
            `\nBefore ZAP: ${skipped} proven findings had no ZAP rule or named input, ${noUrl} had no URL.` +
            `\nA not-confirmed finding stays a finding: ZAP reproducing nothing does not clear what Defuse traced.`,
    );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    void main();
}
