import { readFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import type { Finding } from '../core/finding.js';

export const ZAP_RULE: Record<string, string> = {
    'sql-injection': '40018',
    'xss': '40012',
    'command-injection': '90020',
    'code-injection': '90019',
    'ssrf': '40046',
};

export interface Target {
    id: string;
    rule: string;
    zapRule: string;
    file: string;
    url: string;
    cookie: string;
    from: string;
    param: string;
}

// Where the site runs, where its code sits on disk, and which file is served at which address.
// Each rule is [pattern, url, cookie?] on the file path; the first rule that matches wins.
// A pattern should match the WHOLE path (^...$): the url and cookie are built by replacing what it matched.
export interface UrlConfig {
    base: string;
    root: string;
    rules: [string, string, string?][];
}

export interface BuiltTargets {
    targets: Target[];
    skipped: number; // proven findings with no ZAP rule or no named request input
    noUrl: number; // proven, testable findings whose file matched no URL rule
}

// No matching rule means no URL: a file that is only included by other files has no address of its own.
function toAddress(config: UrlConfig, file: string): { url: string; cookie: string } | undefined {
    const relative = path.relative(config.root, file).replaceAll('\\', '/');
    for (const [pattern, url, cookie] of config.rules) {
        const rule = new RegExp(pattern);
        if (rule.test(relative)) {
            return {
                url: new URL(relative.replace(rule, url), config.base).href,
                cookie: cookie === undefined ? '' : relative.replace(rule, cookie),
            };
        }
    }
    return undefined;
}

// Defuse's proven findings -> the list of addresses ZAP should try. A finding is a target only
// when it is flow-verified, has a ZAP rule, names a request input, and its file has a URL.
export function buildTargets(report: { findings: Finding[] }, config: UrlConfig): BuiltTargets {
    const targets: Target[] = [];
    let skipped = 0;
    let noUrl = 0;

    for (const f of report.findings) {
        if (f.confidence !== 'flow-verified') continue;
        const zapRule = ZAP_RULE[f.ruleId];
        const source = f.flowPath.find((step) => step.kind === 'source');
        const match = source && /\$_(GET|POST|REQUEST|COOKIE)\[\s*['"]([^'"]+)['"]\s*\]/.exec(source.location.snippet);
        if (zapRule === undefined || !match) {
            skipped++;
            continue;
        }
        const address = toAddress(config, f.location.file);
        if (address === undefined) {
            noUrl++;
            continue;
        }
        targets.push({
            id: `${f.ruleId}:${f.location.file}:${f.location.startLine}`,
            rule: f.ruleId,
            zapRule,
            file: f.location.file,
            url: address.url,
            cookie: address.cookie,
            from: match[1] ?? '',
            param: match[2] ?? '',
        });
    }

    return { targets, skipped, noUrl };
}

function main(): void {
    const [reportPath, configPath] = process.argv.slice(2);
    if (reportPath === undefined || configPath === undefined) {
        console.error('usage: node dist/src/dast/targets.js report.json urls.json');
        process.exit(1);
    }
    const report = JSON.parse(readFileSync(reportPath, 'utf8')) as { findings: Finding[] };
    const config = JSON.parse(readFileSync(configPath, 'utf8')) as UrlConfig;
    const { targets, skipped, noUrl } = buildTargets(report, config);
    console.log(JSON.stringify(targets, null, 2));
    console.error(
        `${targets.length} targets; ${skipped} proven findings skipped (no ZAP rule or no named request input); ${noUrl} skipped (no URL rule matched the file)`,
    );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    main();
}
