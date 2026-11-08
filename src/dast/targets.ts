import { readFileSync } from 'node:fs';
import type { Finding } from '../core/finding.js';

const ZAP_RULE: Record<string, string> = {
    'sql-injection': '40018',
    'xss': '40012',
    'command-injection': '90020',
    'code-injection': '90019',
    'ssrf': '40046',
};

interface Target {
    id: string;
    rule: string;
    zapRule: string;
    file: string;
    from: string;
    param: string;
}

const reportPath = process.argv[2];
if (reportPath === undefined) {
    console.error('usage: node dist/src/dast/targets.js report.json');
    process.exit(1);
}

const report = JSON.parse(readFileSync(reportPath, 'utf8')) as { findings: Finding[] };
const targets: Target[] = [];
let skipped = 0;

for (const f of report.findings) {
    if (f.confidence !== 'flow-verified') continue;
    const zapRule = ZAP_RULE[f.ruleId];
    const source = f.flowPath.find((step) => step.kind === 'source');
    const match = source && /\$_(GET|POST|REQUEST|COOKIE)\[\s*['"]([^'"]+)['"]\s*\]/.exec(source.location.snippet);
    if (zapRule === undefined || !match) {
        skipped++;
        continue;
    }
    targets.push({
        id: `${f.ruleId}:${f.location.file}:${f.location.startLine}`,
        rule: f.ruleId,
        zapRule,
        file: f.location.file,
        from: match[1] ?? '',
        param: match[2] ?? '',
    });
}

console.log(JSON.stringify(targets, null, 2));
console.error(`${targets.length} targets; ${skipped} proven findings skipped (no ZAP rule or no named request input)`);
