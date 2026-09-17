/**
 * THE RULE REGISTRY
 *
 * One list, one place. Adding a rule = write the file, import it, add it here.
 * The engine imports nothing but this.
 *
 * `validateRegistry()` runs on every scan. It refuses to start if a rule breaks
 * the honesty contract - for example by declaring a language as `implemented`
 * with an empty note. A rule that cannot say what it does not cover has not
 * finished thinking, and shipping it silently is the failure mode this whole
 * project is a reaction to.
 */

import type { LanguageId } from '../parse/languages.js';
import { LANGUAGES } from '../parse/languages.js';
import type { Rule } from './contract.js';
import { codeInjectionRule } from './code-injection.js';
import { commandInjectionRule } from './command-injection.js';
import { hardcodedSecretRule } from './hardcoded-secret.js';
import { sqlInjectionRule } from './sql-injection.js';
import { ssrfRule } from './ssrf.js';
import { unsafeDeserializationRule } from './unsafe-deserialization.js';
import { weakHashRule } from './weak-hash.js';
import { formatStringRule } from './format-string.js';
import { unboundedCopyRule } from './unbounded-copy.js';
import { xssRule } from './xss.js';

export const ALL_RULES: readonly Rule[] = [
  sqlInjectionRule,
  commandInjectionRule,
  formatStringRule,
  unboundedCopyRule,
  codeInjectionRule,
  xssRule,
  ssrfRule,
  unsafeDeserializationRule,
  hardcodedSecretRule,
  weakHashRule,
];

export function rulesForLanguage(language: LanguageId): Rule[] {
  return ALL_RULES.filter((rule) => {
    const support = rule.support[language];
    return support !== undefined && support.status !== 'not-implemented';
  });
}

export function getRule(id: string): Rule | undefined {
  return ALL_RULES.find((rule) => rule.id === id);
}

/** Throws if the registry violates the project's own honesty requirements. */
export function validateRegistry(): void {
  const problems: string[] = [];
  const seen = new Set<string>();

  for (const rule of ALL_RULES) {
    if (seen.has(rule.id)) problems.push(`duplicate rule id: ${rule.id}`);
    seen.add(rule.id);

    if (rule.limitations.trim().length < 20) {
      problems.push(`${rule.id}: 'limitations' is missing or too short to be useful`);
    }
    if (rule.explanation.trim().length < 40) {
      problems.push(`${rule.id}: 'explanation' is missing or too short to teach anything`);
    }
    for (const language of LANGUAGES) {
      const support = rule.support[language.id];
      if (!support) continue;
      if (support.note.trim().length < 15) {
        problems.push(
          `${rule.id}/${language.id}: support note is empty - a gap must be described, not implied`,
        );
      }
      if (support.status !== 'implemented' && !/PARTIAL|NOT|not covered|missing/i.test(support.note)) {
        problems.push(
          `${rule.id}/${language.id}: status is '${support.status}' but the note does not say what is missing`,
        );
      }
    }
  }

  if (problems.length > 0) {
    throw new Error(
      `Rule registry violates the honesty contract:\n  - ${problems.join('\n  - ')}`,
    );
  }
}
