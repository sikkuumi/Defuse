/**
 * WHAT DEFUSE KNOWS ABOUT PHP RELEASES - AND WHEN IT LAST CHECKED.
 * ================================================================
 *
 * Every other check in Defuse reads the code it is given and needs nothing
 * else. This one compares a version number with facts about the world, and
 * facts about the world go stale: a release that is current today is missing a
 * fix next month. So the table carries the date it was checked, and every
 * finding and report built on it prints that date. A stale table is then a
 * visible fact rather than a quiet wrong answer.
 *
 * Every entry was read from php.net on the date below, not from news reports:
 *   https://www.php.net/supported-versions.php   support dates, 8.2 - 8.5
 *   https://www.php.net/eol.php                  end-of-life dates
 *   https://www.php.net/archive/2026             the 21 Oct 2026 security releases
 *
 * TO UPDATE: change the facts, change CHECKED, run `npm test`. The tests pin
 * the table's shape, not today's numbers, so an update is a data change only.
 */

/** The day these facts were read from php.net. ISO date. */
export const PHP_FACTS_CHECKED = '2026-10-28';

export const PHP_FACT_SOURCES: readonly string[] = [
  'https://www.php.net/supported-versions.php',
  'https://www.php.net/eol.php',
  'https://www.php.net/archive/2026',
];

/**
 * Branches still receiving security fixes, and until when. A branch past its
 * date on the day of the scan is treated as end of life - the scan date
 * decides that, not the table date, so 8.2 turns out of support on 1 Jan 2027
 * without anyone editing this file.
 */
export const PHP_SECURITY_UNTIL: Readonly<Record<string, string>> = {
  '8.2': '2026-12-31',
  '8.3': '2027-12-31',
  '8.4': '2028-12-31',
  '8.5': '2029-12-31',
};

/** Branches php.net lists as end of life, with the date support ended. */
export const PHP_END_OF_LIFE: Readonly<Record<string, string>> = {
  '8.1': '2025-12-31',
  '8.0': '2023-11-26',
  '7.4': '2022-11-28',
  '7.3': '2021-12-06',
  '7.2': '2020-11-30',
  '7.1': '2019-12-01',
  '7.0': '2019-01-10',
  '5.6': '2018-12-31',
  '5.5': '2016-07-21',
  '5.4': '2015-09-03',
  '5.3': '2014-08-14',
  '5.2': '2011-01-06',
  '5.1': '2006-08-24',
  '5.0': '2005-09-05',
};

export interface PhpAdvisory {
  /** The name it is known by, for a reader who has seen the news. */
  readonly name: string;
  readonly cves: readonly string[];
  /** ISO date of the fixing releases. */
  readonly published: string;
  /** One plain sentence: what an attacker gets. */
  readonly impact: string;
  /** Per supported branch, the first release with the fix. */
  readonly fixedIn: Readonly<Record<string, string>>;
  /** The oldest branch reported affected. Older branches are end of life anyway. */
  readonly oldestAffected: string;
}

/**
 * Only advisories severe enough to change what a reader should do today. This
 * is not a vulnerability database and does not pretend to be one - see the
 * limitations text in runtime-version.ts. One entry is a deliberate start.
 */
export const PHP_ADVISORIES: readonly PhpAdvisory[] = [
  {
    name: 'PHP2Shell',
    cves: ['CVE-2026-109618', 'CVE-2026-109619'],
    published: '2026-10-21',
    impact:
      'two critical flaws in PHP itself that can let an attacker run code on the server ' +
      'without logging in, reported exploited in the wild',
    fixedIn: { '8.2': '8.2.35', '8.3': '8.3.36', '8.4': '8.4.27', '8.5': '8.5.12' },
    oldestAffected: '5.4',
  },
];
