import { ALL_RULES } from '../rules/registry.js';
import { LANGUAGES } from '../parse/languages.js';
import type { BenchmarkResult } from './coverage-table.js';
import { BASE_CSS, FOOTER_CSS, NAV_CSS, esc, siteFooter, siteNav } from './site.js';

/**
 * THE PRICING PAGE
 * ================
 *
 * Generated like the landing page, and held to the same rule: it may not say
 * more than is true today.
 *
 *   - Every feature listed under a plan EXISTS. Nothing planned is listed as
 *     if it were built; a plan that is not built yet is shown as "coming soon"
 *     with no price and no feature list.
 *   - Numbers come from the registry and the measurement files, not from the
 *     prose, so `npm test` fails if the page and the engine disagree.
 *   - No "most popular" badge. There is nothing to be popular among yet, and a
 *     badge that says otherwise is the kind of claim this project exists to
 *     refuse. The cards do carry a badge, because the design has a place for
 *     one - and it holds a FACT about the plan ("Open source", "5+ developers"),
 *     never a ranking.
 *   - How buying works is said plainly: there is no checkout. A plan is set up
 *     by hand after someone asks.
 *
 * The paid tools are Defuse Team, a separate private program that reads the
 * scanner's JSON. They organise findings; they never re-decide one. That is
 * stated on the page, because it is the promise a buyer most needs.
 */

/** Where a plan enquiry goes: a public GitHub issue form, .github/ISSUE_TEMPLATE/plan-enquiry.yml. */
const ENQUIRY_URL = 'https://github.com/Sikkuumi/Defuse/issues/new?template=plan-enquiry.yml';
const enquiry = (plan: string): string => `${ENQUIRY_URL}&title=${encodeURIComponent(`Plan enquiry: ${plan}`)}`;

export interface PlanFeature {
  readonly name: string;
  readonly detail: string;
}

export interface Plan {
  readonly name: string;
  readonly status: 'available' | 'coming-soon';
  /** Shown only for an available plan. */
  readonly price?: { readonly amount: string; readonly unit: string; readonly note?: string };
  readonly forWhom: string;
  /**
   * A fact about the plan, shown in the corner of its card. A fact, never a
   * ranking: "open source", "from 5 developers". See the note above on badges.
   */
  readonly badge?: string;
  /** "Everything in Pro, and:" - the plan below this one. */
  readonly builds?: string;
  readonly features: readonly PlanFeature[];
  readonly cta: { readonly label: string; readonly href: string; readonly primary?: boolean };
}

/** Team is priced per developer with a floor of this many. */
export const TEAM_MIN_SEATS = 5;
const TEAM_PRICE = 69;

/** Rule/language pairs the engine declares it does not implement - counted, never typed in. */
function countNotImplemented(): number {
  let n = 0;
  for (const rule of ALL_RULES) {
    for (const language of LANGUAGES) {
      if (rule.support[language.id]?.status === 'not-implemented') n++;
    }
  }
  return n;
}

export function plans(): Plan[] {
  const notImplemented = countNotImplemented();
  return [
    {
      name: 'Community',
      status: 'available',
      price: { amount: 'Free', unit: 'for everyone, for good', note: 'Open source, AGPL-3.0' },
      forWhom: 'Anyone scanning their own code, on their own machine or in their own CI.',
      badge: 'Open source',
      builds: 'Included:',
      features: [
        {
          name: 'The scanner',
          detail: `${LANGUAGES.length} languages and ${ALL_RULES.length} rules. Data flow is traced in every language, into other functions, and into other files in every language but PHP.`,
        },
        {
          name: 'Two labels on every finding',
          detail: 'Proven, with the path from source to sink printed; or to review, a matched pattern that was not traced. Never blended into one score.',
        },
        {
          name: 'What it did not check',
          detail: `Every run lists the rule and language pairs it does not cover - ${notImplemented} today - each with its reason.`,
        },
        {
          name: 'Terminal, JSON and CI',
          detail: 'A terminal command, JSON output, and SARIF for GitHub code scanning. The point-and-click browser app is in Pro.',
        },
        {
          name: 'Client report',
          detail: 'One HTML file for a client or a manager, with the proven problems, what to review and what was not checked. Prints to PDF.',
        },
      ],
      cta: { label: 'Run it now', href: 'https://github.com/Sikkuumi/Defuse#readme' },
    },
    {
      name: 'Pro',
      status: 'available',
      price: { amount: '$29', unit: 'per developer / month' },
      forWhom: 'One developer working through findings over time, on their own machine.',
      badge: 'One developer',
      builds: 'Everything in Community, and:',
      features: [
        {
          name: 'The browser app',
          detail: 'A point-and-click page that scans on your own machine and uploads nothing - the same engine as the terminal, run from a browser instead of a command line.',
        },
        {
          name: 'New problems only',
          detail: 'Compare two scans and see only what a change added. A line that moved is matched, not called new; what disappeared is "no longer reported", never "fixed".',
        },
        {
          name: 'Trend dashboard',
          detail: 'Proven and to-review counts across your scans, in one file that opens offline. Where the scanner itself changed, the point is marked with the reason.',
        },
      ],
      cta: { label: 'Ask for Pro', href: enquiry('Pro') },
    },
    {
      name: 'Team',
      status: 'available',
      price: {
        amount: `$${TEAM_PRICE}`,
        unit: 'per developer / month',
        note: `From ${TEAM_MIN_SEATS} developers ($${TEAM_PRICE * TEAM_MIN_SEATS} a month).`,
      },
      forWhom: 'A team that wants every pull request checked, and one shared record of what was decided.',
      badge: `${TEAM_MIN_SEATS}+ developers`,
      builds: 'Everything in Pro, and:',
      features: [
        {
          name: 'Pull-request check',
          detail: 'Each pull request is scanned against its base. One comment, updated on every push, lists only what it adds, and the check fails only on new problems at the level you set.',
        },
        {
          name: 'Shared triage',
          detail: 'False alarms and accepted risks are marked in the repository with a reason and a name. A mark never hides a finding, ends when the code changes, and a pull request cannot approve its own.',
        },
        {
          name: 'Automatic history',
          detail: 'One scan a day kept on its own branch, and the trend dashboard rebuilt on every push to main. On private repositories, unless you choose otherwise.',
        },
      ],
      cta: { label: 'Ask for Team', href: enquiry('Team'), primary: true },
    },
    /*
     * BUSINESS AND ENTERPRISE - the agreed plan (2026-11-08), built in two moves.
     *
     * Move 1 (this): they go on the page as "coming soon" - no price, no
     * features - because none of their features exist yet and this page may
     * only list what is built (npm test enforces it). The decided numbers are
     * recorded here so a later session needs nothing but the code:
     *
     *   Business   $129 per developer / month, floor of 10 developers.
     *              Badge when live: "10+ developers".
     *   Enterprise contract only - price is "Contact us", never a number.
     *
     * Move 2 (a later session): BUILD the Business features, then flip Business
     * to status 'available' with price $129 the moment it has one real feature.
     * Buildable in this repo, in order: portfolio dashboard across repos ->
     * findings API / bulk export -> org-wide policy (one fail-gate for all
     * repos) -> scheduled DAST across apps. SSO, seats/roles and priority
     * support need auth and support infra, so they stay coming-soon until real.
     * Enterprise is self-hosted / air-gapped, SSO+SCIM, a compliance pack
     * (SOC 2 / ISO 27001 / PCI evidence, signed audit trail), private custom
     * rules and data-residency controls - contract and infra work, listed only
     * as it ships.
     *
     * DAST is a PAID capability too (Pro and Team), but it is kept off the live
     * cards for the same reason: only the engine (src/dast) exists, not a
     * product a buyer can use. When DAST is wired as a feature, it is added as
     * Pro "run a dynamic confirmation against your app" + newly-confirmed-only,
     * and Team "dynamic confirmation on each pull request" + shared record. A
     * confirmation never creates or clears a finding, so "the scanner is free"
     * still holds: it confirms what SAST already proved.
     */
    {
      name: 'Business',
      status: 'coming-soon',
      forWhom: 'A company with many teams and repositories that wants one view and one policy across all of them.',
      features: [],
      cta: { label: 'Tell us you need it', href: enquiry('Business') },
    },
    {
      name: 'Enterprise',
      status: 'coming-soon',
      forWhom: 'A large or regulated organisation that runs the scanner inside its own network and answers to auditors.',
      features: [],
      cta: { label: 'Contact us', href: enquiry('Enterprise') },
    },
  ];
}

/** Lucide's "check" icon (ISC licence), inline so the page still calls nobody. */
const CHECK_ICON =
  '<svg class="tick" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.25" ' +
  'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>';

function planCard(p: Plan): string {
  if (p.status === 'coming-soon') {
    return `      <div class="plan soon">
        <h3 class="pname">${esc(p.name)}</h3>
        <div class="tag">Coming soon</div>
        <p class="who">${esc(p.forWhom)}</p>
        <p class="who">Not available yet. If you need it, say so - it will be shaped around real requests rather than guessed at.</p>
        <a class="pbtn" href="${esc(p.cta.href)}">${esc(p.cta.label)}</a>
      </div>`;
  }
  const price = p.price!;
  // One card: a header (name, who it is for, a fact in the corner), the price
  // on one line, the features as a checked list, and one full-width button.
  // The plan whose button is the primary one gets a brand-coloured ring.
  return `      <div class="plan glass${p.cta.primary ? ' featured' : ''}">
        <div class="phead">
          <h3 class="pname">${esc(p.name)}</h3>
          ${p.badge ? `<span class="badge">${esc(p.badge)}</span>` : ''}
          <p class="who">${esc(p.forWhom)}</p>
        </div>
        <div class="pricebox">
          <div class="priceline"><span class="amount">${esc(price.amount)}</span><span class="unit">${esc(price.unit)}</span></div>
          ${price.note ? `<div class="pnote">${esc(price.note)}</div>` : ''}
        </div>
        ${p.builds ? `<div class="builds">${esc(p.builds)}</div>` : ''}
        <ul class="feats">
${p.features.map((f) => `          <li>${CHECK_ICON}<div><b>${esc(f.name)}</b><span>${esc(f.detail)}</span></div></li>`).join('\n')}
        </ul>
        <a class="pbtn${p.cta.primary ? ' primary' : ''}" href="${esc(p.cta.href)}">${esc(p.cta.label)}</a>
      </div>`;
}

export function renderPricing(benchmark: BenchmarkResult): string {
  // The precision figures stay on the main page, beside the footnote that says what they do and do not
  // promise. Quoted alone on a page that sells, a 100% would read as a promise about your code.
  const all = plans();
  const available = all.filter((p) => p.status === 'available');
  const soon = all.filter((p) => p.status === 'coming-soon');
  const notImplemented = countNotImplemented();

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Defuse — plans and pricing</title>
<meta name="description" content="Defuse is free and open source. Paid plans add tools for working through findings over time and across a team - and never change what the scanner finds.">
<meta property="og:title" content="Defuse — plans and pricing">
<meta property="og:description" content="The scanner is free. Paid plans organise findings; they never re-decide one.">
<meta property="og:type" content="website">
<meta name="theme-color" content="#262626">
<link rel="icon" href="defuse-mark.png">
<style>
${BASE_CSS}
  header{position:relative;padding:0 0 clamp(40px,6vw,72px)}
${NAV_CSS}
  h1{font-size:clamp(38px,6.4vw,72px);letter-spacing:-2px;margin:22px 0 0;max-width:17ch}
  .lede{margin-top:22px;font-size:clamp(16px,1.9vw,19px);font-weight:300;max-width:62ch}

  /* ---------- the plans ----------
     Card layout after shadcn's pricing card: a header with a fact badge in the
     corner, the price on one line, a checked feature list, one full-width
     button, and a ring on the plan whose button is the primary one. Drawn
     with this site's own colours, fonts and glass surface - no framework. */
  .plans{display:grid;grid-template-columns:1fr;gap:20px;margin-top:8px;max-width:420px;margin-left:auto;margin-right:auto}
  @media(min-width:960px){.plans{grid-template-columns:repeat(3,minmax(0,1fr));gap:22px;max-width:none}}
  .plan{position:relative;display:flex;flex-direction:column;border-radius:12px;box-shadow:0 1px 2px rgba(0,0,0,.25)}
  .plan.featured{border-color:var(--brand);box-shadow:0 0 0 1px var(--brand),0 18px 50px -24px rgba(121,44,247,.55)}
  .phead{position:relative;padding:24px 24px 0}
  .pname{font-size:24px;font-weight:600;letter-spacing:-.4px;line-height:1.1;color:var(--white);padding-right:120px}
  .badge{position:absolute;top:24px;right:24px;font-family:"IBM Plex Mono",monospace;font-size:11.5px;font-weight:500;letter-spacing:.3px;
    color:var(--brand-soft);background:rgba(121,44,247,.14);border:1px solid rgba(121,44,247,.35);border-radius:999px;padding:3px 10px;white-space:nowrap}
  .plan.featured .badge{color:var(--white);background:var(--brand);border-color:var(--brand)}
  .who{margin-top:8px;font-size:14px;line-height:1.55;color:var(--mute)}
  .pricebox{padding:22px 24px 0}
  .priceline{display:flex;align-items:baseline;flex-wrap:wrap;gap:4px 8px}
  .amount{font-weight:600;font-size:clamp(32px,3.2vw,38px);letter-spacing:-1.2px;line-height:1;color:var(--white);font-variant-numeric:tabular-nums}
  .unit{font-size:14px;color:var(--mute)}
  .pnote{margin-top:8px;font-size:13px;color:var(--faint)}
  /* Side by side, the headers and price blocks are given the same height, so
     the feature lists start on one line across the three cards. */
  @media(min-width:960px){.plan .phead{min-height:130px}.plan .pricebox{min-height:92px}}
  .builds{margin:20px 24px 0;padding-top:16px;border-top:1px solid var(--hair);font-family:"IBM Plex Mono",monospace;font-size:12px;letter-spacing:1px;color:var(--faint)}
  .feats{list-style:none;margin:12px 24px 24px;flex-grow:1;display:flex;flex-direction:column;gap:14px}
  .feats li{display:flex;gap:10px;align-items:flex-start}
  .feats .tick{flex-shrink:0;margin-top:3px;color:var(--brand-soft)}
  .feats b{display:block;font-weight:500;font-size:14.5px;color:var(--white)}
  .feats span{display:block;margin-top:3px;font-size:13.5px;line-height:1.55;color:var(--mute)}
  .pbtn{display:flex;align-items:center;justify-content:center;height:42px;margin:0 24px 24px;font-size:14px;font-weight:500;color:var(--white);
    background:var(--glass);border:1px solid var(--line);border-radius:8px;padding:0 16px;transition:background 200ms ease,border-color 200ms ease}
  .pbtn:hover{background:rgba(245,245,245,.07);border-color:var(--brand-lift);color:var(--white)}
  .pbtn.primary{background:var(--brand);border-color:var(--brand)}
  .pbtn.primary:hover{background:var(--brand-lift);border-color:var(--brand-lift)}
  .pbtn:focus-visible{outline:2px solid var(--brand-soft);outline-offset:3px}

  /* Not built yet: drawn as an outline with no price, so it cannot be mistaken
     for something on sale. None are listed today - see plans(). */
  .soonrow{display:grid;grid-template-columns:1fr;gap:18px;margin-top:18px}
  @media(min-width:760px){.soonrow{grid-template-columns:1fr 1fr;gap:20px}}
  .plan.soon{border:1px solid var(--hair);border-radius:12px;background:transparent;padding:24px;box-shadow:none}
  .plan.soon .pname{color:var(--mute);font-size:20px;padding-right:0}
  .plan.soon .who{margin-top:10px}
  .plan.soon .pbtn{margin:20px 0 0;align-self:flex-start;color:var(--mute)}
  .tag{margin-top:12px;align-self:flex-start;font-family:"IBM Plex Mono",monospace;font-size:11.5px;letter-spacing:1.4px;text-transform:uppercase;color:var(--mute);border:1px solid var(--line);border-radius:6px;padding:4px 9px}

  /* ---------- promises, effort, buying ---------- */
  .three{display:grid;grid-template-columns:1fr;gap:18px;margin-top:40px}
  @media(min-width:900px){.three{grid-template-columns:repeat(3,1fr);gap:20px}}
  .three .glass{padding:26px 24px}
  .three h3{font-size:19px;font-weight:500;letter-spacing:-.3px;color:var(--white)}
  .three p{margin-top:10px;font-size:14.5px}
  .stats{display:grid;grid-template-columns:repeat(2,1fr);gap:14px;margin-top:40px}
  @media(min-width:760px){.stats{grid-template-columns:repeat(4,1fr);gap:18px}}
  .stat{padding:24px 22px;border-radius:14px}
  .stat b{display:block;font-weight:700;font-size:clamp(26px,3.2vw,34px);letter-spacing:-1px}
  .stat span{display:block;margin-top:5px;font-family:"IBM Plex Mono",monospace;font-size:11.5px;letter-spacing:1.4px;text-transform:uppercase;color:var(--faint)}
  .steps{margin:26px 0 0 20px;color:var(--mute);max-width:70ch}
  .steps li{margin:10px 0}
  .steps strong{color:var(--white);font-weight:500}
${FOOTER_CSS}
</style>
</head>
<body>

<header>
  <div class="wrap">
${siteNav('pricing')}
    <div class="kicker" style="margin-top:clamp(30px,5vw,64px)">Plans and pricing</div>
    <h1>The scanner is free. Teams pay for the tools around it.</h1>
    <p class="lede">Community is the whole scanner, open source, with nothing held back. The paid plans add
      tools for working through findings over time and across a team. They read what the scanner found;
      they never change what it found or how it is labelled.</p>
  </div>
</header>

<section id="plans" style="padding-top:clamp(36px,5vw,56px)">
  <div class="wrap">
    <div class="plans">
${available.map(planCard).join('\n')}
    </div>
${soon.length > 0 ? `    <div class="soonrow">\n${soon.map(planCard).join('\n')}\n    </div>\n` : ''}    <p class="mono" style="margin-top:22px;font-size:12.5px;color:var(--faint);max-width:none">Prices in US dollars.
      There is no checkout yet - see how buying works below.</p>
  </div>
</section>

<section id="promise">
  <div class="wrap">
    <div class="kicker">The same in every plan</div>
    <h2>Paying never makes<br>a guess look like a proof.</h2>
    <div class="three">
      <div class="glass">
        <h3>The scanner decides</h3>
        <p>The paid tools read the scanner's own output. They organise findings - compare them, mark them,
          chart them - and never re-decide or relabel one.</p>
      </div>
      <div class="glass">
        <h3>Nothing is hidden</h3>
        <p>A finding your team marks is still listed, with the reason beside it. A comparison never calls a
          finding fixed; it says "no longer reported", because that is all it can know.</p>
      </div>
      <div class="glass">
        <h3>Your code stays with you</h3>
        <p>Everything runs on your machine or in your own CI. There is no account to make and nothing is
          uploaded anywhere.</p>
      </div>
    </div>
  </div>
</section>

<section id="work">
  <div class="wrap">
    <div class="kicker">The work behind it</div>
    <h2>Measured, and<br>published whole.</h2>
    <p style="margin-top:20px">The engine is scored against OWASP BenchmarkJava, with the two labels scored
      separately. Safety rules are switched off one at a time to prove a test notices. And the scanner
      is run on large real projects - Django, WordPress and VS Code among them - to find what synthetic tests
      miss. <a href="index.html#numbers">The measurements, and what they do not promise, are on the main page.</a></p>
    <div class="stats">
      <div class="stat glass"><b>${benchmark.scored.toLocaleString('en-US')}</b><span>benchmark cases scored</span></div>
      <div class="stat glass"><b>${ALL_RULES.length}</b><span>rules</span></div>
      <div class="stat glass"><b>${LANGUAGES.length}</b><span>languages traced</span></div>
      <div class="stat glass"><b>${notImplemented}</b><span>gaps listed by name</span></div>
    </div>
  </div>
</section>

<section id="buying">
  <div class="wrap">
    <div class="kicker">How buying works, today</div>
    <h2>Set up by hand,<br>for now.</h2>
    <ol class="steps">
      <li><strong>Ask</strong> using the button on the plan you want. It opens a short request form on GitHub.</li>
      <li><strong>Hear back</strong> privately, with the licence terms and an invoice.</li>
      <li><strong>Get the package</strong> - a file your machine or your CI installs next to the scanner.</li>
    </ol>
    <p style="margin-top:20px">The request form is public. Write only the plan, the number of developers and
      how to reach you privately - never code, keys or company details.</p>
  </div>
</section>

<div class="wrap">
${siteFooter()}
</div>

</body>
</html>
`;
}
