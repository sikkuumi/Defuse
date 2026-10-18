import { ALL_RULES } from '../rules/registry.js';
import { LANGUAGES } from '../parse/languages.js';
import type { BenchmarkResult } from './coverage-table.js';
import { BASE_CSS, FOOTER_CSS, NAV_CSS, SERVICE, esc, siteFooter, siteNav } from './site.js';

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
 *     refuse.
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
  /** "Everything in Pro, and:" - the plan below this one. */
  readonly builds?: string;
  readonly features: readonly PlanFeature[];
  readonly cta: { readonly label: string; readonly href: string; readonly primary?: boolean };
}

/** Team is priced per developer with a floor of this many. */
export const TEAM_MIN_SEATS = 5;
const TEAM_PRICE = 49;

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
          name: 'Terminal, browser and CI',
          detail: 'A terminal command, a browser page that scans on your own machine and uploads nothing, JSON output, and SARIF for GitHub code scanning.',
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
      price: { amount: '$19', unit: 'per developer / month' },
      forWhom: 'One developer working through findings over time, on their own machine.',
      builds: 'Everything in Community, and:',
      features: [
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
        note: `From ${TEAM_MIN_SEATS} developers ($${TEAM_PRICE * TEAM_MIN_SEATS} a month). 14-day trial on request.`,
      },
      forWhom: 'A team that wants every pull request checked, and one shared record of what was decided.',
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
    {
      name: 'Business',
      status: 'coming-soon',
      forWhom: 'Organisations that want one yearly price.',
      features: [],
      cta: { label: 'Tell us you need it', href: enquiry('Business') },
    },
    {
      name: 'Enterprise',
      status: 'coming-soon',
      forWhom: 'Large organisations with their own terms and reviews.',
      features: [],
      cta: { label: 'Tell us you need it', href: enquiry('Enterprise') },
    },
  ];
}

function planCard(p: Plan): string {
  if (p.status === 'coming-soon') {
    return `      <div class="plan soon">
        <div class="pname">${esc(p.name)}</div>
        <div class="tag">Coming soon</div>
        <p class="who">${esc(p.forWhom)}</p>
        <p class="who">Not available yet. If you need it, say so - it will be shaped around real requests rather than guessed at.</p>
        <a class="pbtn" href="${esc(p.cta.href)}">${esc(p.cta.label)}</a>
      </div>`;
  }
  const price = p.price!;
  return `      <div class="plan glass">
        <div class="pname">${esc(p.name)}</div>
        <div class="pricebox">
          <div class="amount">${esc(price.amount)}</div>
          <div class="unit">${esc(price.unit)}</div>
          ${price.note ? `<div class="pnote">${esc(price.note)}</div>` : ''}
        </div>
        <p class="who">${esc(p.forWhom)}</p>
        ${p.builds ? `<div class="builds">${esc(p.builds)}</div>` : ''}
        <ul class="feats">
${p.features.map((f) => `          <li><b>${esc(f.name)}</b><span>${esc(f.detail)}</span></li>`).join('\n')}
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

  /* ---------- the plans ---------- */
  .plans{display:grid;grid-template-columns:1fr;gap:18px;margin-top:8px}
  @media(min-width:960px){.plans{grid-template-columns:repeat(3,1fr);gap:20px}}
  .plan{display:flex;flex-direction:column;padding:30px 28px 28px;border-radius:16px}
  .pname{font-family:"IBM Plex Mono",monospace;font-size:13px;letter-spacing:2.2px;text-transform:uppercase;color:var(--white)}
  .amount{margin-top:18px;font-weight:700;font-size:clamp(38px,4vw,48px);letter-spacing:-1.6px;line-height:1;color:var(--white)}
  .unit{margin-top:8px;font-family:"IBM Plex Mono",monospace;font-size:12.5px;color:var(--mute)}
  .pnote{margin-top:6px;font-size:13.5px;color:var(--mute)}
  .who{margin-top:18px;font-size:15px;color:var(--mute)}
  /* Side by side, the price blocks and the one-line descriptions are given the same height, so the
     feature lists start on one line across the three cards. */
  @media(min-width:960px){.plan.glass .pricebox{min-height:150px}.plan.glass .who{min-height:4.8em}}
  .builds{margin-top:22px;padding-top:18px;border-top:1px solid var(--hair);font-family:"IBM Plex Mono",monospace;font-size:12px;letter-spacing:1px;color:var(--faint)}
  .feats{list-style:none;margin:14px 0 26px;flex-grow:1}
  .feats li{padding:12px 0;border-bottom:1px solid var(--hair)}
  .feats li:last-child{border-bottom:0}
  .feats b{display:block;font-weight:500;font-size:15px;color:var(--white)}
  .feats span{display:block;margin-top:4px;font-size:14px;line-height:1.55;color:var(--mute)}
  .pbtn{display:block;text-align:center;font-family:"IBM Plex Mono",monospace;font-size:14px;color:var(--white);
    border:1px solid var(--line);border-radius:999px;padding:12px 20px;transition:background 220ms ease,border-color 220ms ease}
  .pbtn:hover{background:var(--glass);border-color:var(--brand-lift);color:var(--white)}
  .pbtn.primary{background:var(--brand);border-color:var(--brand)}
  .pbtn.primary:hover{background:var(--brand-lift)}
  .pbtn:focus-visible{outline:2px solid var(--brand-soft);outline-offset:3px}

  /* Not built yet: drawn as an outline with no price, so it cannot be mistaken for something on sale. */
  .soonrow{display:grid;grid-template-columns:1fr;gap:18px;margin-top:18px}
  @media(min-width:760px){.soonrow{grid-template-columns:1fr 1fr;gap:20px}}
  .plan.soon{border:1px solid var(--hair);background:transparent;padding:26px 28px}
  .plan.soon .pname{color:var(--mute)}
  .plan.soon .who{margin-top:10px;font-size:14.5px}
  .plan.soon .pbtn{margin-top:20px;align-self:flex-start;color:var(--mute)}
  .tag{margin-top:14px;align-self:flex-start;font-family:"IBM Plex Mono",monospace;font-size:11.5px;letter-spacing:1.4px;text-transform:uppercase;color:var(--mute);border:1px solid var(--line);border-radius:6px;padding:4px 9px}

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
    <div class="soonrow">
${soon.map(planCard).join('\n')}
    </div>
    <p class="mono" style="margin-top:22px;font-size:12.5px;color:var(--faint);max-width:none">Prices in US dollars.
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
    <p style="margin-top:14px">Would rather have a person run it for you? The security check is
      ${esc(SERVICE.price.toLowerCase())} per project - <a href="index.html#check">see what it includes</a>.</p>
  </div>
</section>

<div class="wrap">
${siteFooter()}
</div>

</body>
</html>
`;
}
