import { ALL_RULES } from '../rules/registry.js';
import { LANGUAGES } from '../parse/languages.js';
import type { BenchmarkResult, LabelSplitResult } from './coverage-table.js';

/**
 * THE SITE IS GENERATED, FOR THE SAME REASON THE README BLOCKS ARE.
 * ================================================================
 *
 * A marketing page is the single most likely thing in any project to carry a
 * number the code moved past two months ago. It is written once, in a hurry,
 * by someone who knows the figures by heart - and then it sits there being
 * quietly wrong while the engine improves underneath it.
 *
 * This tool cannot afford that. Its whole claim is that it does not say more
 * than it knows, and a landing page boasting a precision figure the benchmark
 * has since revised would be exactly the failure it sells against.
 *
 * So every figure on the page comes from `docs/benchmark-result.json` and
 * `docs/label-split-result.json`, the rule and language counts come from the
 * registry, and `npm test` fails if `docs/index.html` disagrees with what this
 * function produces. The page cannot be wrong without the build going red.
 *
 * Nothing here is hand-typed except the prose - and the prose makes no
 * quantitative claims at all, which is deliberate rather than lazy.
 *
 * ON THE LOOK, since it is unusual for this category:
 *
 * The two labels are told apart by TEMPERATURE, not by a traffic light. Ice
 * (#8FD3FF) is proven, rose (#E58FA8) is guessed. Green-and-amber is what every
 * other scanner uses, and it fails twice: it dies in grayscale, and red/green
 * colour blindness is the most common kind there is. Cold against warm survives
 * both, and the two are reinforced by shape as well - a filled dot for proven, a
 * hollow ring for guessed - so the distinction never rests on colour alone.
 *
 * Motion earns its place exactly once: on the proof section the trace draws
 * itself, source to sink, one hop at a time. That animation is the product. It
 * is also fully disabled under `prefers-reduced-motion`.
 */

const esc = (s: string): string =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export function renderSite(benchmark: BenchmarkResult, split: LabelSplitResult): string {
  const verified = split.tiers.find((t) => t.label.startsWith('flow-verified'));
  const signature = split.tiers.find((t) => t.label.startsWith('signature-only'));
  if (!verified || !signature) throw new Error('label split is missing a tier');

  const ruleCount = ALL_RULES.length;
  const languageNames = LANGUAGES.map((l) => l.displayName);
  const exclDecoy = (
    (verified.tp / (verified.tp + verified.nonDecoyFalsePositives)) *
    100
  ).toFixed(1);
  const gap = (
    Number.parseFloat(verified.precision) - Number.parseFloat(signature.precision)
  ).toFixed(1);

  /* Rule/language pairs the engine declares it does not implement. Counted, not
     asserted - if a rule gains a language this number drops on its own. */
  let notImplemented = 0;
  for (const rule of ALL_RULES) {
    for (const language of LANGUAGES) {
      if (rule.support[language.id]?.status === 'not-implemented') notImplemented++;
    }
  }

  /* Bar widths are the measured percentages, so the chart cannot disagree with
     the number printed beside it. */
  const bar = (p: string): string => Number.parseFloat(p).toFixed(1);

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Defuse — static analysis that says what it proved</title>
<meta name="description" content="A multi-language SAST scanner that labels every finding proven or guessed, prints the path behind every claim, and publishes what it did not check.">
<meta property="og:title" content="Defuse">
<meta property="og:description" content="Every scanner says possible. This one says what it proved.">
<meta property="og:type" content="website">
<meta name="theme-color" content="#0B0A10">
<link rel="icon" href="defuse-mark.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=JetBrains+Mono:wght@400;500&family=Sora:wght@300;400;600&display=swap" rel="stylesheet">
<style>
  :root{
    --void:#0B0A10; --panel:#14121C; --deep:#0F0D16; --line:#262233; --hair:#1C1926;
    --ink:#EDEAF4; --mute:#9A94AD; --faint:#6B6580;
    --violet:#9F6BFF; --ice:#8FD3FF; --rose:#E58FA8; --alarm:#FF3D5A;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  html{scroll-behavior:smooth}
  body{
    background:var(--void); color:var(--ink);
    font-family:"Sora",system-ui,sans-serif; font-weight:300; line-height:1.6;
    -webkit-font-smoothing:antialiased; overflow-x:hidden;
  }
  .wrap{max-width:1180px;margin:0 auto;padding:0 28px}
  a{color:var(--ice);text-decoration:none;transition:color 220ms ease}
  a:hover{color:#C4E8FF}
  .serif{font-family:"Instrument Serif",Georgia,serif;font-weight:400}
  .mono,code{font-family:"JetBrains Mono",ui-monospace,monospace}
  .kicker{font-family:"JetBrains Mono",monospace;font-size:12px;letter-spacing:3.2px;text-transform:uppercase;color:var(--faint);display:flex;align-items:center;gap:13px}
  h2{font-family:"Instrument Serif",Georgia,serif;font-weight:400;font-size:clamp(34px,5.4vw,62px);line-height:1.04;letter-spacing:-1px;margin:20px 0 0}
  p{color:var(--mute);max-width:64ch}
  section{padding:clamp(64px,9vw,120px) 0;border-top:1px solid var(--hair);position:relative}

  /* ---------- motion ---------- */
  @keyframes sweep{0%{transform:translateY(-180px);opacity:0}12%{opacity:.5}88%{opacity:.5}100%{transform:translateY(120vh);opacity:0}}
  @keyframes rise{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
  @keyframes pulse{0%,100%{opacity:.3}50%{opacity:1}}
  @keyframes grow{0%{transform:scaleY(0);opacity:0}7%{opacity:1}52%{transform:scaleY(1)}92%{transform:scaleY(1);opacity:1}100%{transform:scaleY(1);opacity:0}}
  @keyframes node{0%,8%{opacity:.16;transform:scale(.76)}20%{opacity:1;transform:scale(1)}92%{opacity:1;transform:scale(1)}100%{opacity:.16;transform:scale(.76)}}
  @keyframes halo{0%,8%{box-shadow:0 0 0 0 rgba(143,211,255,0)}22%{box-shadow:0 0 0 12px rgba(143,211,255,.12)}46%{box-shadow:0 0 0 20px rgba(143,211,255,0)}100%{box-shadow:0 0 0 0 rgba(143,211,255,0)}}
  @keyframes barIn{from{transform:scaleX(0)}to{transform:scaleX(1)}}
  .rise{animation:rise 900ms cubic-bezier(.22,.9,.24,1) both}
  .spine{transform-origin:top center;animation:grow 7s cubic-bezier(.5,0,.2,1) infinite}
  .n{animation:node 7s cubic-bezier(.4,0,.2,1) infinite}
  .n.halo{animation:node 7s cubic-bezier(.4,0,.2,1) infinite,halo 7s cubic-bezier(.4,0,.2,1) infinite}
  .barfill{transform-origin:left center;animation:barIn 1500ms cubic-bezier(.22,.9,.24,1) both}
  @media (prefers-reduced-motion: reduce){
    html{scroll-behavior:auto}
    .rise,.spine,.n,.n.halo,.barfill,.sweep,.dot{animation:none!important;opacity:1!important;transform:none!important}
  }

  /* ---------- hero ---------- */
  header{position:relative;overflow:hidden;padding:0 0 clamp(60px,8vw,110px)}
  .glow{position:absolute;inset:0;pointer-events:none;background:radial-gradient(900px 520px at 20% 6%,rgba(159,107,255,.15),transparent 68%),radial-gradient(760px 480px at 88% 92%,rgba(143,211,255,.09),transparent 70%)}
  .sweep{position:absolute;left:0;right:0;top:0;height:170px;pointer-events:none;background:linear-gradient(180deg,transparent,rgba(143,211,255,.14),transparent);animation:sweep 9s cubic-bezier(.4,0,.2,1) infinite}
  nav{position:relative;display:flex;align-items:center;gap:20px;padding:30px 0}
  nav img{width:30px;height:auto}
  .word{font-family:"Instrument Serif",Georgia,serif;font-size:28px;color:var(--violet)}
  .navlinks{display:none;gap:26px;margin-left:auto}
  @media(min-width:860px){.navlinks{display:flex}}
  .navlinks a{font-size:14px;color:var(--mute)}
  .ghbtn{margin-left:auto;font-family:"JetBrains Mono",monospace;font-size:13px;color:var(--ink);border:1px solid #332C47;border-radius:999px;padding:11px 20px;transition:background 260ms ease,border-color 260ms ease}
  @media(min-width:860px){.ghbtn{margin-left:8px}}
  .ghbtn:hover{background:#1B1826;border-color:#4A4160;color:var(--ink)}
  h1{font-family:"Instrument Serif",Georgia,serif;font-weight:400;font-size:clamp(46px,8.6vw,104px);line-height:.99;letter-spacing:-1.6px;margin:30px 0 0;max-width:13ch}
  .lede{font-size:clamp(16px,2vw,19px);line-height:1.66;margin-top:32px;max-width:58ch}
  .cmdrow{display:flex;flex-wrap:wrap;align-items:center;gap:16px;margin-top:40px}
  .cmd{font-family:"JetBrains Mono",monospace;font-size:clamp(13px,2vw,16px);background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:17px 24px;word-break:break-all}
  .chips{display:flex;flex-wrap:wrap;gap:14px;margin-top:46px}
  .chip{display:flex;align-items:center;gap:12px;border-radius:999px;padding:12px 22px;transition:transform 320ms cubic-bezier(.22,.9,.24,1)}
  .chip:hover{transform:translateY(-3px)}
  .chip.warm{border:1px solid #4A2E3C;background:rgba(229,143,168,.06)}
  .chip.cold{border:1px solid #22465E;background:rgba(143,211,255,.07)}
  .dot{width:9px;height:9px;border-radius:50%}
  .ring{width:9px;height:9px;border-radius:50%;border:1.5px solid var(--rose)}

  /* ---------- cards ---------- */
  .two{display:grid;gap:24px;margin-top:40px}
  @media(min-width:860px){.two{grid-template-columns:1fr 1fr}}
  .card{background:var(--panel);border-radius:22px;padding:clamp(28px,3.4vw,42px);transition:transform 420ms cubic-bezier(.22,.9,.24,1)}
  .card:hover{transform:translateY(-6px)}
  .card.warm{border:1px solid #3A2733}
  .card.cold{border:1px solid #22465E}
  .quote{font-family:"Instrument Serif",Georgia,serif;font-size:clamp(25px,3.2vw,34px);line-height:1.22;color:var(--ink);margin:26px 0 0}
  .meta{border-top:1px solid var(--hair);margin-top:26px;padding-top:20px;font-family:"JetBrains Mono",monospace;font-size:12px;color:var(--faint);line-height:1.9}

  /* ---------- proof ---------- */
  .proof{display:grid;gap:34px;margin-top:40px}
  @media(min-width:960px){.proof{grid-template-columns:minmax(0,1.05fr) minmax(0,1fr)}}
  .term{background:var(--deep);border:1px solid var(--line);border-radius:22px;overflow:hidden}
  .bar{background:var(--panel);border-bottom:1px solid var(--line);padding:16px 24px;display:flex;align-items:center;gap:9px}
  .bar i{width:10px;height:10px;border-radius:50%;display:block}
  .term .body{padding:30px 26px;font-family:"JetBrains Mono",monospace;font-size:clamp(12px,1.6vw,14px);line-height:2;color:#A8A2B8;overflow-x:auto}
  .trace{background:var(--panel);border:1px solid var(--line);border-radius:22px;padding:clamp(28px,3.4vw,42px);position:relative}
  .spine{position:absolute;left:calc(clamp(28px,3.4vw,42px) + 21px);top:118px;width:2px;height:300px;background:linear-gradient(180deg,var(--rose),var(--ice));border-radius:2px}
  .hop{display:flex;align-items:flex-start;gap:24px}
  .hop + .hop{margin-top:64px}
  .hop .n{width:22px;height:22px;border-radius:50%;background:var(--void);flex-shrink:0;margin-left:10px}

  /* ---------- numbers ---------- */
  .row{display:grid;grid-template-columns:1fr;gap:10px;padding:22px 16px;border-bottom:1px solid #16131F;border-radius:10px;transition:background 300ms ease}
  .row:hover{background:rgba(159,107,255,.05)}
  @media(min-width:860px){.row{grid-template-columns:190px 1fr 80px 80px;gap:22px;align-items:center}}
  .track{flex-grow:1;height:10px;background:#16131F;border-radius:999px;overflow:hidden}
  .track > div{height:10px;border-radius:999px}
  .pc{font-family:"Instrument Serif",Georgia,serif;font-size:clamp(26px,3.4vw,34px);color:var(--ink);min-width:96px}
  .num{font-family:"JetBrains Mono",monospace;font-size:13px;color:var(--mute)}
  @media(min-width:860px){.num{text-align:right}}
  .foot{display:flex;gap:20px;margin-top:44px}
  .foot > .rule{width:3px;flex-shrink:0;background:linear-gradient(180deg,var(--violet),transparent);border-radius:3px}
  .stats{display:grid;grid-template-columns:repeat(2,1fr);gap:14px;margin-top:38px}
  @media(min-width:720px){.stats{grid-template-columns:repeat(4,1fr)}}
  .stat{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:22px;text-align:center}
  .stat b{display:block;font-family:"Instrument Serif",Georgia,serif;font-weight:400;font-size:34px;letter-spacing:-.5px}
  .stat span{font-size:13px;color:var(--mute)}

  footer{border-top:1px solid var(--hair);padding:52px 0 76px;display:flex;flex-wrap:wrap;gap:20px;align-items:center;justify-content:space-between}
  .ice{color:var(--ice)} .rose{color:var(--rose)} .alarm{color:var(--alarm)} .vio{color:var(--violet)}
</style>
</head>
<body>

<header>
  <div class="glow"></div>
  <div class="sweep"></div>
  <div class="wrap">
    <nav>
      <img src="defuse-mark.png" alt="">
      <span class="word">Defuse</span>
      <div class="navlinks">
        <a href="#labels">Labels</a>
        <a href="#proof">Proof</a>
        <a href="#numbers">Measurements</a>
        <a href="#gaps">Gaps</a>
      </div>
      <a class="ghbtn" href="https://github.com/sikkuumi/Defuse">github</a>
    </nav>

    <div class="rise" style="padding-top:clamp(40px,7vw,90px)">
      <div class="kicker"><span class="dot" style="background:var(--ice);animation:pulse 2.6s ease-in-out infinite"></span>Static application security testing</div>
      <h1>Every scanner says <em class="rose" style="font-style:italic">possible</em>. This one says what it <span class="ice">proved</span>.</h1>
      <p class="lede">Every finding carries one of two labels, and they are never blended. One matched a
        pattern. The other traced attacker data from source to sink and prints every hop it walked,
        so you can audit the claim instead of believing it.</p>
      <div class="cmdrow">
        <div class="cmd"><span style="color:var(--faint)">$</span>&nbsp; npx github:sikkuumi/Defuse scan .</div>
        <span class="mono" style="font-size:12px;color:var(--faint)">no install · no account · AGPL-3.0</span>
      </div>
      <div class="chips">
        <div class="chip warm"><span class="ring"></span><span class="mono rose" style="font-size:14px">signature-based</span><span style="font-size:13px;color:var(--mute)">a shape that matched</span></div>
        <div class="chip cold"><span class="dot" style="background:var(--ice)"></span><span class="mono ice" style="font-size:14px">flow-verified</span><span style="font-size:13px;color:var(--mute)">a path that was walked</span></div>
      </div>
    </div>
  </div>
</header>

<section id="labels">
  <div class="wrap">
    <div class="kicker">Two labels, never blurred</div>
    <h2>A guess and a proof are<br>not the same sentence.</h2>
    <p style="margin-top:22px">Most tools report everything at one confidence and leave the triage to you.
      The word they hide behind is <em class="rose" style="font-style:italic">possible</em> — and it covers
      both a traced data path and a lucky-looking regex.</p>

    <div class="two">
      <div class="card warm">
        <div style="display:flex;align-items:center;gap:13px"><span class="ring" style="width:11px;height:11px"></span><span class="mono rose" style="font-size:17px">signature-based</span></div>
        <p class="quote">“This code has the <em class="rose" style="font-style:italic">shape</em> of a bug.”</p>
        <p style="margin-top:18px;font-size:15px">A pattern matched in the syntax tree. Data flow was not
          traced. It is a lead worth opening, not a fact — and the report says exactly that, every time.</p>
        <div class="meta">evidence &nbsp;·&nbsp; one matched pattern<br>claim &nbsp;&nbsp;&nbsp;&nbsp;·&nbsp; worth your attention</div>
      </div>
      <div class="card cold">
        <div style="display:flex;align-items:center;gap:13px"><span class="dot" style="width:11px;height:11px;background:var(--ice)"></span><span class="mono ice" style="font-size:17px">flow-verified</span></div>
        <p class="quote">“Attacker data actually <em class="ice" style="font-style:italic">reaches</em> here.”</p>
        <p style="margin-top:18px;font-size:15px">Traced hop by hop, across functions and across files, with
          the whole path printed beside the finding — including the steps where its knowledge ran out.</p>
        <div class="meta">evidence &nbsp;·&nbsp; a printed source&rarr;sink path<br>claim &nbsp;&nbsp;&nbsp;&nbsp;·&nbsp; check it yourself</div>
      </div>
    </div>

    <div style="display:flex;gap:18px;align-items:flex-start;margin-top:44px">
      <svg viewBox="0 0 24 24" style="width:21px;height:21px;flex-shrink:0;margin-top:3px" aria-hidden="true"><path d="M12 3l7 3.5v5c0 4.2-2.9 7.8-7 9-4.1-1.2-7-4.8-7-9v-5z" fill="none" stroke="#9F6BFF" stroke-width="1.5" stroke-linejoin="round"></path></svg>
      <p style="font-size:17px;max-width:70ch">A rule cannot set its own confidence. Only a printed path earns
        the cold one — and that is enforced by the type system, not by a style guide.</p>
    </div>
  </div>
</section>

<section id="proof">
  <div class="wrap">
    <div class="kicker">Every claim ships its working</div>
    <h2>Don’t trust it. <em class="ice" style="font-style:italic">Check</em> it.</h2>

    <div class="proof">
      <div class="term">
        <div class="bar"><i style="background:var(--alarm)"></i><i style="background:var(--rose)"></i><i style="background:var(--ice)"></i><span class="mono" style="font-size:12px;color:var(--faint);margin-left:12px">defuse scan .</span></div>
        <div class="body">
          <div><span class="alarm">CRITICAL</span>&nbsp;&nbsp;<span style="color:var(--faint)">cmdi.c:44</span></div>
          <div style="color:var(--ink)">Attacker-controlled data from <span class="rose">argv[1]</span></div>
          <div style="color:var(--ink)">reaches a shell, which runs the string</div>
          <div style="margin-top:18px">command-injection &nbsp;·&nbsp; CWE-78</div>
          <div><span class="ice">[flow-verified]</span> <span style="color:var(--faint)">— 3 hops, printed below</span></div>
          <div style="margin-top:22px;color:var(--faint)">limitations</div>
          <div style="color:var(--faint);font-size:13px;line-height:1.85">confirms the data flow, not exploitability in<br>production. Does not model memory safety<br>in C: it tracks values, not sizes.</div>
        </div>
      </div>

      <div class="trace">
        <div class="kicker" style="margin-bottom:34px">The path it walked</div>
        <div class="spine"></div>
        <div class="hop">
          <span class="n halo" style="border:2px solid var(--rose)"></span>
          <div><div class="mono rose" style="font-size:15px">argv[1]</div><div style="margin-top:6px;font-size:14px;color:var(--mute)">a command-line argument — the source</div></div>
        </div>
        <div class="hop">
          <span class="n halo" style="border:2px solid #B9A8D8;animation-delay:1.4s,1.4s"></span>
          <div><div class="mono" style="font-size:15px;color:var(--ink)">sprintf(cmd, …)</div><div style="margin-top:6px;font-size:14px;color:var(--mute)">written into <code style="font-size:13px">cmd</code>, unescaped</div></div>
        </div>
        <div class="hop">
          <span class="n halo" style="background:var(--ice);animation-delay:2.8s,2.8s"></span>
          <div><div class="mono ice" style="font-size:15px">system(cmd)</div><div style="margin-top:6px;font-size:14px;color:var(--mute)">arrives at the shell — the sink</div></div>
        </div>
        <p style="margin-top:38px;border-top:1px solid var(--hair);padding-top:20px;font-size:14px">Three hops,
          every one printed. If a hop rests on something the engine could not follow, that hop says so rather
          than being smoothed over.</p>
      </div>
    </div>
  </div>
</section>

<section id="numbers">
  <div class="wrap">
    <div class="kicker">Measured, and published whole</div>
    <h2>What the cold label<br>is actually worth.</h2>
    <p style="margin-top:22px">Scored against OWASP BenchmarkJava, ${benchmark.scored} labelled test cases, on
      engine ${esc(benchmark.engineVersion)} (${esc(split.measuredAt)}). Each label is scored
      <em style="font-style:italic">separately</em>, because one blended figure would be the same averaging this
      tool refuses to do inside a single finding.</p>

    <div style="margin-top:40px">
      <div class="row" style="border-bottom:1px solid var(--hair);padding-bottom:12px">
        <span class="mono" style="font-size:11px;letter-spacing:2.2px;text-transform:uppercase;color:var(--faint)">tier</span>
        <span class="mono" style="font-size:11px;letter-spacing:2.2px;text-transform:uppercase;color:var(--faint)">precision</span>
        <span class="num" style="font-size:11px;letter-spacing:2.2px;text-transform:uppercase;color:var(--faint)">found</span>
        <span class="num" style="font-size:11px;letter-spacing:2.2px;text-transform:uppercase;color:var(--faint)">wrong</span>
      </div>

      <div class="row">
        <span class="mono ice" style="font-size:15px">flow-verified</span>
        <div style="display:flex;align-items:center;gap:18px">
          <div class="track"><div class="barfill" style="width:${bar(verified.precision)}%;background:linear-gradient(90deg,#4E8FBF,#8FD3FF)"></div></div>
          <span class="pc">${esc(verified.precision)}</span>
        </div>
        <span class="num">${verified.tp}</span><span class="num">${verified.fp}</span>
      </div>

      <div class="row">
        <span class="mono rose" style="font-size:15px">signature-based</span>
        <div style="display:flex;align-items:center;gap:18px">
          <div class="track"><div class="barfill" style="width:${bar(signature.precision)}%;background:linear-gradient(90deg,#8A5468,#E58FA8);animation-delay:160ms"></div></div>
          <span class="pc">${esc(signature.precision)}</span>
        </div>
        <span class="num">${signature.tp}</span><span class="num">${signature.fp}</span>
      </div>

      <div class="row">
        <span class="mono" style="font-size:15px;color:var(--mute)">both combined</span>
        <div style="display:flex;align-items:center;gap:18px">
          <div class="track"><div class="barfill" style="width:${bar(benchmark.precision)}%;background:linear-gradient(90deg,#4A3E63,#9F6BFF);animation-delay:320ms"></div></div>
          <span class="pc">${esc(benchmark.precision)}</span>
        </div>
        <span class="num">${benchmark.tp}</span><span class="num">${benchmark.fp}</span>
      </div>
    </div>

    <p style="margin-top:34px;font-size:20px;color:var(--ink);max-width:70ch">The cold label is worth
      <span class="serif ice" style="font-size:30px">${gap}</span> points of precision over the warm one.
      That gap is the entire claim this tool makes, and it is measured here rather than asserted.</p>

    <div class="foot">
      <div class="rule"></div>
      <div>
        <div class="mono vio" style="font-size:11px;letter-spacing:2.4px;text-transform:uppercase">The footnote, printed rather than buried</div>
        <p style="margin-top:14px;font-size:15px;max-width:74ch">${verified.decoyFalsePositives} of the
          ${verified.fp} false positives still wearing the cold label (${esc(verified.decoyShare)}) are the
          benchmark’s own constant-branch decoys — a data path that genuinely exists, inside a branch that can
          never run. That leaves <span style="color:var(--ink)">${verified.nonDecoyFalsePositives}</span>
          ordinary mistakes, which would put <code class="ice" style="font-size:14px">flow-verified</code>
          precision at ${exclDecoy}%. Both numbers are here because neither alone is the truth: the first is
          contaminated by synthetic traps, the second needs cases excluded, and you deserve to see the size of
          that choice rather than inherit it.</p>
      </div>
    </div>
  </div>
</section>

<section id="gaps">
  <div class="wrap">
    <div class="kicker">The part nobody ships</div>
    <h2>It prints what it<br>didn’t check.</h2>
    <p style="margin-top:22px">Every run ends with the rule and language combinations this engine does not
      implement — currently ${notImplemented} of them — each with the real reason, not a placeholder. In C it
      states outright that it does not model memory safety: no buffer overflows, no use-after-free. It tracks
      values, not sizes.</p>
    <p style="margin-top:16px">A gap you can read is a gap you can plan around. A gap you can’t see is the one
      that gets you.</p>

    <div class="stats">
      <div class="stat"><b>${LANGUAGES.length}</b><span>languages</span></div>
      <div class="stat"><b>${ruleCount}</b><span>rules</span></div>
      <div class="stat"><b>${benchmark.filesParsed}</b><span>files scored</span></div>
      <div class="stat"><b>AGPL</b><span>3.0 · or commercial</span></div>
    </div>
    <p class="mono" style="margin-top:24px;font-size:13px;color:var(--faint)">${languageNames.join(' · ')}</p>

    <div style="display:flex;gap:20px;margin-top:44px;border-top:1px solid var(--hair);padding-top:32px">
      <div class="rule" style="width:3px;flex-shrink:0;background:linear-gradient(180deg,var(--violet),transparent);border-radius:3px"></div>
      <div>
        <div class="mono vio" style="font-size:11px;letter-spacing:2.4px;text-transform:uppercase">What it costs</div>
        <p style="margin-top:14px;font-size:15px;max-width:72ch">The scanner is AGPL-3.0 and free. Pointing it at your own
          code — closed-source, proprietary, commercial, any of it — puts no obligation on you whatsoever, and running it
          unmodified inside a company is free and unencumbered. The one obligation attaches if you modify it and then serve
          your modified version to other people over a network, in which case those users are owed your source. If those
          terms do not work for your company, and for some they genuinely do not, the copyright sits in one place and a
          commercial licence can be discussed.</p>
      </div>
    </div>
  </div>
</section>

<div class="wrap">
  <footer>
    <div style="display:flex;align-items:center;gap:14px">
      <img src="defuse-mark.png" alt="" style="width:26px;height:auto">
      <span class="word" style="font-size:22px">Defuse</span>
    </div>
    <div class="mono" style="font-size:13px;color:var(--faint)"><a href="https://github.com/sikkuumi/Defuse">github.com/sikkuumi/Defuse</a> · AGPL-3.0 · commercial licence available</div>
  </footer>
</div>

</body>
</html>
`;
}
