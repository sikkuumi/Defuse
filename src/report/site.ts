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
 *
 * ON THE LOOK.
 * ============
 *
 * ONE ACCENT, AND IT IS THE MARK'S OWN.
 *
 * #792CF7 is not a purple chosen to go with the logo - it is the exact value
 * sampled out of `docs/defuse-mark.png`, and the same value the Instagram
 * carousel uses. An earlier version of this page ran on #9F6BFF, a lighter
 * purple that matched nothing, which is how a brand ends up with three
 * different primaries and no one able to say which is right.
 *
 * The ground (#262626), the raised surface (#2C2C2C), the white (#F5F5F5) and
 * the muted text (#A8A8A8) are all measured out of the carousel for the same
 * reason. The site and the social page are now one thing.
 *
 * PROVEN VERSUS GUESSED IS CARRIED BY VALUE AND SHAPE, NOT BY HUE.
 *
 * This replaces an ice/rose temperature split, and the replacement is better
 * rather than merely different. Any hue pair - green/amber, blue/pink - fails
 * for someone: red-green colour blindness is the most common kind there is,
 * and every one of them dies in a grayscale print. So the distinction is now
 * carried three ways at once, none of which is colour:
 *
 *     flow-verified   solid filled dot   white text    solid border
 *     signature-based hollow ring        muted text    dashed border
 *
 * Filled against hollow. Bright against dim. Unbroken against broken. That
 * survives grayscale, every form of colour blindness, and a bad monitor - and
 * it reads as what it means, because a proof is substantial and a guess is an
 * outline. Purple stays a brand colour and never becomes a status colour,
 * which is the mistake that made the previous palette need four accents.
 *
 * GLASS, HONESTLY.
 *
 * Surfaces are translucent over the grid, so the panels read as laid on the
 * page rather than cut into it. Every one also declares a solid base colour
 * underneath, because `backdrop-filter` is the first thing to be switched off
 * on a locked-down machine and a panel that becomes unreadable without it is
 * a decoration pretending to be a layout.
 *
 * MOTION EARNS ITS PLACE ONCE.
 *
 * The trace on the proof section draws itself, source to sink, one hop at a
 * time. That animation IS the product. The glow sweep and the pulsing halos
 * that used to be here were not - they were the house style of every generated
 * landing page on the internet, and they have been removed. Everything that
 * remains is disabled under `prefers-reduced-motion`.
 */

const esc = (s: string): string =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** The install line, in one place - the hero prints it and the button copies it. */
const INSTALL_COMMAND = 'npx github:Sikkuumi/Defuse scan .';

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
<meta name="theme-color" content="#262626">
<link rel="icon" href="defuse-mark.png">
<style>
  /*
   * THE FONTS ARE SERVED FROM THIS ORIGIN. THE PAGE CALLS NOBODY.
   *
   * This used to be a stylesheet link to fonts.googleapis.com, which meant the
   * homepage of a security tool made a request to a third party before it had
   * drawn anything - handing that third party the visitor's IP address and
   * user agent on the way. The people most likely to open devtools on this
   * page are exactly the people who would notice, and they would be right to.
   *
   * Six files, about 100KB, latin subsets only. Both families are SIL Open
   * Font License 1.1, which permits redistribution and requires the licence to
   * travel with the files - hence docs/fonts/LICENSE-*.txt, which are served
   * alongside rather than being a gesture.
   *
   * font-display:swap draws the text immediately in the fallback and repaints
   * when the real face arrives. The alternative, block, hides the heading until
   * the font loads, and a blank hero is a worse failure than a brief reflow.
   */
  @font-face{font-family:"Space Grotesk";src:url("fonts/space-grotesk-latin-300-normal.woff2") format("woff2");font-weight:300;font-style:normal;font-display:swap}
  @font-face{font-family:"Space Grotesk";src:url("fonts/space-grotesk-latin-400-normal.woff2") format("woff2");font-weight:400;font-style:normal;font-display:swap}
  @font-face{font-family:"Space Grotesk";src:url("fonts/space-grotesk-latin-500-normal.woff2") format("woff2");font-weight:500;font-style:normal;font-display:swap}
  @font-face{font-family:"Space Grotesk";src:url("fonts/space-grotesk-latin-700-normal.woff2") format("woff2");font-weight:700;font-style:normal;font-display:swap}
  @font-face{font-family:"IBM Plex Mono";src:url("fonts/ibm-plex-mono-latin-400-normal.woff2") format("woff2");font-weight:400;font-style:normal;font-display:swap}
  @font-face{font-family:"IBM Plex Mono";src:url("fonts/ibm-plex-mono-latin-500-normal.woff2") format("woff2");font-weight:500;font-style:normal;font-display:swap}

  :root{
    /* Ground and surfaces, sampled from the Instagram carousel. */
    --bg:#262626; --panel:#2C2C2C; --raised:#2F2F2F;
    --white:#F5F5F5; --mute:#A8A8A8; --faint:#6E6E6E;
    /* One accent, three tints. #792CF7 is the mark's own value; the lighter two
       exist only so that text on this ground clears contrast - 792CF7 sits at
       3.4:1, which is fine for a 40px heading and not fine for a 14px line. */
    --brand:#792CF7; --brand-lift:#9153F7; --brand-soft:#A87BFF;
    --line:rgba(245,245,245,.10); --hair:rgba(245,245,245,.06);
    --glass:rgba(245,245,245,.035);
  }
  *{box-sizing:border-box;margin:0;padding:0}
  html{scroll-behavior:smooth}
  body{
    background:var(--bg); color:var(--white);
    font-family:"Space Grotesk",system-ui,sans-serif; font-weight:400; line-height:1.6;
    -webkit-font-smoothing:antialiased; overflow-x:hidden;
    /* The 34px grid from the carousel, at the faintest weight that still reads. */
    background-image:
      linear-gradient(rgba(245,245,245,.020) 1px,transparent 1px),
      linear-gradient(90deg,rgba(245,245,245,.020) 1px,transparent 1px);
    background-size:34px 34px;
  }
  .wrap{max-width:1140px;margin:0 auto;padding:0 28px}
  a{color:var(--brand-soft);text-decoration:none;transition:color 200ms ease}
  a:hover{color:var(--white)}
  .mono,code{font-family:"IBM Plex Mono",ui-monospace,monospace}
  .kicker{font-family:"IBM Plex Mono",monospace;font-size:12px;letter-spacing:2.6px;text-transform:uppercase;color:var(--faint)}
  h1,h2,h3{font-weight:700;letter-spacing:-.9px;line-height:1.06}
  h2{font-size:clamp(32px,4.6vw,52px);margin:18px 0 0}
  p{color:var(--mute);max-width:66ch}
  section{padding:clamp(60px,8vw,104px) 0;border-top:1px solid var(--hair);position:relative}

  /* ---------- glass ---------- */
  /* Every glass surface names --panel first, so the layout survives with
     backdrop-filter switched off or unsupported. */
  .glass{
    background:var(--panel); background:linear-gradient(180deg,var(--glass),rgba(245,245,245,.012)),var(--panel);
    -webkit-backdrop-filter:blur(16px) saturate(118%); backdrop-filter:blur(16px) saturate(118%);
    border:1px solid var(--line); border-radius:16px;
  }

  /* ---------- motion ---------- */
  @keyframes rise{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
  /*
   * THE TRACE RUNS ON ONE CLOCK.
   *
   * It used to run on four. Each node shared a single "node" keyframe set and
   * was staggered with animation-delay: 0s, 1.4s, 2.8s. That is not a stagger,
   * and measuring it showed two separate faults.
   *
   * An animation-delay delays the START of the loop. Until it elapses the
   * element renders in its ordinary un-animated state - fully opaque - so on
   * load nodes 2 and 3 sat at opacity 1 while node 1 was still dark, then
   * snapped down to the 0% keyframe when their delay ran out. The dots went
   * OUT in sequence instead of lighting UP in sequence, which is the exact
   * opposite of the thing this animation exists to show.
   *
   * And because a delay shifts the whole loop, each element restarted at a
   * different moment: sampled at 7.3s the spine had reset to nothing while
   * nodes 2 and 3 were still lit from the previous pass. After one cycle the
   * four elements were permanently incoherent.
   *
   * Now the stagger lives in the keyframes and every element runs the same 7s
   * period with no delay, so they reset together and the order holds forever.
   * The percentages are the choreography: node 1 lights at 10%, the spine
   * grows from 8% to 46%, and node 3 lights at 46% - the line arrives exactly
   * as the sink does, rather than finishing 0.4s early as it used to.
   */
  @keyframes grow{0%{transform:scaleY(0);opacity:0}8%{transform:scaleY(0);opacity:1}46%,90%{transform:scaleY(1);opacity:1}100%{transform:scaleY(1);opacity:0}}
  @keyframes n1{0%,3%{opacity:.18;transform:scale(.74)}10%,90%{opacity:1;transform:scale(1)}100%{opacity:.18;transform:scale(.74)}}
  @keyframes n2{0%,20%{opacity:.18;transform:scale(.74)}28%,90%{opacity:1;transform:scale(1)}100%{opacity:.18;transform:scale(.74)}}
  @keyframes n3{0%,38%{opacity:.18;transform:scale(.74)}46%,90%{opacity:1;transform:scale(1)}100%{opacity:.18;transform:scale(.74)}}
  @keyframes barIn{from{transform:scaleX(0)}to{transform:scaleX(1)}}
  .rise{animation:rise 780ms cubic-bezier(.22,.9,.24,1) both}
  .spine{transform-origin:top center;animation:grow 7s cubic-bezier(.5,0,.2,1) infinite}
  .n1{animation:n1 7s cubic-bezier(.4,0,.2,1) infinite}
  .n2{animation:n2 7s cubic-bezier(.4,0,.2,1) infinite}
  .n3{animation:n3 7s cubic-bezier(.4,0,.2,1) infinite}
  .barfill{transform-origin:left center;animation:barIn 1400ms cubic-bezier(.22,.9,.24,1) both}

  /* ---------- the ambient field ---------- */
  /*
   * Three soft purple masses that drift behind everything, very slowly.
   *
   * z-index:-1 rather than a stacking fight: the body's background - the grid -
   * is painted onto the canvas before any negative-z-index layer, so the grid
   * stays visible THROUGH these, and all ordinary content stays above them
   * without a single z-index added anywhere else.
   *
   * The periods are 44s, 59s and 71s. They are deliberately not multiples of
   * one another, so the three drifts only return to the same arrangement after
   * about forty minutes - long enough that the motion never reads as a loop,
   * which is the whole difference between ambient and animated. "alternate"
   * eases each one back the way it came instead of snapping to its start.
   *
   * Only transform and opacity are animated. Moving a background-position
   * or animating a blur would repaint a full-screen gradient every frame and
   * make the page stutter while scrolling; a transform is handed to the GPU as
   * a layer and costs essentially nothing.
   *
   * The alpha is low on purpose. At these values the purple lifts the ground by
   * a few percent and never approaches the text, so nothing on the page loses
   * contrast as a mass passes under it.
   */
  .field{position:fixed;inset:0;z-index:-1;pointer-events:none;overflow:hidden}
  .orb{position:absolute;will-change:transform}
  .orb.a{width:72vmax;height:72vmax;left:-16vmax;top:-22vmax;
    background:radial-gradient(circle,rgba(121,44,247,.17),rgba(121,44,247,.05) 40%,transparent 67%);
    animation:driftA 44s ease-in-out infinite alternate}
  .orb.b{width:58vmax;height:58vmax;right:-18vmax;bottom:-16vmax;
    background:radial-gradient(circle,rgba(121,44,247,.13),rgba(145,83,247,.04) 42%,transparent 68%);
    animation:driftB 59s ease-in-out infinite alternate}
  .orb.c{width:46vmax;height:46vmax;left:52%;top:28%;
    background:radial-gradient(circle,rgba(145,83,247,.09),transparent 64%);
    animation:driftC 71s ease-in-out infinite alternate}
  @keyframes driftA{from{transform:translate3d(0,0,0) scale(1)}to{transform:translate3d(7vw,5vh,0) scale(1.14)}}
  @keyframes driftB{from{transform:translate3d(0,0,0) scale(1.08)}to{transform:translate3d(-6vw,-4vh,0) scale(1)}}
  @keyframes driftC{from{transform:translate3d(0,0,0) scale(.94);opacity:.75}to{transform:translate3d(-5vw,6vh,0) scale(1.1);opacity:1}}

  @media (prefers-reduced-motion: reduce){
    html{scroll-behavior:auto}
    .rise,.spine,.n,.barfill{animation:none!important;opacity:1!important;transform:none!important}
    .card{transition:none!important}
    /* The field stays - it is colour, not motion - but it stops moving. */
    .orb{animation:none!important}
  }

  /* ---------- nav + hero ---------- */
  /* The header no longer carries its own gradient - the ambient field above
     covers the whole page, and two purple washes stacked in the same corner
     read as a smudge rather than as depth. */
  header{position:relative;padding:0 0 clamp(54px,7vw,92px)}
  nav{position:relative;display:flex;align-items:center;gap:18px;padding:26px 0}
  nav img{width:29px;height:auto}
  .word{font-weight:700;font-size:25px;letter-spacing:-.6px;color:var(--brand-lift)}
  .navlinks{display:none;gap:30px;margin-left:26px}
  .navlinks a{font-size:14px;color:var(--mute)}
  .navlinks a:hover{color:var(--white)}
  @media(min-width:880px){.navlinks{display:flex}}
  .ghbtn{margin-left:auto;font-family:"IBM Plex Mono",monospace;font-size:13px;color:var(--white);border:1px solid var(--line);border-radius:999px;padding:10px 19px;transition:background 220ms ease,border-color 220ms ease}
  .ghbtn:hover{background:var(--glass);border-color:var(--brand-lift);color:var(--white)}

  .hero{position:relative;padding-top:clamp(38px,6vw,84px)}
  h1{font-size:clamp(40px,7.4vw,86px);letter-spacing:-2.2px;margin:22px 0 0;max-width:15ch}
  .lede{margin-top:24px;font-size:clamp(16px,1.9vw,19px);font-weight:300;max-width:60ch}

  /* ---------- the command, and its copy control ---------- */
  .cmdrow{margin-top:34px;display:flex;flex-wrap:wrap;gap:14px;align-items:center;max-width:100%}
  /* min-width:0 on both the box and the text is what actually lets the command
     scroll inside its own panel instead of pushing the copy button off a phone
     screen - a flex item defaults to min-width:auto and refuses to shrink below
     its content, which on a 390px viewport clipped the button entirely. */
  .cmd{display:flex;align-items:center;gap:14px;padding:15px 16px 15px 22px;border-radius:13px;font-family:"IBM Plex Mono",monospace;font-size:clamp(13px,1.9vw,15.5px);max-width:100%;min-width:0}
  .cmd .txt{white-space:nowrap;overflow-x:auto;scrollbar-width:none;min-width:0;flex:1 1 auto}
  .cmd .txt::-webkit-scrollbar{display:none}
  .copy{flex-shrink:0;width:36px;height:36px;display:flex;align-items:center;justify-content:center;border:1px solid var(--line);border-radius:9px;background:transparent;color:var(--mute);cursor:pointer;transition:color 180ms ease,border-color 180ms ease,background 180ms ease}
  .copy:hover{color:var(--white);border-color:var(--brand-lift);background:var(--glass)}
  .copy:focus-visible{outline:2px solid var(--brand-soft);outline-offset:2px}
  .copy.ok{color:var(--brand-soft);border-color:var(--brand-soft)}
  .copy svg{width:16px;height:16px}
  .sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}

  /* ---------- the two labels ---------- */
  /* Proven is filled, bright and unbroken. Guessed is hollow, dim and dashed.
     Not one of those three is a hue. */
  .chips{margin-top:30px;display:flex;flex-wrap:wrap;gap:12px}
  .chip{display:flex;align-items:center;gap:11px;padding:12px 18px;border-radius:999px;font-size:13px;color:var(--mute)}
  .chip.proven{border:1px solid var(--line);background:var(--glass)}
  .chip.guessed{border:1px dashed rgba(245,245,245,.16)}
  .dot{width:9px;height:9px;border-radius:50%;background:var(--brand);flex-shrink:0}
  .ring{width:9px;height:9px;border-radius:50%;border:1.5px solid var(--faint);flex-shrink:0}
  .chip .name{font-family:"IBM Plex Mono",monospace;font-size:13.5px}
  .chip.proven .name{color:var(--white)}
  .chip.guessed .name{color:var(--mute)}

  .two{display:grid;grid-template-columns:1fr;gap:20px;margin-top:44px}
  @media(min-width:880px){.two{grid-template-columns:1fr 1fr;gap:24px}}
  /* The cards are buttons, so everything the browser puts on a button has to be
     turned off before the card looks like a card again. */
  .card{display:block;width:100%;text-align:left;font:inherit;color:inherit;cursor:pointer;
    -webkit-appearance:none;appearance:none;padding:34px 32px 30px;border-radius:16px;
    transition:transform 420ms cubic-bezier(.22,.9,.24,1),opacity 420ms ease,
               border-color 420ms ease,box-shadow 420ms ease}
  .card.proven{background:var(--panel);background:linear-gradient(180deg,var(--glass),rgba(245,245,245,.012)),var(--panel);-webkit-backdrop-filter:blur(16px);backdrop-filter:blur(16px);border:1px solid var(--line)}
  .card.guessed{background:transparent;border:1px dashed rgba(245,245,245,.14)}
  .card .row{display:flex;align-items:center;gap:12px}
  .card .body{display:block;margin-top:16px;font-size:15px;color:var(--mute)}
  .quote{display:block;font-size:clamp(21px,2.6vw,27px);font-weight:500;letter-spacing:-.6px;line-height:1.24;color:var(--white);margin:22px 0 0}
  .card.guessed .quote{color:var(--mute)}
  .meta{display:block;border-top:1px solid var(--hair);margin-top:24px;padding-top:18px;font-family:"IBM Plex Mono",monospace;font-size:12px;color:var(--faint);line-height:1.9}

  /* Hover only hints; the commitment is the click. */
  @media(hover:hover){.card:hover{border-color:rgba(145,83,247,.45)}}
  .card:focus-visible{outline:2px solid var(--brand-soft);outline-offset:3px}
  /* Held: lifted, edged in the brand, with the light coming off it. */
  .card.pop{transform:scale(1.022);border-color:var(--brand-lift);border-style:solid;
    box-shadow:0 0 0 1px rgba(121,44,247,.3),0 22px 60px -26px rgba(121,44,247,.62)}
  /* Let go: pushed back, never hidden. .42 keeps the text legible for anyone who
     reads it anyway, since this is a de-emphasis the reader chose and can undo. */
  .card.dim{opacity:.42;transform:scale(.99)}
  .hint{margin-top:16px;font-size:13.5px;color:var(--faint)}

  /* ---------- proof ---------- */
  .proof{display:grid;grid-template-columns:1fr;gap:24px;margin-top:44px}
  @media(min-width:980px){.proof{grid-template-columns:1.05fr .95fr;gap:30px}}
  .term{border-radius:16px;overflow:hidden}
  .term .bar{display:flex;align-items:center;gap:9px;padding:13px 18px;border-bottom:1px solid var(--line);background:rgba(245,245,245,.02)}
  .term .bar i{width:9px;height:9px;border-radius:50%;background:rgba(245,245,245,.16)}
  .term .body{padding:28px 24px;font-family:"IBM Plex Mono",monospace;font-size:clamp(12px,1.6vw,13.5px);line-height:2;color:var(--mute);overflow-x:auto}
  .sev{color:var(--white);font-weight:500;letter-spacing:.5px}
  .trace{position:relative;padding:32px 30px;border-radius:16px}
  /* The spine is anchored to the hop list rather than to the card, so it starts
     at the first node and stops at the last however the text rewraps. Pinned to
     the card it needed two magic offsets and was wrong at every width but one. */
  .hops{position:relative}
  /* left/top/bottom are measured, not guessed: the nodes are 15px wide so their
     centre line sits at 7.5px, and a 2px spine centres on it at 6.5px. The
     first hop's top margin collapses out of .hops, which is why the first node
     centre lands at 10.5 and not at 44.5. */
  .spine{position:absolute;left:6.5px;top:10.5px;bottom:40px;width:2px;background:linear-gradient(180deg,var(--brand),rgba(121,44,247,.16));border-radius:2px}
  .hop{position:relative;display:flex;gap:22px;align-items:flex-start;margin-top:34px}
  .n{width:15px;height:15px;border-radius:50%;flex-shrink:0;margin-top:3px;background:var(--bg);border:2px solid var(--faint)}
  .n.on{background:var(--brand);border-color:var(--brand)}

  /* ---------- numbers ---------- */
  .row{display:grid;grid-template-columns:150px 1fr 62px 62px;gap:14px;align-items:center;padding:20px 4px;border-bottom:1px solid var(--hair)}
  @media(min-width:880px){.row{grid-template-columns:190px 1fr 86px 86px;gap:22px;padding:24px 8px}}
  .track{flex-grow:1;height:8px;background:rgba(245,245,245,.06);border-radius:999px;overflow:hidden}
  .pc{font-weight:700;font-size:clamp(21px,2.6vw,28px);letter-spacing:-.8px;min-width:78px}
  .num{font-family:"IBM Plex Mono",monospace;font-size:13px;color:var(--mute);text-align:right}
  .lbl{font-family:"IBM Plex Mono",monospace;font-size:13.5px;display:flex;align-items:center;gap:10px}
  .foot{display:flex;gap:18px;margin-top:38px;padding-top:28px;border-top:1px solid var(--hair)}
  .foot .rule{width:2px;flex-shrink:0;background:var(--brand);border-radius:2px}

  /* ---------- stats + languages ---------- */
  .stats{display:grid;grid-template-columns:repeat(2,1fr);gap:14px;margin-top:40px}
  @media(min-width:760px){.stats{grid-template-columns:repeat(4,1fr);gap:18px}}
  .stat{padding:24px 22px;border-radius:14px}
  .stat b{display:block;font-weight:700;font-size:clamp(26px,3.2vw,34px);letter-spacing:-1px}
  .stat span{display:block;margin-top:5px;font-family:"IBM Plex Mono",monospace;font-size:11.5px;letter-spacing:1.6px;text-transform:uppercase;color:var(--faint)}
  .langs{margin-top:22px;display:flex;flex-wrap:wrap;gap:9px}
  .langs span{font-family:"IBM Plex Mono",monospace;font-size:12.5px;color:var(--mute);border:1px solid var(--hair);border-radius:7px;padding:7px 12px}

  footer{border-top:1px solid var(--hair);padding:46px 0 70px;display:flex;flex-wrap:wrap;gap:18px;align-items:center;justify-content:space-between}
</style>
</head>
<body>

<div class="field" aria-hidden="true">
  <div class="orb a"></div>
  <div class="orb b"></div>
  <div class="orb c"></div>
</div>

<header>
  <div class="wrap">
    <nav>
      <img src="defuse-mark.png" alt="">
      <span class="word">Defuse</span>
      <div class="navlinks">
        <a href="#finding">A finding</a>
        <a href="#labels">The labels</a>
        <a href="#numbers">Measurements</a>
        <a href="#gaps">Gaps</a>
      </div>
      <a class="ghbtn" href="https://github.com/Sikkuumi/Defuse">github</a>
    </nav>

    <div class="hero rise">
      <div class="kicker">Static application security testing</div>
      <h1>Every scanner says possible. This one says what it proved.</h1>
      <p class="lede">Every finding carries one of two labels, and they are never blended. One matched a
        pattern. The other traced attacker data from source to sink and prints every hop it walked, so you
        can audit the claim instead of believing it.</p>

      <div class="cmdrow">
        <div class="cmd glass">
          <span class="txt"><span style="color:var(--faint)">$</span>&nbsp; ${esc(INSTALL_COMMAND)}</span>
          <button class="copy" id="copycmd" type="button" hidden
                  data-copy="${esc(INSTALL_COMMAND)}" aria-label="Copy the install command">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
                 stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <rect x="9" y="9" width="11" height="11" rx="2.5"></rect>
              <path d="M5 15V6a2.5 2.5 0 0 1 2.5-2.5H15"></path>
            </svg>
          </button>
        </div>
        <span class="mono" style="font-size:12px;color:var(--faint)">no install · no account · AGPL-3.0</span>
      </div>
      <span class="sr" id="copystate" role="status" aria-live="polite"></span>

      <div class="chips">
        <div class="chip proven"><span class="dot"></span><span class="name">flow-verified</span>a path that was walked</div>
        <div class="chip guessed"><span class="ring"></span><span class="name">signature-based</span>a shape that matched</div>
      </div>
    </div>
  </div>
</header>

<section id="finding">
  <div class="wrap">
    <div class="kicker">Before anything is claimed</div>
    <h2>This is one finding,<br>printed whole.</h2>
    <p style="margin-top:20px">Nothing below is summarised. The label, the path, and the limits of what the
      engine could establish all ship together, because a claim without its working is just a louder guess.</p>

    <div class="proof">
      <div class="term glass">
        <div class="bar"><i></i><i></i><i></i><span class="mono" style="font-size:12px;color:var(--faint);margin-left:10px">defuse scan .</span></div>
        <div class="body">
          <div><span class="sev">CRITICAL</span>&nbsp;&nbsp;<span style="color:var(--faint)">cmdi.c:44</span></div>
          <div style="color:var(--white)">Attacker-controlled data from argv[1]</div>
          <div style="color:var(--white)">reaches a shell, which runs the string</div>
          <div style="margin-top:16px">command-injection &nbsp;·&nbsp; CWE-78</div>
          <div><span class="dot" style="display:inline-block;margin-right:7px"></span><span style="color:var(--white)">[flow-verified]</span> <span style="color:var(--faint)">— 3 hops, printed below</span></div>
          <div style="margin-top:20px;color:var(--faint)">limitations</div>
          <div style="color:var(--faint);font-size:12.5px;line-height:1.85">confirms the data flow, not exploitability<br>in production. Does not model memory<br>safety in C: it tracks values, not sizes.</div>
        </div>
      </div>

      <div class="trace glass">
        <div class="kicker" style="margin-bottom:30px">The path it walked</div>
        <div class="hops">
        <div class="spine"></div>
        <div class="hop">
          <span class="n on n1"></span>
          <div><div class="mono" style="font-size:14.5px;color:var(--white)">argv[1]</div><div style="margin-top:5px;font-size:14px;color:var(--mute)">a command-line argument — the source</div></div>
        </div>
        <div class="hop">
          <span class="n on n2"></span>
          <div><div class="mono" style="font-size:14.5px;color:var(--white)">sprintf(cmd, …)</div><div style="margin-top:5px;font-size:14px;color:var(--mute)">written into <code style="font-size:13px">cmd</code>, unescaped</div></div>
        </div>
        <div class="hop">
          <span class="n on n3"></span>
          <div><div class="mono" style="font-size:14.5px;color:var(--white)">system(cmd)</div><div style="margin-top:5px;font-size:14px;color:var(--mute)">arrives at the shell — the sink</div></div>
        </div>
        </div>
        <p style="margin-top:34px;border-top:1px solid var(--hair);padding-top:18px;font-size:14px">Three hops,
          every one printed. Where a hop rests on something the engine could not follow, that hop says so
          rather than being smoothed over.</p>
      </div>
    </div>
  </div>
</section>

<section id="labels">
  <div class="wrap">
    <div class="kicker">Two labels, never blurred</div>
    <h2>A guess and a proof are<br>not the same sentence.</h2>
    <p style="margin-top:20px">Most tools report everything at one confidence and leave the triage to you.
      The word they hide behind is <em style="font-style:italic;color:var(--white)">possible</em> — and it
      covers both a traced data path and a lucky-looking regex.</p>

    <!--
      Real <button>s, not divs wearing role="button". That buys keyboard
      operation, focus, and the pressed state from the platform instead of from
      script. The price is that a button may only contain phrasing content, so
      every <p> and <div> inside became a <span style="display:block"> - same
      rendering, valid markup.
    -->
    <div class="two" id="labelcards">
      <button type="button" class="card proven" aria-pressed="false">
        <span class="row"><span class="dot" style="width:11px;height:11px"></span><span class="mono" style="font-size:16px;color:var(--white)">flow-verified</span></span>
        <span class="quote">“Attacker data actually reaches here.”</span>
        <span class="body">Traced hop by hop, across functions and across files, with
          the whole path printed beside the finding — including the steps where its knowledge ran out.</span>
        <span class="meta">evidence &nbsp;·&nbsp; a printed source&rarr;sink path<br>claim &nbsp;&nbsp;&nbsp;&nbsp;·&nbsp; check it yourself</span>
      </button>
      <button type="button" class="card guessed" aria-pressed="false">
        <span class="row"><span class="ring" style="width:11px;height:11px"></span><span class="mono" style="font-size:16px;color:var(--mute)">signature-based</span></span>
        <span class="quote">“This code has the shape of a bug.”</span>
        <span class="body">A pattern matched in the syntax tree. Data flow was not
          traced. It is a lead worth opening, not a fact — and the report says exactly that, every time.</span>
        <span class="meta">evidence &nbsp;·&nbsp; one matched pattern<br>claim &nbsp;&nbsp;&nbsp;&nbsp;·&nbsp; worth your attention</span>
      </button>
    </div>
    <p class="hint" hidden>Pick one to hold it. Pick it again to let both go.</p>

    <div style="display:flex;gap:16px;align-items:flex-start;margin-top:40px">
      <svg viewBox="0 0 24 24" style="width:20px;height:20px;flex-shrink:0;margin-top:3px" aria-hidden="true"><path d="M12 3l7 3.5v5c0 4.2-2.9 7.8-7 9-4.1-1.2-7-4.8-7-9v-5z" fill="none" stroke="#9153F7" stroke-width="1.5" stroke-linejoin="round"></path></svg>
      <p style="font-size:16.5px;max-width:68ch;color:var(--white)">A rule cannot set its own confidence. Only a
        printed path earns the filled label — and that is enforced by the type system, not by a style guide.</p>
    </div>
  </div>
</section>

<section id="numbers">
  <div class="wrap">
    <div class="kicker">Measured, and published whole</div>
    <h2>What the filled label<br>is actually worth.</h2>
    <p style="margin-top:20px">Scored against OWASP BenchmarkJava, ${benchmark.scored} labelled test cases, on
      engine ${esc(benchmark.engineVersion)} (${esc(split.measuredAt)}). Each label is scored
      <em style="font-style:italic;color:var(--white)">separately</em>, because one blended figure would be the
      same averaging this tool refuses to do inside a single finding.</p>

    <div style="margin-top:38px">
      <div class="row" style="padding-bottom:10px">
        <span class="mono" style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--faint)">tier</span>
        <span class="mono" style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--faint)">precision</span>
        <span class="num" style="font-size:11px;letter-spacing:2px;text-transform:uppercase">found</span>
        <span class="num" style="font-size:11px;letter-spacing:2px;text-transform:uppercase">wrong</span>
      </div>

      <div class="row">
        <span class="lbl" style="color:var(--white)"><span class="dot"></span>flow-verified</span>
        <div style="display:flex;align-items:center;gap:16px">
          <div class="track"><div class="barfill" style="width:${bar(verified.precision)}%;height:8px;background:var(--brand);border-radius:999px"></div></div>
          <span class="pc">${esc(verified.precision)}</span>
        </div>
        <span class="num">${verified.tp}</span><span class="num">${verified.fp}</span>
      </div>

      <div class="row">
        <span class="lbl" style="color:var(--mute)"><span class="ring"></span>signature-based</span>
        <div style="display:flex;align-items:center;gap:16px">
          <div class="track"><div class="barfill" style="width:${bar(signature.precision)}%;height:8px;background:rgba(245,245,245,.22);border-radius:999px;animation-delay:150ms"></div></div>
          <span class="pc" style="color:var(--mute)">${esc(signature.precision)}</span>
        </div>
        <span class="num">${signature.tp}</span><span class="num">${signature.fp}</span>
      </div>

      <div class="row">
        <span class="lbl" style="color:var(--faint)">both combined</span>
        <div style="display:flex;align-items:center;gap:16px">
          <div class="track"><div class="barfill" style="width:${bar(benchmark.precision)}%;height:8px;background:rgba(121,44,247,.45);border-radius:999px;animation-delay:300ms"></div></div>
          <span class="pc" style="color:var(--mute)">${esc(benchmark.precision)}</span>
        </div>
        <span class="num">${benchmark.tp}</span><span class="num">${benchmark.fp}</span>
      </div>
    </div>

    <p style="margin-top:32px;font-size:19px;color:var(--white);max-width:68ch">The filled label is worth
      <span style="font-weight:700;font-size:27px;letter-spacing:-1px;color:var(--brand-soft)">${gap}</span>
      points of precision over the hollow one. That gap is the entire claim this tool makes, and it is measured
      here rather than asserted.</p>

    <div class="foot">
      <div class="rule"></div>
      <div>
        <div class="mono" style="font-size:11px;letter-spacing:2.2px;text-transform:uppercase;color:var(--brand-soft)">The footnote, printed rather than buried</div>
        <p style="margin-top:12px;font-size:15px;max-width:72ch">${verified.decoyFalsePositives} of the
          ${verified.fp} false positives still wearing the filled label (${esc(verified.decoyShare)}) are the
          benchmark’s own constant-branch decoys — a data path that genuinely exists, inside a branch that can
          never run. That leaves <span style="color:var(--white)">${verified.nonDecoyFalsePositives}</span>
          ordinary mistakes, which would put <code style="font-size:14px;color:var(--white)">flow-verified</code>
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
    <p style="margin-top:20px">Every run ends with the rule and language combinations this engine does not
      implement — currently ${notImplemented} of them — each with the real reason, not a placeholder. In C it
      states outright that it does not model memory safety: no buffer overflows, no use-after-free. It tracks
      values, not sizes.</p>
    <p style="margin-top:14px">A gap you can read is a gap you can plan around. A gap you can’t see is the one
      that gets you.</p>

    <div class="stats">
      <div class="stat glass"><b>${LANGUAGES.length}</b><span>languages</span></div>
      <div class="stat glass"><b>${ruleCount}</b><span>rules</span></div>
      <div class="stat glass"><b>${benchmark.filesParsed}</b><span>files scored</span></div>
      <div class="stat glass"><b>AGPL</b><span>3.0 · or commercial</span></div>
    </div>
    <div class="langs">${languageNames.map((n) => `<span>${esc(n)}</span>`).join('')}</div>
  </div>
</section>

<section id="cost">
  <div class="wrap">
    <div class="kicker">What it costs</div>
    <h2>Free, and specific<br>about what that means.</h2>
    <p style="margin-top:20px">The scanner is AGPL-3.0. Pointing it at your own code — closed-source,
      proprietary, commercial, any of it — puts no obligation on you whatsoever, and running it unmodified
      inside a company is free and unencumbered.</p>
    <p style="margin-top:14px">The one obligation attaches if you modify it and then serve your modified
      version to other people over a network, in which case those users are owed your source. If those terms
      do not work for your company, and for some they genuinely do not, the copyright sits in one place and a
      commercial licence can be discussed.</p>
  </div>
</section>

<div class="wrap">
  <footer>
    <div style="display:flex;align-items:center;gap:13px">
      <img src="defuse-mark.png" alt="" style="width:25px;height:auto">
      <span class="word" style="font-size:20px">Defuse</span>
    </div>
    <div class="mono" style="font-size:13px;color:var(--faint)"><a href="https://github.com/Sikkuumi/Defuse">github.com/Sikkuumi/Defuse</a> · AGPL-3.0 · commercial licence available</div>
  </footer>
</div>

<script>
/* The copy button starts hidden and is revealed only once we know the clipboard
   is reachable, so a browser without it shows no dead control - the command is
   plain selectable text either way, and the page needs no script to be usable. */
(function () {
  var btn = document.getElementById('copycmd');
  var live = document.getElementById('copystate');
  if (!btn || !navigator.clipboard) return;
  var idle = btn.innerHTML;
  var done = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6L9 17l-5-5"></path></svg>';
  var timer;
  btn.hidden = false;
  btn.addEventListener('click', function () {
    navigator.clipboard.writeText(btn.getAttribute('data-copy')).then(function () {
      clearTimeout(timer);
      btn.innerHTML = done;
      btn.classList.add('ok');
      if (live) live.textContent = 'Install command copied';
      timer = setTimeout(function () {
        btn.innerHTML = idle;
        btn.classList.remove('ok');
        if (live) live.textContent = '';
      }, 1800);
    });
  });
})();

/* Hold one label, push the other back.
   The hint stays hidden until this runs, so a reader with no JavaScript is
   never told to click something that will not respond. The cards are real
   buttons, so Enter and Space already work and aria-pressed carries the state
   to a screen reader - all this adds is the two classes. */
(function () {
  var wrap = document.getElementById('labelcards');
  if (!wrap) return;
  var cards = Array.prototype.slice.call(wrap.querySelectorAll('.card'));
  if (cards.length < 2) return;
  var hint = document.querySelector('.hint');
  if (hint) hint.hidden = false;

  cards.forEach(function (card) {
    card.addEventListener('click', function () {
      var alreadyHeld = card.classList.contains('pop');
      cards.forEach(function (c) {
        c.classList.remove('pop', 'dim');
        c.setAttribute('aria-pressed', 'false');
      });
      if (alreadyHeld) return; // a second click on the held card releases both
      card.classList.add('pop');
      card.setAttribute('aria-pressed', 'true');
      cards.forEach(function (c) {
        if (c !== card) c.classList.add('dim');
      });
    });
  });
})();
</script>

</body>
</html>
`;
}
