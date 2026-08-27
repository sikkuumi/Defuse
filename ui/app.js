/**
 * The page. Collects files, hands them to the worker, renders what comes back.
 *
 * It deliberately contains NO analysis logic - not a rule, not a heuristic, not
 * a severity decision. Everything it draws came out of `analyze()`. If this file
 * ever starts deciding things, the browser and the CLI have begun to disagree.
 */

import { SCANNABLE_EXTENSIONS } from '/engine/parse/languages.js';

const $ = (id) => document.getElementById(id);
const scannable = new Set(SCANNABLE_EXTENSIONS);

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_FILES = 4000;

let worker = null;
let lastResult = null;
let filter = 'all';

/** path -> source text, kept so the code pane can render any file instantly. */
const sources = new Map();
let openPath = null;
let selectedId = null;

/* ------------------------------------------------------------------ worker */

function startWorker() {
  worker = new Worker('/worker.js', { type: 'module' });
  worker.addEventListener('message', (event) => {
    const message = event.data;
    if (message.type === 'ready') {
      $('version').textContent = `v${message.engine.version}`;
      $('phase').textContent = message.engine.analysisLabel;
    } else if (message.type === 'progress') {
      const pct = message.total ? Math.round((message.done / message.total) * 100) : 0;
      $('barFill').style.width = `${pct}%`;
      $('progressLabel').textContent = `${message.done} / ${message.total} · ${message.file}`;
    } else if (message.type === 'done') {
      lastResult = message.result;
      render(message.result);
    } else if (message.type === 'error') {
      $('progressLabel').innerHTML = `<span class="err">scan failed: ${escapeHtml(message.message)}</span>`;
    }
  });
}
startWorker();

/* ------------------------------------------------------------- file intake */

function isScannable(name, size) {
  const dot = name.lastIndexOf('.');
  if (dot < 0) return false;
  return scannable.has(name.slice(dot).toLowerCase()) && size <= MAX_FILE_BYTES;
}

/*
 * Directories nobody means to scan: dependencies, build output, caches.
 *
 * This regex used to exist only in `readEntry` - the drag-and-drop path - so
 * the SAME folder gave two different answers depending on how it arrived.
 * Dropped, it was 59 files. Chosen with the folder button, it was 176 files,
 * because `readAll` filtered on extension and size and nothing else, and the
 * report filled up with third-party code: ten findings inside node_modules and
 * two in a vendored parser runtime, where `credentials: "same-origin"` read as
 * a hardcoded credential.
 *
 * The CLI has skipped these directories all along. Two intakes into one engine
 * disagreeing about what "this folder" means is the browser shell drifting from
 * the command line, which is the one thing this project cannot let happen.
 */
const IGNORED_DIRECTORY =
  /(^|\/)(node_modules|bower_components|jspm_packages|\.git|dist|build|out|target|bin|obj|vendor|third_party|\.venv|venv|__pycache__|site-packages|\.next|\.nuxt|coverage|\.cache|\.pytest_cache)(\/|$)/;

function inIgnoredDirectory(relativePath) {
  // A single loose file has no directory to judge, so it is always allowed.
  return relativePath.includes('/') && IGNORED_DIRECTORY.test(relativePath);
}

async function readAll(fileList) {
  const picked = [...fileList]
    .filter((f) => isScannable(f.name, f.size))
    .filter((f) => !inIgnoredDirectory(f.webkitRelativePath || f.name))
    .slice(0, MAX_FILES);
  return Promise.all(
    picked.map(async (file) => ({
      // webkitRelativePath keeps the folder structure, which the import
      // resolver needs: without it every file looks like it lives at the root
      // and no relative import could ever resolve.
      path: file.webkitRelativePath || file.name,
      source: await file.text(),
    })),
  );
}

/** Recursively read a dropped directory through the (non-standard) entry API. */
async function readEntry(entry, prefix, out) {
  if (out.length >= MAX_FILES) return;
  if (entry.isFile) {
    const file = await new Promise((resolve) => entry.file(resolve));
    if (isScannable(file.name, file.size)) {
      out.push({ path: `${prefix}${file.name}`, source: await file.text() });
    }
    return;
  }
  if (!entry.isDirectory) return;
  if (inIgnoredDirectory(`${entry.name}/`)) return;

  const reader = entry.createReader();
  for (;;) {
    const batch = await new Promise((resolve) => reader.readEntries(resolve, () => resolve([])));
    if (batch.length === 0) break;
    for (const child of batch) await readEntry(child, `${prefix}${entry.name}/`, out);
  }
}

function scan(files) {
  if (files.length === 0) {
    $('progressLabel').innerHTML =
      `<span class="err">No files with a supported extension (${escapeHtml([...scannable].join(' '))}).</span>`;
    $('intake').style.display = 'none';
    $('progress').style.display = 'block';
    return;
  }
  $('intake').style.display = 'none';
  $('results').style.display = 'none';
  $('progress').style.display = 'block';
  $('barFill').style.width = '0%';
  sources.clear();
  for (const file of files) sources.set(file.path, file.source);
  $('progressLabel').textContent = `parsing ${files.length} file(s)…`;
  worker.postMessage({ files, options: {} });
}

$('pick').addEventListener('click', () => $('dirInput').click());
$('pickFiles').addEventListener('click', () => $('fileInput').click());
$('dirInput').addEventListener('change', async (e) => scan(await readAll(e.target.files)));
$('fileInput').addEventListener('change', async (e) => scan(await readAll(e.target.files)));
$('rescan').addEventListener('click', () => {
  $('results').style.display = 'none';
  $('progress').style.display = 'none';
  $('intake').style.display = 'block';
});

const drop = $('drop');
for (const type of ['dragenter', 'dragover']) {
  drop.addEventListener(type, (e) => {
    e.preventDefault();
    drop.classList.add('hot');
  });
}
for (const type of ['dragleave', 'drop']) {
  drop.addEventListener(type, () => drop.classList.remove('hot'));
}
drop.addEventListener('drop', async (event) => {
  event.preventDefault();
  const items = [...(event.dataTransfer?.items ?? [])];
  const entries = items.map((i) => i.webkitGetAsEntry?.()).filter(Boolean);
  if (entries.length > 0) {
    const out = [];
    for (const entry of entries) await readEntry(entry, '', out);
    scan(out);
  } else {
    scan(await readAll(event.dataTransfer?.files ?? []));
  }
});

/* --------------------------------------------------------------- rendering */

function escapeHtml(text) {
  return String(text ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );
}

/*
 * The numeric counterpart to escapeHtml, and it exists for the same reason.
 *
 * We ran this project's own scanner over this file. It reported five
 * `innerHTML` assignments and, for each one, named the exact sub-expressions it
 * could not prove safe - `finding.severity`, `reading.value`, `c.state`. Every
 * one of those is a number or a fixed enum the engine produced, so none of them
 * is exploitable today.
 *
 * We escaped them anyway, and it is worth saying why rather than filing it as a
 * false positive. "It happens to be safe right now" is an argument about the
 * CURRENT engine; `escapeHtml`/`num` at the boundary is a property of THIS file
 * that no change on the other side can take away. The scanner could not see the
 * argument, only the boundary - and it was right that the boundary was open.
 *
 * `num` is used where the value is genuinely numeric, because it says what the
 * value IS. It returns 0 for anything that is not a finite number, so a
 * malformed report renders a zero instead of the word "undefined".
 */
function num(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

/* --------------------------------- gauges -------------------------------- */

/**
 * One dial. The reading comes straight from the engine - this function does
 * arithmetic only to turn a number into an arc.
 *
 * A half circle, not the 260-degree sweep this started as.
 *
 * The wide sweep left a gap at the bottom that the centred number sat awkwardly
 * above, and - more to the point - it made a near-empty dial look BROKEN. Across
 * the corpus the two severity readings occupy between 0% and 24% of their scale,
 * so a stub arc in the lower-left corner is the normal case, not the edge case.
 *
 * A semicircle puts the number in a natural well, and printing the two ends of
 * the scale turns "a tiny arc" into "near the bottom of 500", which is the fact.
 */
const SWEEP = 180;
const START = 180;

function polar(cx, cy, r, degrees) {
  const rad = (degrees * Math.PI) / 180;
  return [cx + r * Math.cos(rad), cy + r * Math.sin(rad)];
}

function arcPath(cx, cy, r, fromDeg, toDeg) {
  const [x1, y1] = polar(cx, cy, r, fromDeg);
  const [x2, y2] = polar(cx, cy, r, toDeg);
  const large = Math.abs(toDeg - fromDeg) > 180 ? 1 : 0;
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
}

const SEV_LABEL = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' };

/** The composition strip: what the total is actually made of. */
function composition(reading) {
  if (reading.id === 'analysis-coverage') return '';
  if (reading.segments.length === 0) {
    return `<p class="g-none">No findings in this category, so there is nothing to break down.
      That is a measurement, not a verdict.</p>`;
  }
  const bars = reading.segments
    .map((s) => `<i data-sev="${escapeHtml(s.severity)}" style="flex:${Math.max(s.share, 0.02)}"
                    title="${num(s.count)} ${escapeHtml(SEV_LABEL[s.severity])} x ${num(s.weight) / num(s.count)} = ${num(s.weight)}"></i>`)
    .join('');
  const keys = reading.segments
    .map(
      (s) => `<span><b data-sev="${escapeHtml(s.severity)}" style="background:var(--sev-${escapeHtml(s.severity)})"></b>${num(s.count)} ${escapeHtml(SEV_LABEL[s.severity])}</span>`,
    )
    .join('');
  return `<p class="g-seg-head">made of</p>
          <div class="g-seg" role="img"
              aria-label="Made up of ${reading.segments.map((s) => `${num(s.count)} ${escapeHtml(SEV_LABEL[s.severity])}`).join(', ')}">${bars}</div>
          <div class="g-legend">${keys}</div>`;
}

function gauge(reading) {
  const cx = 100;
  const cy = 100;
  const r = 76;
  const fraction = reading.max > 0 ? Math.min(reading.value / reading.max, 1) : 0;
  const end = START + SWEEP * fraction;

  // A zero reading draws NO value arc at all. Not a sliver, not a rounded cap
  // sitting at the start - an empty track, because the honest picture of
  // "nothing measured here" is nothing.
  const value = fraction > 0 ? `<path class="g-val" d="${arcPath(cx, cy, r, START, end)}" />` : '';

  return `<figure class="gauge" data-id="${escapeHtml(reading.id)}">
    <svg viewBox="0 0 200 118" role="img"
         aria-label="${escapeHtml(reading.label)}: ${num(reading.value)}${escapeHtml(reading.unit)} of ${num(reading.max)}${escapeHtml(reading.unit)}">
      <path class="g-track" d="${arcPath(cx, cy, r, START, START + SWEEP)}" />
      ${value}
      <text class="g-num" x="${cx}" y="${cy - 6}" text-anchor="middle">${num(reading.value)}${escapeHtml(reading.unit)}</text>
      <text class="g-end" x="${cx - r}" y="${cy + 16}" text-anchor="middle">0</text>
      <text class="g-end" x="${cx + r}" y="${cy + 16}" text-anchor="middle">${num(reading.max)}${escapeHtml(reading.unit)}</text>
    </svg>
    <figcaption>
      <span class="g-label">${escapeHtml(reading.label)}</span>
      ${reading.capped ? `<span class="g-pin" title="The dial stops at ${num(reading.max)}. The real total is ${num(reading.rawTotal)}.">pinned &mdash; real total ${num(reading.rawTotal)}</span>` : ''}
      ${composition(reading)}
      <p class="g-mean">${escapeHtml(reading.meaning)}</p>
      <details class="g-work">
        <summary>show the arithmetic</summary>
        <ul>${reading.working.map((line) => `<li>${escapeHtml(line)}</li>`).join('')}</ul>
      </details>
    </figcaption>
  </figure>`;
}

function renderGauges(score) {
  // Nothing was analysed. Show that INSTEAD of the dials - three zeroes beside a
  // warning are still read as three zeroes, and "94% coverage" beside them is
  // read as reassurance. An empty file and ten lines of careful code used to
  // produce the identical panel.
  if (score.examinedNothing) {
    $('gauges').innerHTML = `<div class="noread">
      <p class="noread-head">No reading</p>
      <p>The file(s) parsed, but not one statement, call or assignment reached a rule &mdash;
      there was no code here to analyse. The three dials are withheld rather than shown as
      zeroes, because zero findings out of zero examined is the absence of a result, not a
      result. Check the scan was pointed at the right path.</p>
    </div>`;
    return;
  }

  const spots = score.blindSpots.length
    ? `<div class="blindspots">
         <span class="bs-head">Where this scan stopped early</span>
         ${score.blindSpots
           .map((s) => `<span class="bs"><b>${num(s.count)}</b> ${escapeHtml(s.label)}</span>`)
           .join('')}
       </div>`
    : `<div class="blindspots"><span class="bs-head">No truncated traces, unmodelled hops or unreadable
         files across the ${num(score.shapesExamined)} code shape(s) examined &mdash; within the rules that
         ran, the dials are reading everything the engine can do.</span></div>`;

  $('gauges').innerHTML = `<div class="gauge-row">${score.gauges.map(gauge).join('')}</div>${spots}`;
}

function tile(value, label, sub, className = '') {
  return `<div class="tile ${className}"><div class="n">${value}</div>
    <div class="k">${escapeHtml(label)}</div>
    ${sub ? `<div class="sub">${escapeHtml(sub)}</div>` : ''}</div>`;
}

function renderFlow(path) {
  const hops = path
    .map((step, index) => {
      const pip = index === 0 ? '┌' : index === path.length - 1 ? '└' : '│';
      return `<div class="hop" data-kind="${step.kind}">
        <div class="pip">${pip}</div>
        <div class="loc" title="${escapeHtml(step.location.file)}">${escapeHtml(step.location.file)}:${step.location.startLine}</div>
        <div class="kind">${step.kind}</div>
        <div class="what">${escapeHtml(step.description)}</div>
      </div>`;
    })
    .join('');
  return `<div class="flow">${hops}</div>`;
}

/* ------------------------------------------------------------ the deck --- */

/** A stable id for a finding, so selection survives re-filtering. */
const idOf = (f) => `${f.ruleId}|${f.location.file}|${f.location.startLine}|${f.location.startColumn}`;

function findingsFor(path) {
  return (lastResult?.findings ?? []).filter((f) => f.location.file === path);
}
function cleanFor(path) {
  return (lastResult?.verifiedClean ?? []).filter((c) => c.file === path);
}
/**
 * Did this file fail to parse?
 *
 * This matters more than it looks. Without it, a file whose syntax tree came
 * back broken sits in the tree with no badge - looking exactly like a file we
 * read end to end and found nothing wrong with. "We could not read this" and
 * "this is clean" would be drawn the same way, which is the one thing this
 * tool promises never to do.
 */
function parseProblemFor(path) {
  return (lastResult?.parseProblems ?? []).find((p) => p.file === path);
}
/**
 * How this file participates - computed by the ENGINE, not here.
 *
 * The important case: a file can hold the line that actually causes a bug while
 * the finding is reported in another file, because findings are reported at the
 * sink. `handler.js` builds the SQL; `db.js` runs it and gets the finding. If
 * this page only knew about finding locations, handler.js would look untouched
 * - and because it also has two sanitised lines, it would look GREEN. The file
 * you have to edit would be the one marked safe.
 */
const NO_ROLE = { findingsReported: 0, onPathOf: 0, verifiedCleanLines: 0, pathLines: [] };

/**
 * The same three states in words, for a screen reader.
 *
 * A coloured pill reading "1" is invisible to anyone not looking at it. The
 * distinction it encodes - a finding here, versus data passing through toward
 * a finding elsewhere, versus a line proved clean - is the whole point of the
 * tree, so it has to survive in text too.
 */
function describeRole(role, broken) {
  if (broken) return 'did not fully parse, parts unchecked';
  const parts = [];
  if (role.findingsReported) parts.push(`${role.findingsReported} finding${role.findingsReported === 1 ? '' : 's'}`);
  if (role.onPathOf) parts.push(`on the path of ${role.onPathOf} finding${role.onPathOf === 1 ? '' : 's'} filed elsewhere`);
  if (!parts.length && role.verifiedCleanLines) {
    parts.push(`${role.verifiedCleanLines} line${role.verifiedCleanLines === 1 ? '' : 's'} proved clean`);
  }
  return parts.length ? parts.join(', ') : 'nothing reported';
}
function roleFor(path) {
  return (lastResult?.fileRoles ?? []).find((r) => r.file === path) ?? NO_ROLE;
}

/* --------------------------------- tree --------------------------------- */

function renderTree() {
  const paths = [...sources.keys()].sort();
  const byDir = new Map();
  for (const p of paths) {
    const cut = p.lastIndexOf('/');
    const dir = cut < 0 ? '' : p.slice(0, cut);
    if (!byDir.has(dir)) byDir.set(dir, []);
    byDir.get(dir).push(p);
  }

  const html = [...byDir.entries()]
    .map(([dir, files]) => {
      const rows = files
        .map((p) => {
          const role = roleFor(p);
          const broken = parseProblemFor(p);

          // Four different things, drawn four different ways - never merged.
          // Warnings first; the green count appears only when there is nothing
          // to warn about, because a reassurance sitting next to a warning is
          // worse than no reassurance at all.
          // Each badge carries a GLYPH as well as a colour, matching the gutter
          // legend exactly. Three counts that differ only by hue tell a
          // colour-blind reader nothing - and "1 finding" versus "1 line we
          // proved clean" is the most consequential distinction on the page.
          let badge = '';
          if (broken) {
            badge = `<span class="count warn" title="This file did not fully parse, so parts of it were never analysed. An empty result here means UNCHECKED, not clean."><i aria-hidden="true">!</i>&nbsp;</span>`;
          } else {
            if (role.findingsReported) {
              badge += `<span class="count" title="${role.findingsReported} finding(s) reported in this file"><i aria-hidden="true">●</i>${role.findingsReported}</span>`;
            }
            if (role.onPathOf) {
              badge += `<span class="count via" title="Attacker data starts here or passes through here on its way to ${role.onPathOf} finding(s) reported in ANOTHER file. Often this is where the fix belongs, even though the finding is filed at the sink."><i aria-hidden="true">◆</i>${role.onPathOf}</span>`;
            }
            if (!badge && role.verifiedCleanLines) {
              badge = `<span class="count ok" title="${num(role.verifiedCleanLines)} line(s) the tracer reached and proved a sanitiser covers"><i aria-hidden="true">✓</i>${num(role.verifiedCleanLines)}</span>`;
            }
          }
          const state = broken ? ' broken' : role.onPathOf ? ' via' : '';
          // A real <button>: keyboard operation, focus handling and the right
          // screen-reader role all arrive for free, and cannot be forgotten.
          return `<button type="button" class="file${state}" data-path="${escapeHtml(p)}"
                    aria-current="${p === openPath}">
                    <span class="name" title="${escapeHtml(p)}">${escapeHtml(p.slice(p.lastIndexOf('/') + 1))}</span>
                    ${badge}
                    <span class="sr">${describeRole(role, broken)}</span>
                  </button>`;
        })
        .join('');
      return `${dir ? `<div class="dir">${escapeHtml(dir)}/</div>` : ''}${rows}`;
    })
    .join('');

  $('tree').innerHTML = html;
  const files = [...$('tree').querySelectorAll('.file')];
  for (const [index, el] of files.entries()) {
    el.addEventListener('click', () => openFile(el.dataset.path));
    // Up/Down walk the list the way every file tree does; Home/End jump.
    // Tab still steps through file by file, so nobody is trapped either way.
    el.addEventListener('keydown', (event) => {
      const to =
        event.key === 'ArrowDown' ? index + 1
        : event.key === 'ArrowUp' ? index - 1
        : event.key === 'Home' ? 0
        : event.key === 'End' ? files.length - 1
        : null;
      if (to === null) return;
      event.preventDefault();
      const next = files[Math.max(0, Math.min(files.length - 1, to))];
      if (next) {
        next.focus();
        openFile(next.dataset.path);
      }
    });
  }
}

/* ------------------------------- code pane ------------------------------- */

function openFile(path, line) {
  const source = sources.get(path);
  if (source === undefined) return;
  const changed = path !== openPath;
  openPath = path;
  $('codePath').textContent = path;

  if (changed) {
    const hits = new Map();
    for (const f of findingsFor(path)) hits.set(f.location.startLine, f.severity);
    const guards = new Set(cleanFor(path).map((c) => c.line));
    // Lines a traced flow passes through. A line that is already a finding
    // stays red - it does not need a weaker mark on top of a stronger one.
    const onPath = new Set(roleFor(path).pathLines);

    const lines = source.split('\n');
    const rendered = lines
      .map((text, i) => {
        const n = i + 1;
        const cls = hits.has(n) ? ' hit' : onPath.has(n) ? ' via' : guards.has(n) ? ' guard' : '';
        const mark = hits.has(n)
          ? '\u25cf'
          : onPath.has(n)
            ? '\u25c6'
            : guards.has(n)
              ? '\u2713'
              : '';
        const why = onPath.has(n) && !hits.has(n)
          ? ' title="Attacker data passes through this line on its way to a finding reported elsewhere."'
          : '';
        return `<div class="cl${cls}" data-line="${n}"${why}><span class="ln">${n}</span><span class="mk">${mark}</span><span class="tx">${escapeHtml(text) || ' '}</span></div>`;
      })
      .join('');
    // Said at the top of the code itself, not only as a badge in the tree.
    // Someone reading this pane and seeing no red marks must not be allowed to
    // conclude the file is fine when we never got a usable tree out of it.
    const broken = parseProblemFor(path);
    const notice = broken
      ? `<div class="unparsed">This file did not fully parse &mdash;
         ${broken.issues.length} problem${broken.issues.length === 1 ? '' : 's'},
         first at line ${escapeHtml(broken.issues[0]?.line ?? '?')}.
         Anything the broken syntax hid was never analysed, so the absence of
         marks below means <b>unchecked</b>, not clean.</div>`
      : '';
    $('codeBody').innerHTML = `${notice}<div class="codelines">${rendered}</div>`;
    renderTree();
  }

  for (const el of $('codeBody').querySelectorAll('.cl.focus')) el.classList.remove('focus');
  if (line) {
    const row = $('codeBody').querySelector(`.cl[data-line="${line}"]`);
    if (row) {
      row.classList.add('focus');
      // Smooth scrolling is motion, and some people have asked their system
      // not to move things. Jump instead - the destination is what matters.
      const still = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
      row.scrollIntoView({ block: 'center', behavior: still ? 'auto' : 'smooth' });
    }
    // Announced rather than only shown, so a keyboard user who jumped here
    // from a flow hop is told where they landed.
    $('codeStatus').textContent = `${path}, line ${line}`;
  }
}

/* --------------------------------- ledger -------------------------------- */

function renderHop(step, index, total) {
  const pip = index === 0 ? '\u250c' : index === total - 1 ? '\u2514' : '\u2502';
  const where = `${step.location.file.split('/').pop()}:${step.location.startLine}`;
  // A button, because a hop IS an action - it navigates the code pane to
  // another file. Walking the path with the keyboard is the thing this deck
  // exists for, and until now Tab could not reach a single hop.
  return `<button type="button" class="hop" data-kind="${escapeHtml(step.kind)}"
      data-file="${escapeHtml(step.location.file)}" data-line="${num(step.location.startLine)}"
      aria-label="${escapeHtml(step.kind)} at ${escapeHtml(where)}: ${escapeHtml(step.description)}. Opens this line.">
    <span class="pip" aria-hidden="true">${pip}</span>
    <span class="loc" title="${escapeHtml(step.location.file)}">${escapeHtml(where)}</span>
    <span class="kind">${escapeHtml(step.kind)}</span>
    <span class="what">${escapeHtml(step.description)}</span>
  </button>`;
}

function renderRow(finding) {
  const id = idOf(finding);
  const verified = finding.confidence === 'flow-verified';
  const files = new Set((finding.flowPath ?? []).map((s) => s.location.file));
  const open = id === selectedId;

  // The row is a container, not a control: a <button> cannot legally contain
  // the hop buttons inside the detail. So the summary is the button and the
  // detail sits beside it - which is also the correct disclosure pattern.
  return `<div class="row" data-id="${escapeHtml(id)}" data-sev="${escapeHtml(finding.severity)}">
    <button type="button" class="row-head" aria-expanded="${open}">
    <span class="top">
      <span class="sev ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
      <span class="rwhere">${escapeHtml(finding.location.file.split('/').pop())}:${num(finding.location.startLine)}</span>
      <span class="badge ${verified ? 'flow' : 'sig'}">${verified ? 'flow' : 'sig'}</span>
      ${files.size > 1 ? `<span class="badge">${files.size} files</span>` : ''}
      ${
        // A traced path is only as strong as its weakest hop. When one of them
        // passes through a function we do not model, "no sanitiser on the path"
        // is an assumption - and that has to be visible next to the FLOW badge,
        // not only inside the expanded detail.
        verified && finding.unmodelledHops?.length
          ? `<span class="badge assumed" title="This path passes through ${finding.unmodelledHops.map(escapeHtml).join(', ')}, which we do not model. We assume the value is preserved; if it is actually sanitised, this finding is wrong.">${finding.unmodelledHops.length} assumed</span>`
          : ''
      }
    </span>
    <span class="rmsg">${escapeHtml(finding.message)}</span>
    </button>
    ${
      open
        ? `<div class="detail"><dl>
             <dt>why</dt><dd>${escapeHtml(finding.reasoning)}</dd>
             ${
               finding.flowPath
                 ? `<dt>flow</dt><dd><div class="flow">${finding.flowPath
                     .map((step, i) => renderHop(step, i, finding.flowPath.length))
                     .join('')}</div></dd>`
                 : ''
             }
             <dt>rule</dt><dd>${escapeHtml(finding.ruleId)} \u00b7 ${escapeHtml(finding.cwe)} \u00b7 ${escapeHtml(finding.owasp)}</dd>
             <dt>gap</dt><dd class="gap">${escapeHtml(finding.limitations)}</dd>
           </dl></div>`
        : ''
    }
  </div>`;
}

function renderFindings() {
  if (!lastResult) return;
  const shown = lastResult.findings.filter((f) => filter === 'all' || f.confidence === filter);
  $('ledgerCount').textContent = `(${shown.length})`;
  $('ledger').innerHTML =
    shown.length === 0
      ? lastResult.score?.examinedNothing
        // "Nothing here" with no denominator is the same sentence whether we
        // examined ten thousand constructs or none. The count is the difference.
        ? `<div class="placeholder">Nothing here, because nothing was analysed &mdash;
           <b>0</b> code shapes were examined. This is the absence of a result,
           not a clean one.</div>`
        : `<div class="placeholder">Nothing in this view, out of
           <b>${num(lastResult.score?.shapesExamined ?? 0)}</b> code shape(s) examined. That is
           not the same as &ldquo;safe&rdquo; &mdash; read the section below.</div>`
      : shown.map(renderRow).join('');

  for (const row of $('ledger').querySelectorAll('.row')) {
    const id = row.dataset.id;
    row.querySelector('.row-head').addEventListener('click', () => {
      const finding = shown.find((f) => idOf(f) === id);
      const wasOpen = selectedId === id;
      selectedId = wasOpen ? null : id;
      renderFindings();
      if (finding && selectedId) openFile(finding.location.file, finding.location.startLine);
      // Focus follows the row across the re-render, or the keyboard user is
      // dumped back at the top of the document every time they open a finding.
      const again = $('ledger').querySelector(`.row[data-id="${CSS.escape(id)}"] .row-head`);
      if (again && document.activeElement !== again) again.focus();
    });
    // A hop can point into a DIFFERENT file - that is the whole point of
    // cross-file tracing, so activating one has to be able to switch files.
    for (const hop of row.querySelectorAll('.hop')) {
      hop.addEventListener('click', () => openFile(hop.dataset.file, Number(hop.dataset.line)));
    }
  }
}

function render(result) {
  if (result.score) renderGauges(result.score);
  const flow = result.findings.filter((f) => f.confidence === 'flow-verified').length;
  const sig = result.findings.length - flow;
  const sev = {};
  for (const f of result.findings) sev[f.severity] = (sev[f.severity] ?? 0) + 1;

  const severityLine = ['critical', 'high', 'medium', 'low', 'info']
    .filter((s) => sev[s])
    .map((s) => `${sev[s]} ${s}`)
    .join(' · ');

  $('summary').innerHTML = [
    tile(flow, 'flow-verified', 'attacker data traced into the sink', 'tile-verified'),
    tile(sig, 'signature-based', 'pattern matched, data flow NOT traced', 'tile-signature'),
    tile(result.stats.filesParsed, 'files parsed', severityLine || 'no findings'),
    tile(
      `${result.stats.durationMs}ms`,
      'scan time',
      result.crossFile.enabled
        ? `${result.crossFile.resolved} cross-file call(s) followed, ${result.crossFile.ambiguous} declined`
        : 'cross-file off',
    ),
  ].join('');

  const engine = result.coverage.engine;
  const partial = result.coverage.gaps.filter((c) => c.status === 'partial');
  const noTaint = result.coverage.taint.filter((t) => !t.implemented);

  // Analysis depth, stated POSITIVELY, for the languages actually in this scan.
  // The panel below only ever listed languages where taint is MISSING - so with
  // all five implemented it said nothing, and a reader with a stale belief
  // ("Go is signature-only") had nothing to correct it. Twice a tester wrote a
  // fixture on exactly that belief. A capability mentioned only in the negative
  // cannot be confirmed by the person who needs to trust it.
  const depthRows = Object.keys(result.byLanguage).sort().map((id) => {
    const cell = result.coverage.taint.find((t) => t.language === id);
    const deep = Boolean(cell?.implemented);
    return `<li class="depth ${deep ? 'deep' : 'shallow'}">
      <b>${escapeHtml(id)}</b>
      <span>${deep ? 'signature + data flow' : 'signature only - the tracer does not run here'}</span>
      <em>${num(result.byLanguage[id])} file(s)</em>
    </li>`;
  }).join('');

  $('gaps').innerHTML = `
    <p class="grouphead">OWASP Top 10 (2025) &mdash; ${result.coverage.owaspCoverage.filter((c) => c.state === 'none').length} of 10 have no rule at all</p>
    <p class="why">No category here is comprehensively covered &mdash; the three with rules
      are checked in part only, and what they leave out is named. Silence in a category with
      no rule is not a result: code full of those bugs looks exactly like code without.</p>
    <ul class="uncovered">${result.coverage.owaspCoverage.map((c) => `
      <li data-state="${escapeHtml(c.state)}">
        <b>${c.state === 'partial' ? 'PARTIAL' : 'NO RULE'}</b>
        <strong>${escapeHtml(c.id)}</strong> ${escapeHtml(c.title)}
        ${c.weCheck ? `<span class="does">we check ${escapeHtml(c.weCheck)}</span>` : ''}
        <span>${c.state === 'partial' ? 'in scope: ' : 'e.g. '}${escapeHtml(c.examples)}</span>
        ${c.note ? `<em>${escapeHtml(c.note)}</em>` : ''}</li>`).join('')}</ul>

    <p class="grouphead">Analysis depth in this scan</p>
    <ul class="depths">${depthRows}</ul>
    <p class="why">A flow-verified finding can only come from a language on the
      &ldquo;signature + data flow&rdquo; line. Where it says signature only, zero verified
      findings means the tracer never ran there &mdash; not that the code is clean.</p>

    <h3>Read this before treating the list above as complete</h3>
    <p class="why">A short findings list can mean "your code is fine" or it can mean
      "we did not look". These are the things this engine does not do, printed on
      every scan so the difference is never left to guesswork.</p>

    <p class="grouphead">Engine limits</p>
    <ul>${engine.notImplemented.map((x) => `<li>${escapeHtml(x)}</li>`).join('')}</ul>

    ${
      partial.length
        ? `<p class="grouphead">Rules with partial language coverage (${partial.length})</p>
           <ul>${partial
             .map((c) => `<li><b>${escapeHtml(c.ruleId)} / ${escapeHtml(c.language)}</b> — ${escapeHtml(c.note)}</li>`)
             .join('')}</ul>`
        : ''
    }
    ${
      noTaint.length
        ? `<p class="grouphead">Languages with no data-flow verification</p>
           <ul>${noTaint.map((t) => `<li><b>${escapeHtml(t.language)}</b> — ${escapeHtml(t.note)}</li>`).join('')}</ul>`
        : ''
    }
    ${
      result.parseProblems.length
        ? `<p class="grouphead">Files that did not fully parse (${result.parseProblems.length})</p>
           <ul>${result.parseProblems
             .slice(0, 8)
             .map((p) => `<li>${escapeHtml(p.file)}</li>`)
             .join('')}</ul>`
        : ''
    }
    <p class="why" style="margin:0">Coverage: ${num(result.coverage.counts.implemented)} implemented ·
      ${num(result.coverage.counts.partial)} partial · ${num(result.coverage.counts.notImplemented)} not implemented
      (of ${num(result.coverage.counts.rules)} rules × ${num(result.coverage.counts.languages)} languages)</p>`;

  selectedId = null;
  openPath = null;
  renderTree();
  renderFindings();

  // Open the file with the most findings, so the deck is never empty on arrival.
  const busiest = [...sources.keys()].sort(
    (a, b) => findingsFor(b).length - findingsFor(a).length,
  )[0];
  if (busiest) openFile(busiest);

  $('progress').style.display = 'none';
  $('results').style.display = 'block';
}

for (const button of $('filters').querySelectorAll('button[data-filter]')) {
  button.addEventListener('click', () => {
    filter = button.dataset.filter;
    for (const other of $('filters').querySelectorAll('button[data-filter]')) {
      other.setAttribute('aria-pressed', String(other === button));
    }
    renderFindings();
  });
}

$('download').addEventListener('click', () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'ns1-findings.json';
  link.click();
  URL.revokeObjectURL(link.href);
});

/* ------------------------------------------------------------------ sample */

const SAMPLE = [
  {
    path: 'sample/handler.js',
    source: `const { runQuery } = require('./db');
const escapeHtml = require('escape-html');

// The source is here; the sink is one file away in db.js.
function listUsers(req) {
  return runQuery("SELECT * FROM users WHERE id = " + req.query.id);
}

// Escaped for HTML, then used in HTML - the right soap for the job.
function greet(req, el) {
  el.innerHTML = "<b>Hello " + escapeHtml(req.query.name) + "</b>";
}

// A number cannot carry a quote, so this one is provably clean.
function byNumericId(req, db) {
  const id = parseInt(req.query.id, 10);
  return db.query("SELECT * FROM users WHERE id = " + id);
}
`,
  },
  {
    path: 'sample/db.js',
    source: `const conn = require('./conn');

function runQuery(sqlText) {
  return conn.query(sqlText);
}

module.exports = { runQuery };
`,
  },
  {
    path: 'sample/report.py',
    source: `import subprocess
from flask import request


def export(cursor):
    # SQL built with an f-string from a request parameter.
    cursor.execute(f"SELECT * FROM orders WHERE name = '{request.args['name']}'")


def ping():
    # A shell command glued together from user input.
    subprocess.run("ping -c 1 " + request.args["host"], shell=True)


API_KEY = "AKIAIOSFODNN7EXAMPLE"
`,
  },
];

$('sample').addEventListener('click', () => scan(SAMPLE));
