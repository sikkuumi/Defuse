/**
 * Terminal colour, in about forty lines and zero dependencies.
 *
 * ANSI escape codes are just special character sequences: printing "\x1b[31m"
 * tells the terminal "red from here", and "\x1b[0m" means "back to normal".
 * Every colour library is a wrapper around that idea.
 *
 * We turn colour OFF when output is being piped into a file or another program
 * (`process.stdout.isTTY` is false), and we honour the NO_COLOR convention,
 * because escape codes in a log file are unreadable garbage.
 */

const enabled =
  process.env['NO_COLOR'] === undefined &&
  process.env['TERM'] !== 'dumb' &&
  process.stdout.isTTY === true;

function wrap(open: number, close: number) {
  return (text: string): string => (enabled ? `\x1b[${open}m${text}\x1b[${close}m` : text);
}

export const color = {
  enabled,
  bold: wrap(1, 22),
  dim: wrap(2, 22),
  italic: wrap(3, 23),
  underline: wrap(4, 24),
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  blue: wrap(34, 39),
  magenta: wrap(35, 39),
  cyan: wrap(36, 39),
  white: wrap(37, 39),
  gray: wrap(90, 39),
  bgRed: wrap(41, 49),
  bgYellow: wrap(43, 49),
};

/** Word-wrap a paragraph to `width`, indenting every line after the first. */
export function wrapText(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    if (current.length === 0) {
      current = word;
    } else if (current.length + 1 + word.length <= width) {
      current += ` ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);
  return lines.join(`\n${indent}`);
}


/**
 * BOX-DRAWING GLYPHS, AND WHY THEY NEED A FALLBACK
 *
 * The report uses characters like ─ ✓ ● because they read well in a terminal.
 * They are also a portability hazard: they are multi-byte UTF-8, and the moment
 * output leaves a UTF-8 terminal the bytes can be re-interpreted by something
 * that assumes a legacy code page. Redirecting a scan to a file on Windows and
 * opening it in Notepad turns every `──` into `ÔöÇÔöÇ` - the report becomes
 * unreadable while the analysis behind it was perfectly correct.
 *
 * So: one table, two spellings, and a switch. ASCII is chosen automatically
 * when output is being redirected on Windows (the case that actually breaks),
 * and can be forced anywhere with --ascii or NS1_ASCII=1.
 */
let asciiMode =
  process.env['NS1_ASCII'] === '1' ||
  (process.platform === 'win32' && process.stdout.isTTY !== true);

export function setAsciiMode(enabled: boolean): void {
  asciiMode = enabled;
}

const GLYPHS = {
  rule: ['\u2500', '-'],
  vertical: ['\u2502', '|'],
  cornerTop: ['\u250c', '+'],
  cornerBottom: ['\u2514', '+'],
  tick: ['\u2713', 'ok'],
  cross: ['\u2717', 'X'],
  dotFull: ['\u25cf', '*'],
  dotHalf: ['\u25d0', '~'],
  dotEmpty: ['\u25cb', 'o'],
  middot: ['\u00b7', '-'],
  arrow: ['\u2192', '->'],
  ellipsis: ['\u2026', '...'],
} as const;

export type GlyphName = keyof typeof GLYPHS;

/** The right spelling of a glyph for wherever this output is going. */
export function g(name: GlyphName): string {
  const pair = GLYPHS[name];
  return asciiMode ? pair[1] : pair[0];
}
