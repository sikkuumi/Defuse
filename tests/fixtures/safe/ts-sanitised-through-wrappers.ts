// EXPECT-NONE
//
// A SANITISER MUST STILL BE VISIBLE THROUGH A TYPESCRIPT WRAPPER.
//
// Unwrapping is not free. Every node the tracer learns to see through is a
// node it could also learn to see PAST - skipping the statement rather than
// stepping into it. The difference does not show up in a vulnerable fixture,
// because a tracer that skips a sanitiser and a tracer that never saw one both
// report the same finding. It only shows up here.
//
// Each case below takes a genuinely attacker-controlled value - the sources
// are real, and without them this file would prove nothing - escapes it, and
// then puts a TypeScript wrapper somewhere in the path. All of it must stay
// silent. A finding in this file means the escape stopped being counted the
// moment a type appeared next to it, which would make the engine loudest
// precisely where a developer had done the right thing.

declare function escapeHtml(value: string): string;
declare function shellQuote(value: string): string;
declare const db: { query(sql: string): Promise<unknown> };

import { exec } from 'child_process';

interface Req {
  query: Record<string, string>;
  body: Record<string, string>;
}

// The sanitiser's ARGUMENT is cast. The escape happens outside the wrapper.
export function castInsideSanitiser(req: Req, el: HTMLElement): void {
  el.innerHTML = escapeHtml(req.query.bio as string);
}

// The sanitiser's RESULT is cast. The escape happens inside the wrapper, which
// is the harder direction: the tracer has to come back out still knowing the
// value was cleaned.
export function castOutsideSanitiser(req: Req, el: HTMLElement): void {
  el.innerHTML = escapeHtml(req.query.bio) as string;
}

// Angle-bracket spelling of the same thing, since it is a different node.
export function angleBracketOutsideSanitiser(req: Req, el: HTMLElement): void {
  el.innerHTML = <string>escapeHtml(req.query.bio);
}

// A non-null assertion between the escape and the sink.
export function assertionAfterSanitiser(req: Req, el: HTMLElement): void {
  const clean = escapeHtml(req.query.bio)!;
  el.innerHTML = clean;
}

// A double assertion, which is two wrappers deep.
export function doubleAssertionAfterSanitiser(req: Req, el: HTMLElement): void {
  const clean = escapeHtml(req.query.bio) as unknown as string;
  el.innerHTML = clean;
}

// `satisfies` between the escape and the sink.
export function satisfiesAfterSanitiser(req: Req, el: HTMLElement): void {
  const clean = escapeHtml(req.query.bio) satisfies string;
  el.innerHTML = clean;
}

// The escape crosses a generic function boundary on its way to the sink. The
// call graph has to carry the CLEAN status through, not just the taint.
function passThrough<T>(value: T): T {
  return value;
}

export function sanitisedThroughGeneric(req: Req, el: HTMLElement): void {
  const clean = passThrough(escapeHtml(req.query.bio));
  el.innerHTML = clean;
}

// A command sink with a shell-quoting sanitiser and a cast in the middle.
export function quotedThroughCast(req: Req): void {
  const safe = shellQuote(req.query.path as string);
  exec(safe);
}

// A numeric coercion is a sanitiser for SQL: whatever the attacker typed, what
// reaches the query is a number. The annotation on the binding is the only
// TypeScript here, and it must not hide the coercion.
export function numericCoercionWithAnnotation(req: Req): void {
  const id: number = Number(req.query.id);
  void db.query('SELECT * FROM users WHERE id = ' + id);
}
