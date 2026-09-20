// REACT XSS, TRACED FROM A REAL SOURCE.
//
// The TSX fixture that existed before this one was six lines long and had no
// source in it: a component took an `html` prop from nowhere and passed it to
// `dangerouslySetInnerHTML`. That earns a signature-based finding, which is
// the honest label for it - a shape was matched, nothing was followed.
//
// So `.tsx` was in the same position `.ts` was: claimed as a supported
// language with data-flow analysis, and never once traced end to end.
//
// React is also the one place in this suite where the FRAMEWORK does the
// escaping. `{value}` in JSX text is escaped by React before it reaches the
// DOM; `dangerouslySetInnerHTML` is the documented way to ask it not to. A
// scanner that cannot tell those two apart will either miss every real React
// XSS or report every React component ever written, and the cases below pin
// the line between them from both sides.

declare function purify(value: string): string;

interface Props {
  readonly bio: string;
}

// ---------------------------------------------------------------------------
// 1. The address bar to the inner HTML, in one function.
//
// `location.search` is attacker-controlled by anyone who can get a link
// clicked, which is the entire point of the source being in the dictionary.
// ---------------------------------------------------------------------------
export function DirectFromLocation() {
  const raw = location.search;
  // EXPECT-FLOW xss
  const markup = { __html: raw };
  return <div dangerouslySetInnerHTML={markup} />;
}

// ---------------------------------------------------------------------------
// 2. The same, with the value laundered through a TypeScript cast on the way.
//
// This is case 3 of ts-only-syntax.ts arriving in a different grammar. The
// `.tsx` grammar is a separate tree-sitter grammar from `.ts`, so the fix that
// made the angle-bracket cast work over there proves nothing over here - and
// in .tsx the angle-bracket form is unavailable anyway, because `<string>x`
// is a JSX tag. `as` is the only spelling React developers can use, which is
// why it is the one tested here.
// ---------------------------------------------------------------------------
export function ThroughCast() {
  const raw = location.hash as string;
  // EXPECT-FLOW xss
  const markup = { __html: raw };
  return <div dangerouslySetInnerHTML={markup} />;
}

// ---------------------------------------------------------------------------
// 3. The object literal written inline at the sink.
//
// The shape almost every real React codebase actually uses, because nobody
// names the wrapper object.
// ---------------------------------------------------------------------------
export function InlineObject() {
  const raw = document.location.href;
  // EXPECT-FLOW xss
  return <div dangerouslySetInnerHTML={{ __html: raw }} />;
}

// ---------------------------------------------------------------------------
// 4. Storage as the source.
//
// `localStorage` is in the source list because any script on the page can
// write it, which makes it attacker-reachable through a different door than
// the URL.
// ---------------------------------------------------------------------------
export function FromStorage() {
  const raw = localStorage.getItem('draft-bio') ?? '';
  // EXPECT-FLOW xss
  return <span dangerouslySetInnerHTML={{ __html: raw }} />;
}

// ---------------------------------------------------------------------------
// 5. SANITISED. Must stay silent.
//
// `purify` is in the sanitiser list for html sinks. If this fires, the tool is
// loudest at exactly the developer who reached for DOMPurify, which is the
// worst possible place to be wrong.
// ---------------------------------------------------------------------------
export function Sanitised() {
  const raw = location.search;
  const clean = purify(raw);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

// ---------------------------------------------------------------------------
// 6. JSX TEXT. Must stay silent, and this is the important one.
//
// React escapes every expression it renders as a child. `{raw}` here is safe
// no matter what `raw` contains - that is the whole reason
// `dangerouslySetInnerHTML` exists and is spelled the way it is.
//
// Flagging this would be the single most common false positive it is possible
// to have in a React codebase, because this line is in every component. It is
// annotated with nothing on purpose: the assertion is the silence.
// ---------------------------------------------------------------------------
export function EscapedByReact() {
  const raw = location.search;
  return <div title={raw}>{raw}</div>;
}

// ---------------------------------------------------------------------------
// 7. A prop crossing a component boundary. A DOWNGRADE, NOT A JSX PROBLEM.
//
// Predicted EXPECT-FLOW. It comes back signature-based instead - reported, but
// with no path attached.
//
// The obvious story is that JSX element syntax is not recognised as a call.
// The controls say that story is wrong. Calling the same component as an
// ordinary function, `Card({ bio: raw })`, is downgraded in exactly the same
// way, while a plain function taking a plain string argument, `emit(raw)`, is
// traced end to end. So the boundary is not the problem and the angle brackets
// are not the problem: the DESTRUCTURED OBJECT PARAMETER is. The value goes in
// as a property of an object literal and comes out of a destructuring pattern,
// and the engine does not track the interior of objects.
//
// That is the third appearance of the same limitation in these two files, in
// three costumes - an interface-typed literal, a constructor parameter
// property, and now a React prop. Tracking object interiors is the single
// largest thing this engine does not do, and every language here pays for it.
//
// Left annotated with nothing. It is a real vulnerability and the tool DOES
// report it - honestly, as signature-based - so the silence being asserted
// here is only the absence of a proof that was never earned.
// ---------------------------------------------------------------------------
function BioCard({ bio }: Props) {
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}

export function Parent() {
  const raw = location.search;
  return <BioCard bio={raw} />;
}
