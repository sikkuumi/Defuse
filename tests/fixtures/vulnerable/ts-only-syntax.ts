// TYPESCRIPT-ONLY SYNTAX BETWEEN A SOURCE AND A SINK.
//
// WHY THIS FILE EXISTS.
//
// `dictionaries.ts` maps TypeScript to the JavaScript dictionary in one line:
//
//     typescript: JS_DICTIONARY,
//
// and the coverage note printed on every scan said, in full:
//
//     "IMPLEMENTED: identical to JavaScript, including .tsx."
//
// That is an assertion about a language this suite had never traced. Before
// this file, TypeScript had six fixture findings and every one of them was
// signature-based - a pattern matched in the syntax tree, no path walked. So
// the tool was claiming data-flow analysis on TypeScript while holding zero
// evidence that a TypeScript value had ever been followed from a source to a
// sink. That is exactly the shape of overclaim this project exists to refuse,
// and it was sitting in our own coverage note.
//
// The dictionary being shared is not the question. The GRAMMAR is not shared.
// TypeScript has its own tree-sitter grammar, and every construct below is a
// node type the JavaScript lowerer has never once encountered. Any of them
// could sit between a source and a sink and quietly end a trace, and nothing
// in 292 checks would have noticed.
//
// HOW TO READ THE ANNOTATIONS.
//
// Every case below was annotated EXPECT-FLOW before the engine was run,
// because that is what the claim predicts: if TypeScript really is "identical
// to JavaScript", the wrapper is invisible and the path is walked. The
// annotations were a PREDICTION, not a transcript.
//
// WHAT THE FIRST RUN SAID.
//
// Eleven of fifteen predictions held. Four failed, and every failure was a
// COMPLETE MISS rather than a downgrade - the "Unverified surface" gauge read
// 0 for this file, so these were not findings wearing a cautious label, they
// were vulnerable lines the tool never mentioned at all.
//
// Then the failures were sorted, which is the part that changed the answer.
// Each one was rewritten in plain JavaScript and scanned again. Three of the
// four were missed in JavaScript too - so they are general limitations of this
// engine that TypeScript merely happened to expose, and filing them as
// TypeScript bugs would have been a false report in a file written to prevent
// false reports. They are kept below, unannotated, with the control result
// recorded next to each.
//
// Exactly ONE failure was TypeScript's alone: case 3. It was a real bug in
// src/taint/tracer.ts and it is now fixed.
//
// One in four. The claim "identical to JavaScript" was mostly true, and being
// mostly true is not the same as being tested - it was luck until this file
// existed, and the one case that was not lucky had been broken from the day
// TypeScript was added.

import { exec } from 'child_process';

declare const db: { query(sql: string): Promise<unknown> };
declare function render(el: HTMLElement): void;

interface Req {
  query: Record<string, string>;
  body: Record<string, string>;
}

// ---------------------------------------------------------------------------
// 1. An explicit type annotation on the carrier.
//
// The simplest TypeScript there is, and the one that appears in front of
// roughly every variable in a real codebase. In the JavaScript grammar a
// `const` binding has two children; here it has three.
// ---------------------------------------------------------------------------
export function annotatedBinding(req: Req): void {
  const cmd: string = req.query.path;
  // EXPECT-FLOW command-injection
  exec(cmd);
}

// ---------------------------------------------------------------------------
// 2. An `as` cast.
//
// `as` is the single most common TypeScript-only expression in existence. It
// wraps the value in an `as_expression` node that does not exist in the
// JavaScript grammar at all. If the lowerer does not see through it, every
// cast in a codebase becomes a wall that taint cannot cross.
// ---------------------------------------------------------------------------
export function asCast(req: Req): void {
  const cmd = req.query.path as string;
  // EXPECT-FLOW command-injection
  exec(cmd);
}

// ---------------------------------------------------------------------------
// 3. The angle-bracket cast, which is the same operation spelled the old way.
//
// Included separately because it is a DIFFERENT node type from `as`, so
// handling one says nothing about the other.
//
// THIS ONE CAUGHT A REAL BUG, and the reason is worth keeping.
//
// `type_assertion` had been listed as a transparent wrapper in the tracer
// since the file was written. Being listed only says "see through this node";
// it says nothing about WHICH SIDE the value is on. `as` parses as
// [value, type] and `<string>x` parses as [type, value], so the unwrapper -
// which took the first named child - handed the tracer the word `string` and
// was told it was clean. Every angle-bracket cast in every TypeScript file
// ever scanned was a wall that taint could not cross, silently.
//
// The same defect, in the same function, had already been found once for Java
// casts and fixed narrowly for `cast_expression` alone. It took a fixture in a
// third language to show that the narrow fix had left the door open. See
// TYPE_FIRST_WRAPPERS in src/taint/tracer.ts.
// ---------------------------------------------------------------------------
export function angleBracketCast(req: Req): void {
  const cmd = <string>req.query.path;
  // EXPECT-FLOW command-injection
  exec(cmd);
}

// ---------------------------------------------------------------------------
// 4. The non-null assertion.
//
// `!` is how a TypeScript developer silences the compiler about a value that
// might be undefined - which means it clusters precisely around values that
// came from outside the program. Attacker data wears this operator more often
// than average, not less.
// ---------------------------------------------------------------------------
export function nonNullAssertion(req: Req): void {
  const cmd = req.query.path!;
  // EXPECT-FLOW command-injection
  exec(cmd);
}

// ---------------------------------------------------------------------------
// 5. The double assertion.
//
// `as unknown as T` is the escape hatch people reach for when the compiler
// refuses the single cast. Two nested `as_expression` nodes: a lowerer that
// unwraps one level and stops would pass case 2 and fail this one, which is
// why testing only the easy spelling proves less than it appears to.
// ---------------------------------------------------------------------------
export function doubleAssertion(req: Req): void {
  const cmd = req.body.script as unknown as string;
  // EXPECT-FLOW code-injection
  eval(cmd);
}

// ---------------------------------------------------------------------------
// 6. `satisfies`.
//
// The newest of these operators, and the one most likely to have been missed
// simply because it did not exist when most taint engines were written.
// ---------------------------------------------------------------------------
export function satisfiesOperator(req: Req): void {
  const sql = req.query.filter satisfies string;
  // EXPECT-FLOW sql-injection
  void db.query('SELECT * FROM users WHERE name = ' + sql);
}

// ---------------------------------------------------------------------------
// 7. A generic identity function.
//
// The call crosses a function boundary, which the engine already handles in
// JavaScript - but the declaration carries type parameters, so the function
// node has a shape the JavaScript lowerer never indexes. If generics break
// the call graph, taint stops at the door of every utility function in a
// typed codebase, and those are the functions values travel through most.
// ---------------------------------------------------------------------------
function identity<T>(value: T): T {
  return value;
}

export function throughGeneric(req: Req): void {
  const cmd = identity(req.query.path);
  // EXPECT-FLOW command-injection
  exec(cmd);
}

// ---------------------------------------------------------------------------
// 8. An interface-typed object literal. A MISS, AND NOT A TYPESCRIPT ONE.
//
// This was annotated EXPECT-FLOW on the prediction above. It failed, and the
// first instinct was to write it up as a third TypeScript bug. It is not.
//
// The control: the same shape in plain JavaScript, with no interface and no
// annotation, is missed in exactly the same way. The cause is the engine's
// already-declared limitation - the `gap` block printed under every traced
// finding ends with "and does not track the interior of objects" - and the
// interface in front of the literal changes nothing about it.
//
// Left here unannotated rather than deleted. A vulnerable line that this tool
// does not report is worth more in the fixture set than out of it, and the
// note above is the difference between a known gap and a silent one.
// ---------------------------------------------------------------------------
interface Payload {
  readonly cmd: string;
}

export function interfaceTypedObject(req: Req): void {
  const payload: Payload = { cmd: req.query.path };
  exec(payload.cmd);
}

// ---------------------------------------------------------------------------
// 9. A constructor parameter property. ALSO A MISS, ALSO NOT A TYPESCRIPT ONE.
//
// `constructor(private readonly cmd: string)` declares a parameter AND a field
// in one breath, and the field is never written anywhere in the source text -
// which made it look like a guaranteed TypeScript-specific failure.
//
// The control says otherwise. Writing the field the explicit JavaScript way,
// `constructor(cmd) { this.cmd = cmd; }`, and reading it back in a method is
// missed identically. So the parameter property is not what breaks it: taint
// does not survive a trip through a field between two methods in ANY language
// here. Same object-interior limitation as case 8, reached by a different
// road.
//
// This is the correction that mattered most in writing this file. Three of the
// four initial failures were about to be filed as TypeScript bugs. Two of them
// were the engine's general shape, and only a control in another language
// could tell the difference.
// ---------------------------------------------------------------------------
class Runner {
  constructor(private readonly cmd: string) {}

  run(): void {
    exec(this.cmd);
  }
}

export function parameterProperty(req: Req): void {
  new Runner(req.query.path).run();
}

// ---------------------------------------------------------------------------
// 10. A namespace. A MISS, AND THE THIRD ONE THAT IS NOT TYPESCRIPT'S FAULT.
//
// Namespaces wrap declarations in a block the JavaScript grammar has no node
// for, so this looked TypeScript-specific too.
//
// The control: an object literal with a method - `const Shell = { run(c) {...} }`
// called as `Shell.run(x)` - is missed the same way in plain JavaScript. The
// call graph indexes functions by name and resolves a bare `run(x)`; a call
// written as `Something.run(x)` is a member expression, and the trace ends at
// the dot. The namespace is incidental.
//
// Worth stating plainly, because it is a bigger hole than the one this file
// was written to find: a method call on any object ends the trace, in every
// language here. That is not on the TypeScript list. It is on the real list.
// ---------------------------------------------------------------------------
namespace Shell {
  export function run(command: string): void {
    exec(command);
  }
}

export function throughNamespace(req: Req): void {
  Shell.run(req.query.path);
}

// ---------------------------------------------------------------------------
// 11. An enum used as a key.
//
// The enum declaration itself is TypeScript-only. The lookup is a single read
// out of an object that was written once, so the container rule should leave
// the proof intact - one write is not a guess.
// ---------------------------------------------------------------------------
enum Field {
  Path = 'path',
}

export function enumKeyedLookup(req: Req): void {
  const cmd = req.query[Field.Path];
  // EXPECT-FLOW command-injection
  exec(cmd);
}

// ---------------------------------------------------------------------------
// 12. An abstract class with an overridden method.
//
// `abstract` and `override` are both TypeScript-only modifiers sitting in
// front of otherwise ordinary class members.
// ---------------------------------------------------------------------------
abstract class Handler {
  abstract handle(input: string): void;
}

class ExecHandler extends Handler {
  override handle(input: string): void {
    // EXPECT-FLOW command-injection
    exec(input);
  }
}

export function throughAbstract(req: Req): void {
  new ExecHandler().handle(req.query.path);
}

// ---------------------------------------------------------------------------
// 13. A decorated method.
//
// Decorators attach a node in front of the member. Common in NestJS and
// Angular, which is to say common in exactly the server-side TypeScript most
// likely to be scanned.
// ---------------------------------------------------------------------------
function logged(
  _target: unknown,
  _key: string,
  descriptor: PropertyDescriptor,
): PropertyDescriptor {
  return descriptor;
}

class Controller {
  @logged
  search(term: string): void {
    // EXPECT-FLOW sql-injection
    void db.query('SELECT * FROM items WHERE name LIKE ' + term);
  }
}

export function throughDecoratedMethod(req: Req): void {
  new Controller().search(req.query.q);
}

// ---------------------------------------------------------------------------
// 14. An assignment sink reached through a cast.
//
// Combines the two halves: a TypeScript-only expression carrying the value,
// and a property assignment rather than a call as the destination.
// ---------------------------------------------------------------------------
export function castIntoAssignSink(req: Req, el: HTMLElement): void {
  const markup = req.query.bio as string;
  // EXPECT-FLOW xss
  el.innerHTML = markup;
  render(el);
}

// ---------------------------------------------------------------------------
// 15. A sanitiser called through a cast.
//
// The control for every case above. If the engine sees the cast but stops
// seeing the sanitiser, it would report this - so a pass here proves the
// wrapper is being unwrapped rather than the whole statement being skipped.
//
// Deliberately NOT annotated: this line must produce nothing at all.
// ---------------------------------------------------------------------------
declare function escapeHtml(value: string): string;

export function sanitisedThroughCast(req: Req, el: HTMLElement): void {
  const markup = escapeHtml(req.query.bio as string);
  el.innerHTML = markup;
  render(el);
}
