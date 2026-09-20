// EXPECT-NONE
//
// TYPE POSITIONS ARE NOT VALUE POSITIONS.
//
// This file is the other half of vulnerable/ts-only-syntax.ts, and it exists
// because of how that file's one real bug was fixed.
//
// The fix taught the tracer that `<string>x` puts its TYPE first and its value
// last, so the unwrapper now reaches past the type to get the value. A fix
// shaped like that has an obvious failure mode in the opposite direction: a
// tracer that has learned to walk around type syntax could just as easily walk
// INTO it and start treating type names as data.
//
// Nothing below moves a value anywhere. Every identifier that looks like it
// might be flowing is a type: a name the compiler erases before a single byte
// runs. If any of it is reported, the engine is reading the type layer as the
// value layer, and every generic in every TypeScript codebase becomes noise.
//
// The names are deliberately chosen to be tempting. `command`, `query` and
// `exec` all appear here as types or type members, in the same shapes the
// dictionary looks for on the value side.

// A type alias whose members are named exactly like the sinks.
export type Command = {
  readonly exec: string;
  readonly query: string;
};

// An interface extending another - `req.query` appears as a TYPE MEMBER PATH
// here, which is the closest a type can come to impersonating the source
// pattern the dictionary matches.
export interface Request {
  query: Record<string, string>;
}

export interface AuthedRequest extends Request {
  user: { id: number };
}

// `keyof` and indexed access types. `Request['query']` reads like a property
// access and is not one - there is no object, and nothing is read at runtime.
export type QueryOf<T extends Request> = T['query'];
export type Keys = keyof AuthedRequest;

// A conditional type and a mapped type, which between them contain more
// arrows and brackets than most real code and still move nothing.
export type Unwrapped<T> = T extends Promise<infer U> ? U : T;
export type AllOptional<T> = { [K in keyof T]?: T[K] };

// A generic constraint mentioning the source shape.
export function countKeys<T extends Request>(value: T): number {
  return Object.keys(value.query).length;
}

// An `as const` assertion over a literal. Constants, not input.
export const FIELDS = ['name', 'email'] as const;
export type Field = (typeof FIELDS)[number];

// An overload set. The first two lines are signatures with no body at all, so
// there is nothing in them to trace even in principle.
export function format(value: string): string;
export function format(value: number): string;
export function format(value: string | number): string {
  return String(value);
}

// An ambient declaration. No implementation exists anywhere in this file, so
// a call to it cannot be followed - and it must not be invented.
declare function externalHelper(input: string): string;

export function useAmbient(): string {
  return externalHelper('a fixed string');
}

// An angle-bracket cast over a CONSTANT. This is the direct regression guard
// for the TYPE_FIRST_WRAPPERS fix: the unwrapper now reaches the last named
// child of a type_assertion, and the last named child here is a string
// literal that no attacker chose.
export function castedConstant(): string {
  const safe = <string>'ls -la';
  return safe;
}

// A generic class where the type parameter shares a name with a sink kind.
export class Store<Query> {
  private readonly items: Query[] = [];

  add(item: Query): void {
    this.items.push(item);
  }

  all(): readonly Query[] {
    return this.items;
  }
}
