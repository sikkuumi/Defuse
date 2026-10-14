# Break-it probes

Each directory here is a small program that once fooled Defuse's constant
proof: a value the proof called fixed - and withdrew the finding for - that
can in fact carry something the program did not write. Most were written by an
agent whose only job was to find such programs, in two rounds:

- **Round one (p01-p32)** - Java: a class hidden by a variable, a pattern, a
  static import or an inherited member type; an inherited overload; `final`
  that was only a word in a comment; a local out of scope where the value is
  read; a `\u000a` that javac reads as a newline.
- **Round two (g, j, s, p01-py)** - Go, Java, JavaScript, TypeScript, Python:
  block-scoped declarations standing in for imports and package variables,
  Go's receivers, `goto`, type switches and `select`; records and enums;
  `toString()` reached through `+`; a lone carriage return ending a comment.

`p33`, `p34` were added while fixing them. The `c` directories (and `j11`-`j13`,
`k01`-`k07`) are shapes the proof already read correctly when probed, kept so
it stays that way.

Every `EXPECT rule` line must still be reported. `npm test` scans each
directory on its own - they reuse class names - under "Break-it probes".
