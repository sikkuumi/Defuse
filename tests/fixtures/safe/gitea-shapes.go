// EXPECT-NONE
//
// THREE SHAPES FROM SCANNING GITEA (3,338 files, 359 findings).

package fixtures

import (
	"fmt"
	"html"
	"html/template"
)

// 1. AN OAUTH SCOPE IS A NAME, NOT A CREDENTIAL.
//
// 106 of gitea's 359 findings were high-severity "hardcoded secret", and this
// block is most of them. The constant's NAME contains "Token", which is the
// whole reason the name-based signal exists - but the VALUE is `read:admin`,
// a colon-separated scope identifier out of the OAuth spec. It is printed in
// gitea's own API documentation. A credential carries no information about
// itself; this carries nothing else.
type AccessTokenScope string

const (
	AccessTokenScopeReadAdmin        AccessTokenScope = "read:admin"
	AccessTokenScopeWriteAdmin       AccessTokenScope = "write:admin"
	AccessTokenScopeReadActivityPub  AccessTokenScope = "read:activitypub"
	AccessTokenScopeWriteNotifcation AccessTokenScope = "write:notification"
)

// 2. ESCAPING EVERY VALUE AND THEN SAYING "THIS IS HTML" IS THE CORRECT CODE.
//
// Nine more findings were this, at HIGH. `template.HTML` is an escape hatch and
// the rule is right to watch it: it tells Go's template engine "do not escape
// this". But the promise is only hollow when something inside it is unescaped,
// and gitea escapes every single interpolation before making it - which is the
// only way to return assembled HTML from a Go template helper at all.
//
// Reporting this is the worst kind of false positive, because the thing being
// reported IS the fix. A developer who acts on it removes the escaping.
func avatarHTML(class, src, name string) template.HTML {
	return template.HTML(`<img loading="lazy" alt class="` + html.EscapeString(class) +
		`" src="` + html.EscapeString(src) + `" title="` + html.EscapeString(name) + `">`)
}

func iconHTML(icon, name string) template.HTML {
	return template.HTML(fmt.Sprintf("<span>%s(%s)</span>",
		template.HTMLEscapeString(icon), template.HTMLEscapeString(name)))
}

// A KNOWN GAP, written down rather than papered over. gitea really has
//
//     fmt.Sprintf("<span>%s(%d/%s)</span>", template.HTMLEscapeString(icon), size, ...)
//
// where `size` is an int and cannot carry markup - the `%d` verb proves it. The
// check added here only recognises escaper CALLS, so a mixed escaped/numeric
// argument list still reports. Reading Go format verbs to prove the numeric
// ones safe is the obvious next step and is not done yet, so that line stays a
// false positive and is not hidden in this fixture pretending otherwise.

func linkHTML(href, label string) template.HTML {
	return template.HTML("<strong>" + html.EscapeString(href) + html.EscapeString(label) + "</strong>")
}

// STILL REPORTED, and the reason this fixture is not just a licence to ignore
// template.HTML: see vulnerable/xss.go, where one interpolation is raw. One
// unescaped value in an otherwise escaped string is exactly the bug, and the
// proof above has to fail on it or it proves nothing.
