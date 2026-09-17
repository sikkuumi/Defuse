// EXPECT-NONE
//
// ESCAPERS ARE PER-FRAMEWORK, EXACTLY LIKE SOURCES WERE.
//
// A scan of Jenkins (2,064 files, 1,931 of them Java) produced four
// flow-verified findings. TWO OF THEM WERE JENKINS ESCAPING CORRECTLY:
//
//     hudson/Util.java:1932   Functions.htmlAttributeEscape(redirectUrl)
//
// The tracer found a real request parameter, followed it correctly through the
// code, and stopped at an escaper it had never heard of - so it called the line
// proven. That is the seventh time this project has punished a fix, and the
// second time it did so with a PROOF rather than a guess.
//
// The mistake underneath is one I had already made and already fixed, in the
// other direction. Scanning elasticsearch taught that SOURCES are per-framework
// rather than per-language: elasticsearch has zero `@RequestParam` and 783
// `RestRequest`, so a Java source list built from Spring saw nothing. I
// generalised that lesson for sources and never once applied its mirror image:
// a Java ESCAPER list built from Commons Text is just as parochial. Jenkins
// ships its own - htmlAttributeEscape, escapeEcmaScript - and so does ESAPI,
// and so will the next framework.
//
// Hence two fixes rather than one:
//
//   1. The Jenkins/ESAPI spellings were added to the Java sanitiser dictionary,
//      because a flow-verified finding is retracted by the TRACER's list, not
//      by the signature rule's.
//   2. A shape rule, `looksLikeAnEscaperCall`, now recognises a call whose name
//      contains escape/encode/sanitiz AND a markup word (html, xml, attribute,
//      ecma, entities...). A name list can only ever know the frameworks I have
//      already been shown. The shape covers the one I am shown next.
//
// The shape rule is deliberately broad, which is exactly the risk class that
// has bitten this project before - the lowercase-word rejection that dropped
// the corpus from 48 to 32, and the mathjs.eval regression caught only because
// dvna's flow count fell from 3 to 2. So the second half of this file matters
// more than the first: it names the calls that MUST still be treated as unsafe.

import java.io.PrintWriter;

public class JenkinsEscapers {

    // ---- Jenkins' own escaping API. All of these are correct output. ----
    public void jenkinsShapes(PrintWriter out, String redirectUrl, String name) {
        // The exact line from hudson/Util.java that was reported as proven XSS.
        out.printf("<a href='%s'>", Functions.htmlAttributeEscape(redirectUrl));

        // Same family, unqualified, and the String-returning variant.
        out.println(Functions.htmlAttributeEscapeString(name));

        // Commons Text spellings Jenkins also uses heavily. escapeEcmaScript is
        // the one for values landing inside a <script> block.
        out.println(StringEscapeUtils.escapeHtml4(name));
        out.println(StringEscapeUtils.escapeEcmaScript(name));
        out.println(StringEscapeUtils.escapeXml11(name));

        // ESAPI, which a different Java shop will use instead. Neither list is
        // more "standard" than the other - that is the whole point.
        out.println(ESAPI.encoder().encodeForHTML(name));
        out.println(ESAPI.encoder().encodeForHTMLAttribute(name));
        out.println(ESAPI.encoder().encodeForJavaScript(name));

        // Escaped inside an assembled string, which is where the assignment
        // branch has to see it rather than the call branch.
        String row = "<td>" + Functions.htmlAttributeEscape(name) + "</td>";
        out.println(row);
    }

    // ---- Names the SHAPE rule must recognise without being told. ----
    // None of these are in any dictionary. They are here because the next
    // framework will invent its own spelling and I will not be there to add it.
    public void unknownFrameworkShapes(PrintWriter out, String name) {
        out.println(Markup.sanitizeHtmlFragment(name));
        out.println(Templating.encodeHtmlEntities(name));
        out.println(view.escapeXmlAttribute(name));
    }
}

// THE OTHER HALF - deliberately NOT in this file, and it is what keeps the
// fixture honest. The shape rule requires a markup word for a reason:
//
//   escapeShellArg(cmd)   escapes for a SHELL, not for HTML. Still command
//                         injection, must still fire.
//   escapeSql(value)      escapes for SQL. Still SQL injection.
//   urlEncode(value)      percent-encoding is not HTML escaping; `<` survives
//                         it in an attribute context.
//
// See vulnerable/xss.java and vulnerable/cmdi.java. If the shape rule added
// here also silences those, this fixture passing means nothing at all.
