// FIXTURE: Cross-site scripting, Go html/template escape hatch.
package fixtures

import "html/template"

func bio(name string) template.HTML {
	// EXPECT xss
	return template.HTML("<div class=\"bio\">" + name + "</div>")
}
