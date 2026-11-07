package xmltree

import (
	"errors"
	"strings"
	"testing"
)

func mustParse(t *testing.T, s string) *Document {
	t.Helper()
	doc, err := Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestNamespacesAndNames(t *testing.T) {
	doc := mustParse(t, `<p:r xmlns:p="urn:p" xmlns="urn:d" p:a="1" b="2"><c/><p:d xmlns:p="urn:q"/></p:r>`)
	r := doc.Root
	if r.Space != "urn:p" || r.Local != "r" || r.QName() != "p:r" {
		t.Fatalf("%+v", r)
	}
	if v, ok := r.Attr("urn:p", "a"); !ok || v != "1" {
		t.Error("prefixed attribute")
	}
	if v, ok := r.Attr("", "b"); !ok || v != "2" {
		t.Error("an unprefixed attribute has no namespace, whatever the default")
	}
	if c := r.Child("urn:d", "c"); c == nil {
		t.Error("an unprefixed element takes the default namespace")
	}
	if d := r.Child("urn:q", "d"); d == nil {
		t.Error("a redeclared prefix")
	}
	if len(r.NSDecls) != 2 || r.NSDecls[0] != (NSDecl{"p", "urn:p"}) || r.NSDecls[1] != (NSDecl{"", "urn:d"}) {
		t.Errorf("declarations are kept in order: %+v", r.NSDecls)
	}
}

func TestAttributeWhitespaceIsNormalizedButReferencesAreNot(t *testing.T) {
	doc := mustParse(t, "<r a=\"x\ty\nz\" b=\"x&#9;y&#10;z&#13;\"/>")
	if v, _ := doc.Root.Attr("", "a"); v != "x y z" {
		t.Errorf("literal: %q", v)
	}
	if v, _ := doc.Root.Attr("", "b"); v != "x\ty\nz\r" {
		t.Errorf("references: %q", v)
	}
}

func TestTextCommentsAndCDATA(t *testing.T) {
	doc := mustParse(t, `<r>a<![CDATA[<b>]]>c<!--x-->d&amp;&#x41;<?pi data?></r>`)
	kids := doc.Root.Children
	if len(kids) != 4 || kids[0].Data != "a<b>c" || kids[1].Kind != Comment || kids[2].Data != "d&A" || kids[3].Target != "pi" {
		t.Fatalf("%+v", kids)
	}
	if doc.Root.TextContent() != "a<b>cd&A" {
		t.Errorf("text content leaves out the comment: %q", doc.Root.TextContent())
	}
}

func TestLineEndingsAndBOM(t *testing.T) {
	doc := mustParse(t, "\ufeff<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<r>1\r\n2\r3&#13;</r>")
	if doc.Root.TextContent() != "1\n2\n3\r" {
		t.Errorf("%q", doc.Root.TextContent())
	}
}

func TestWhatIsRefused(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`, "DTD"},
		{`<?xml version="1.0"?><!DOCTYPE r><r/>`, "DTD"},
		{`<r>&x;</r>`, "not defined"},
		{`<r><a></b></r>`, "closed by"},
		{`<r a="1" a="2"/>`, "twice"},
		{`<r xmlns:p="urn:x" xmlns:q="urn:x" p:a="1" q:a="2"/>`, "two attributes"},
		{`<p:r/>`, "not declared"},
		{`<r xmlns:p=""/>`, "undeclared"},
		{`<r xmlns:xml="urn:other"/>`, "cannot be bound"},
		{`<r xmlns:p="http://www.w3.org/XML/1998/namespace"/>`, "cannot be bound"},
		{`<r a="<"/>`, "< inside"},
		{`<r a=1/>`, "quoted"},
		{`<r a="1"b="2"/>`, "separated"},
		{`<r>]]></r>`, "]]>"},
		{`<r><!-- a -- b --></r>`, "-- inside"},
		{`<r>` + "\x01" + `</r>`, "not allowed"},
		{`<r a="` + "\x02" + `"/>`, "not allowed"},
		{`<r>&#0;</r>`, "not a character"},
		{`<r>&#x1b;[2J</r>`, "not a character"},
		{`<r>&#xD800;</r>`, "not a character"},
		{`<r>&#xZZ;</r>`, "not a character"},
		{`<r/><r/>`, "second root"},
		{`<r/>text`, "outside"},
		{``, "no root"},
		{`<?xml version="1.0" encoding="ISO-8859-1"?><r/>`, "UTF-8"},
		{"\xff\xfe<r/>", "UTF-8"},
		{`<r>`, "not closed"},
		{`<r a="x`, "closing quote"},
		{`<1r/>`, "bad element name"},
		{`<a:b:c xmlns:a="u"/>`, "bad element name"},
		{`<r><![CDATA[x</r>`, "CDATA"},
		{`<r><!ELEMENT x></r>`, "declaration inside"},
		{`<r><?xml x?></r>`, "target"},
		{`<r a="&#99999999;"/>`, "&"},
	} {
		_, err := Parse([]byte(c.in))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: got %v, want an error containing %q", c.in, err, c.want)
		}
	}
	if _, err := Parse([]byte(`<!DOCTYPE r><r/>`)); !errors.Is(err, ErrDTD) {
		t.Error("ErrDTD")
	}
}

func TestDepthIsLimited(t *testing.T) {
	deep := strings.Repeat("<a>", MaxDepth+1) + strings.Repeat("</a>", MaxDepth+1)
	if _, err := Parse([]byte(deep)); err == nil || !strings.Contains(err.Error(), "deep") {
		t.Fatalf("%v", err)
	}
	ok := strings.Repeat("<a>", MaxDepth) + strings.Repeat("</a>", MaxDepth)
	if _, err := Parse([]byte(ok)); err != nil {
		t.Fatal(err)
	}
}

func TestSyntaxErrorsSayWhere(t *testing.T) {
	_, err := Parse([]byte("<r>\n  <a></b></r>"))
	var se *SyntaxError
	if !errors.As(err, &se) || se.Offset < 6 {
		t.Fatalf("%v", err)
	}
}

func TestPaths(t *testing.T) {
	doc := mustParse(t, `<r><a/><b/><a><c/></a></r>`)
	var c *Node
	doc.Root.Walk(func(n *Node) bool {
		if n.Local == "c" {
			c = n
		}
		return true
	})
	if c.Path() != "r/a[2]/c" {
		t.Errorf("%s", c.Path())
	}
}
