package c14n

import (
	"testing"

	"github.com/sriharifortitude/samlsift/internal/xmltree"
)

func parse(t *testing.T, s string) *xmltree.Document {
	t.Helper()
	doc, err := xmltree.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

var (
	inc    = Options{}
	incCom = Options{WithComments: true}
	exc    = Options{Exclusive: true}
	excCom = Options{Exclusive: true, WithComments: true}
)

// The expected values were produced by libxml2, through lxml.
func TestDocumentsAgainstLibxml2(t *testing.T) {
	for _, c := range []struct {
		name, in string
		opt      Options
		want     string
	}{
		{"sorting", `<r xmlns:b="urn:b" xmlns:a="urn:a" z="1" a:y="2" b:x="3" a="4"/>`, inc,
			`<r xmlns:a="urn:a" xmlns:b="urn:b" a="4" z="1" a:y="2" b:x="3"></r>`},
		{"sorting, exclusive", `<r xmlns:b="urn:b" xmlns:a="urn:a" z="1" a:y="2" b:x="3" a="4"/>`, exc,
			`<r xmlns:a="urn:a" xmlns:b="urn:b" a="4" z="1" a:y="2" b:x="3"></r>`},
		{"escaping", "<r a=\"&lt;&amp;&quot;&#9;&#10;&#13;\" b=\"lit\ttab\">&lt;&amp;&gt;&#13;\"'</r>", inc,
			`<r a="&lt;&amp;&quot;&#x9;&#xA;&#xD;" b="lit tab">&lt;&amp;&gt;&#xD;"'</r>`},
		{"undoing the default namespace", `<r xmlns="urn:d"><c xmlns=""/></r>`, inc, `<r xmlns="urn:d"><c xmlns=""></c></r>`},
		{"undoing it, exclusive", `<r xmlns="urn:d"><c xmlns=""/></r>`, exc, `<r xmlns="urn:d"><c xmlns=""></c></r>`},
		{"unused declarations stay, inclusive", `<r xmlns:u="urn:u" xmlns:a="urn:a"><a:c/></r>`, inc,
			`<r xmlns:a="urn:a" xmlns:u="urn:u"><a:c></a:c></r>`},
		{"unused declarations go, exclusive", `<r xmlns:u="urn:u" xmlns:a="urn:a"><a:c/></r>`, exc, `<r><a:c xmlns:a="urn:a"></a:c></r>`},
		{"outside the root, without comments", `<?a b?><!--x--><r><!--y--><?c?></r><!--z-->`, inc, "<?a b?>\n<r><?c?></r>"},
		{"outside the root, with comments", `<?a b?><!--x--><r><!--y--><?c?></r><!--z-->`, incCom,
			"<?a b?>\n<!--x-->\n<r><!--y--><?c?></r>\n<!--z-->"},
		{"outside the root, exclusive with comments", `<?a b?><!--x--><r><!--y--><?c?></r><!--z-->`, excCom,
			"<?a b?>\n<!--x-->\n<r><!--y--><?c?></r>\n<!--z-->"},
		{"a redundant redeclaration is dropped", `<r xmlns:a="urn:a"><c xmlns:a="urn:a"/></r>`, inc, `<r xmlns:a="urn:a"><c></c></r>`},
		{"CDATA is text", `<r><![CDATA[a < b & c]]></r>`, inc, `<r>a &lt; b &amp; c</r>`},
		{"carriage returns are line feeds", "<r a=\"x\r\ny\">1\r\n2\r3</r>", inc, "<r a=\"x y\">1\n2\n3</r>"},
	} {
		if got := string(Document(parse(t, c.in), nil, c.opt)); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
}

func element(doc *xmltree.Document, local string) *xmltree.Node {
	var out *xmltree.Node
	doc.Root.Walk(func(n *xmltree.Node) bool {
		if out == nil && n.Kind == xmltree.Element && n.Local == local {
			out = n
		}
		return out == nil
	})
	return out
}

func TestSubtreesTakeTheirNamespacesFromAbove(t *testing.T) {
	doc := parse(t, `<r xmlns="urn:d" xmlns:a="urn:a" xmlns:u="urn:u"><a:c x="1"><e/></a:c></r>`)
	c := element(doc, "c")
	if got := string(Subtree(c, nil, inc)); got != `<a:c xmlns="urn:d" xmlns:a="urn:a" xmlns:u="urn:u" x="1"><e></e></a:c>` {
		t.Errorf("inclusive: %s", got)
	}
	if got := string(Subtree(c, nil, exc)); got != `<a:c xmlns:a="urn:a" x="1"><e xmlns="urn:d"></e></a:c>` {
		t.Errorf("exclusive: %s", got)
	}
}

func TestInclusiveCarriesXMLAttributesToTheApex(t *testing.T) {
	// Canonical XML 1.0 section 2.4; exclusive canonicalization does not.
	doc := parse(t, `<r xml:lang="en" xml:space="preserve"><m xml:lang="fr"><c a="1"/></m></r>`)
	c := element(doc, "c")
	if got := string(Subtree(c, nil, inc)); got != `<c a="1" xml:lang="fr" xml:space="preserve"></c>` {
		t.Errorf("inclusive: %s", got)
	}
	if got := string(Subtree(c, nil, exc)); got != `<c a="1"></c>` {
		t.Errorf("exclusive: %s", got)
	}
	m := element(doc, "m")
	if got := string(Subtree(m, nil, inc)); got != `<m xml:lang="fr" xml:space="preserve"><c a="1"></c></m>` {
		t.Errorf("the element's own xml:lang wins: %s", got)
	}
}

func TestInclusivePrefixList(t *testing.T) {
	doc := parse(t, `<r xmlns="urn:d" xmlns:a="urn:a" xmlns:u="urn:u" xmlns:v="urn:v"><a:c><e/></a:c></r>`)
	c := element(doc, "c")
	opt := Options{Exclusive: true, InclusivePrefixes: []string{"u", "missing"}}
	if got := string(Subtree(c, nil, opt)); got != `<a:c xmlns:a="urn:a" xmlns:u="urn:u"><e xmlns="urn:d"></e></a:c>` {
		t.Errorf("a listed prefix is rendered as inclusive canonicalization would: %s", got)
	}
	// "#default" names the default namespace (Exclusive XML Canonicalization, section 3).
	opt.InclusivePrefixes = []string{"#default"}
	if got := string(Subtree(c, nil, opt)); got != `<a:c xmlns="urn:d" xmlns:a="urn:a"><e></e></a:c>` {
		t.Errorf("#default: %s", got)
	}
}

func TestLeavingOutASubtree(t *testing.T) {
	doc := parse(t, `<r><a/><s><t/></s><b/></r>`)
	s := element(doc, "s")
	if got := string(Subtree(doc.Root, s, inc)); got != `<r><a></a><b></b></r>` {
		t.Errorf("subtree: %s", got)
	}
	if got := string(Document(doc, s, exc)); got != `<r><a></a><b></b></r>` {
		t.Errorf("document: %s", got)
	}
}

func TestAlgorithms(t *testing.T) {
	for uri, want := range map[string]Options{Inclusive: inc, InclusiveWithComments: incCom, Exclusive: exc, ExclusiveWithComments: excCom} {
		got, ok := ForAlgorithm(uri)
		if !ok || got.Exclusive != want.Exclusive || got.WithComments != want.WithComments {
			t.Errorf("%s: %+v", uri, got)
		}
	}
	if _, ok := ForAlgorithm("http://www.w3.org/2006/12/xml-c14n11"); ok {
		t.Error("Canonical XML 1.1 is not implemented")
	}
}
