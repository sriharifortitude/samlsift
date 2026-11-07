package c14n

import (
	"bytes"
	"testing"

	"github.com/sriharifortitude/samlsift/internal/xmltree"
)

// FuzzCanonicalFormIsAFixedPoint parses anything, and requires that the canonical form of a
// document parses again to the same canonical form: canonicalization is idempotent, so a
// difference means the parser and the writer disagree about some character or namespace.
func FuzzCanonicalFormIsAFixedPoint(f *testing.F) {
	for _, seed := range []string{
		`<r xmlns:b="urn:b" xmlns:a="urn:a" z="1" a:y="2" b:x="3" a="4"/>`,
		"<r a=\"&lt;&amp;&quot;&#9;&#10;&#13;\" b=\"lit\ttab\">&lt;&amp;&gt;&#13;\"'</r>",
		`<?a b?><!--x--><r xmlns="urn:d"><c xmlns=""><![CDATA[<x>]]></c><!--y--><?c?></r><!--z-->`,
		`<r xml:lang="en"><a:c xmlns:a="urn:a"><e xmlns:a="urn:a" a:k="v"/></a:c></r>`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := xmltree.Parse(data)
		if err != nil {
			return
		}
		for _, opt := range []Options{inc, exc, incCom, excCom} {
			once := Document(doc, nil, opt)
			again, err := xmltree.Parse(once)
			if err != nil {
				t.Fatalf("%+v: the canonical form does not parse: %v\n%q", opt, err, once)
			}
			if twice := Document(again, nil, opt); !bytes.Equal(once, twice) {
				t.Fatalf("%+v: not a fixed point\n once %q\ntwice %q", opt, once, twice)
			}
			doc.Root.Walk(func(n *xmltree.Node) bool {
				if n.Kind == xmltree.Element {
					Subtree(n, nil, opt)
				}
				return true
			})
		}
	})
}
