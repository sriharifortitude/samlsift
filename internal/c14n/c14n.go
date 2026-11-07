// Package c14n implements Canonical XML 1.0 and Exclusive XML Canonicalization 1.0, the two
// algorithms XML signatures in SAML use, over a whole document or over one element's subtree
// with one subtree (the enveloped signature) left out.
package c14n

import (
	"sort"
	"strings"

	"github.com/sriharifortitude/samlsift/internal/xmltree"
)

const (
	Inclusive             = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	InclusiveWithComments = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
	Exclusive             = "http://www.w3.org/2001/10/xml-exc-c14n#"
	ExclusiveWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
)

// Options says how to canonicalize.
type Options struct {
	Exclusive    bool
	WithComments bool
	// InclusivePrefixes is Exclusive C14N's InclusiveNamespaces PrefixList; "#default" names the
	// default namespace.
	InclusivePrefixes []string
}

// ForAlgorithm returns the options for an algorithm URI, and false for one this does not know.
func ForAlgorithm(uri string) (Options, bool) {
	switch uri {
	case Inclusive:
		return Options{}, true
	case InclusiveWithComments:
		return Options{WithComments: true}, true
	case Exclusive:
		return Options{Exclusive: true}, true
	case ExclusiveWithComments:
		return Options{Exclusive: true, WithComments: true}, true
	}
	return Options{}, false
}

type writer struct {
	b       strings.Builder
	opt     Options
	exclude *xmltree.Node
	listed  map[string]bool
}

// Subtree canonicalizes the element n and what is below it, leaving out exclude and its
// subtree if exclude is not nil.
func Subtree(n *xmltree.Node, exclude *xmltree.Node, opt Options) []byte {
	w := newWriter(opt, exclude)
	w.element(n, map[string]string{"": ""}, true)
	return []byte(w.b.String())
}

// Document canonicalizes a whole document, leaving out exclude and its subtree.
func Document(doc *xmltree.Document, exclude *xmltree.Node, opt Options) []byte {
	w := newWriter(opt, exclude)
	afterRoot := false
	for _, c := range doc.Children {
		switch c.Kind {
		case xmltree.Element:
			w.element(c, map[string]string{"": ""}, true)
			afterRoot = true
		case xmltree.Comment, xmltree.ProcInst:
			if c.Kind == xmltree.Comment && !opt.WithComments {
				continue
			}
			if afterRoot {
				w.b.WriteByte('\n')
			}
			w.other(c)
			if !afterRoot {
				w.b.WriteByte('\n')
			}
		}
	}
	return []byte(w.b.String())
}

func newWriter(opt Options, exclude *xmltree.Node) *writer {
	w := &writer{opt: opt, exclude: exclude, listed: map[string]bool{}}
	for _, p := range opt.InclusivePrefixes {
		if p == "#default" {
			p = ""
		}
		w.listed[p] = true
	}
	return w
}

// inScope collects the namespace bindings in force at n: its own declarations and its
// ancestors', nearest first.
func inScope(n *xmltree.Node) map[string]string {
	out := map[string]string{}
	for e := n; e != nil; e = e.Parent {
		for i := len(e.NSDecls) - 1; i >= 0; i-- {
			d := e.NSDecls[i]
			if _, ok := out[d.Prefix]; !ok {
				out[d.Prefix] = d.URI
			}
		}
	}
	return out
}

type attr struct {
	space, name, local, value string
}

// element writes n. rendered holds the namespace declarations already in force in the output:
// what the nearest output ancestor rendered, prefix by prefix. apex is true for the first
// element written, whose ancestors are not in the output.
func (w *writer) element(n *xmltree.Node, rendered map[string]string, apex bool) {
	scope := inScope(n)
	var decls []xmltree.NSDecl
	consider := func(prefix string) {
		if prefix == "xml" {
			return
		}
		uri, ok := scope[prefix]
		if !ok {
			if prefix != "" {
				return
			}
			uri = ""
		}
		if have, ok := rendered[prefix]; ok && have == uri {
			return
		}
		if !ok && uri == "" {
			return
		}
		decls = append(decls, xmltree.NSDecl{Prefix: prefix, URI: uri})
	}
	if w.opt.Exclusive {
		used := map[string]bool{n.Prefix: true}
		for _, a := range n.Attrs {
			if a.Prefix != "" {
				used[a.Prefix] = true
			}
		}
		for p := range w.listed {
			used[p] = true
		}
		for p := range used {
			if w.listed[p] {
				if _, inScopeHere := scope[p]; !inScopeHere && p != "" {
					continue
				}
			}
			consider(p)
		}
	} else {
		for p := range scope {
			consider(p)
		}
		if _, ok := scope[""]; !ok {
			consider("")
		}
	}
	sort.Slice(decls, func(i, j int) bool { return decls[i].Prefix < decls[j].Prefix })

	attrs := make([]attr, 0, len(n.Attrs))
	for _, a := range n.Attrs {
		attrs = append(attrs, attr{a.Space, qualified(a.Prefix, a.Local), a.Local, a.Value})
	}
	if apex && !w.opt.Exclusive {
		// Canonical XML 1.0 carries xml:lang, xml:space and the like down to a subset's apex.
		have := map[string]bool{}
		for _, a := range n.Attrs {
			if a.Space == xmltree.XMLNamespace {
				have[a.Local] = true
			}
		}
		for e := n.Parent; e != nil; e = e.Parent {
			for _, a := range e.Attrs {
				if a.Space == xmltree.XMLNamespace && !have[a.Local] {
					have[a.Local] = true
					attrs = append(attrs, attr{a.Space, "xml:" + a.Local, a.Local, a.Value})
				}
			}
		}
	}
	sort.Slice(attrs, func(i, j int) bool {
		if attrs[i].space != attrs[j].space {
			return attrs[i].space < attrs[j].space
		}
		return attrs[i].local < attrs[j].local
	})

	name := n.QName()
	w.b.WriteByte('<')
	w.b.WriteString(name)
	next := make(map[string]string, len(rendered)+len(decls))
	for k, v := range rendered {
		next[k] = v
	}
	for _, d := range decls {
		if d.Prefix == "" {
			w.b.WriteString(` xmlns="`)
		} else {
			w.b.WriteString(` xmlns:` + d.Prefix + `="`)
		}
		w.b.WriteString(escapeAttr(d.URI))
		w.b.WriteByte('"')
		next[d.Prefix] = d.URI
	}
	for _, a := range attrs {
		w.b.WriteString(" " + a.name + `="` + escapeAttr(a.value) + `"`)
	}
	w.b.WriteByte('>')
	for _, c := range n.Children {
		if c == w.exclude {
			continue
		}
		switch c.Kind {
		case xmltree.Element:
			w.element(c, next, false)
		case xmltree.Text:
			w.b.WriteString(escapeText(c.Data))
		case xmltree.Comment:
			if w.opt.WithComments {
				w.other(c)
			}
		case xmltree.ProcInst:
			w.other(c)
		}
	}
	w.b.WriteString("</" + name + ">")
}

func (w *writer) other(n *xmltree.Node) {
	if n.Kind == xmltree.Comment {
		w.b.WriteString("<!--" + n.Data + "-->")
		return
	}
	w.b.WriteString("<?" + n.Target)
	if n.Data != "" {
		w.b.WriteString(" " + n.Data)
	}
	w.b.WriteString("?>")
}

func qualified(prefix, local string) string {
	if prefix == "" {
		return local
	}
	return prefix + ":" + local
}

var textEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\r", "&#xD;")

var attrEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", `"`, "&quot;", "\t", "&#x9;", "\n", "&#xA;", "\r", "&#xD;")

func escapeText(s string) string { return textEscaper.Replace(s) }

func escapeAttr(s string) string { return attrEscaper.Replace(s) }
