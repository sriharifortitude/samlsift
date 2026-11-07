// Package xmltree parses XML into a tree that keeps what canonicalization needs and
// encoding/xml does not: prefixes as written, namespace declarations in order, comments as
// nodes of their own, and the difference between a literal tab in an attribute value and
// "&#9;". It parses only what a SAML message can legitimately contain, and refuses a DTD,
// which is where entity expansion and external entity attacks live.
package xmltree

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// XMLNamespace is the namespace the xml prefix is bound to.
const XMLNamespace = "http://www.w3.org/XML/1998/namespace"

// Limits on what is parsed, so that a hostile message cannot exhaust the stack or memory.
const (
	MaxDepth = 256
	MaxNodes = 1 << 20
)

// ErrDTD is returned for a document with a document type declaration.
var ErrDTD = errors.New("the document has a DTD; SAML messages must not, and it is not processed")

type Kind int

const (
	Element Kind = iota
	Text
	Comment
	ProcInst
)

// Attr is an attribute other than a namespace declaration.
type Attr struct {
	Prefix, Local string
	// Space is the namespace URI; empty for an unprefixed attribute.
	Space string
	Value string
}

// NSDecl is a namespace declaration as written on an element. Prefix is empty for xmlns="...".
type NSDecl struct {
	Prefix, URI string
}

type Node struct {
	Kind          Kind
	Prefix, Local string
	// Space is the element's namespace URI.
	Space    string
	Attrs    []Attr
	NSDecls  []NSDecl
	Children []*Node
	Parent   *Node
	// Data is the text of a Text or Comment node, and the data of a processing instruction.
	Data string
	// Target is a processing instruction's target.
	Target string
	// Offset is where the node starts in the input, in bytes.
	Offset int
}

// Document is a parsed document: the root element and the comments and processing
// instructions before and after it.
type Document struct {
	Root     *Node
	Children []*Node
}

// SyntaxError reports where the input stops being acceptable.
type SyntaxError struct {
	Offset int
	Msg    string
}

func (e *SyntaxError) Error() string { return fmt.Sprintf("byte %d: %s", e.Offset, e.Msg) }

type parser struct {
	s     string
	i     int
	depth int
	nodes int
}

func (p *parser) fail(format string, args ...any) error {
	return &SyntaxError{Offset: p.i, Msg: fmt.Sprintf(format, args...)}
}

// Parse parses a whole document. Line endings are normalized first, as XML requires.
func Parse(data []byte) (*Document, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("the document is not valid UTF-8")
	}
	s := string(data)
	s = strings.TrimPrefix(s, "\ufeff")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	p := &parser{s: s}
	return p.document()
}

func (p *parser) rest() string { return p.s[p.i:] }

func (p *parser) skipSpace() {
	for p.i < len(p.s) && isSpace(p.s[p.i]) {
		p.i++
	}
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }

func (p *parser) document() (*Document, error) {
	doc := &Document{}
	if strings.HasPrefix(p.rest(), "<?xml") && len(p.rest()) > 5 && isSpace(p.s[p.i+5]) {
		if err := p.declaration(); err != nil {
			return nil, err
		}
	}
	for {
		p.skipSpace()
		switch {
		case p.i >= len(p.s):
			if doc.Root == nil {
				return nil, p.fail("there is no root element")
			}
			return doc, nil
		case strings.HasPrefix(p.rest(), "<!DOCTYPE"):
			return nil, ErrDTD
		case strings.HasPrefix(p.rest(), "<!--"):
			n, err := p.comment()
			if err != nil {
				return nil, err
			}
			doc.Children = append(doc.Children, n)
		case strings.HasPrefix(p.rest(), "<?"):
			n, err := p.procInst()
			if err != nil {
				return nil, err
			}
			doc.Children = append(doc.Children, n)
		case p.s[p.i] == '<':
			if doc.Root != nil {
				return nil, p.fail("a second root element")
			}
			n, err := p.element(nil)
			if err != nil {
				return nil, err
			}
			doc.Root = n
			doc.Children = append(doc.Children, n)
		default:
			return nil, p.fail("text outside the root element")
		}
	}
}

func (p *parser) declaration() error {
	end := strings.Index(p.rest(), "?>")
	if end < 0 {
		return p.fail("an XML declaration without its end")
	}
	decl := p.s[p.i : p.i+end]
	if at := strings.Index(decl, "encoding"); at >= 0 {
		value := strings.ToLower(decl[at:])
		if !strings.Contains(value, "utf-8") && !strings.Contains(value, "utf8") {
			return p.fail("only UTF-8 documents are read")
		}
	}
	p.i += end + 2
	return nil
}

func (p *parser) count() error {
	p.nodes++
	if p.nodes > MaxNodes {
		return p.fail("more than %d nodes", MaxNodes)
	}
	return nil
}

func (p *parser) comment() (*Node, error) {
	start := p.i
	p.i += 4
	end := strings.Index(p.rest(), "--")
	if end < 0 {
		return nil, p.fail("a comment without its end")
	}
	if !strings.HasPrefix(p.s[p.i+end:], "-->") {
		p.i += end
		return nil, p.fail("-- inside a comment")
	}
	text := p.s[p.i : p.i+end]
	if strings.HasSuffix(text, "-") {
		return nil, p.fail("a comment ending in --->")
	}
	if err := checkChars(text); err != nil {
		return nil, p.fail("%v", err)
	}
	p.i += end + 3
	return &Node{Kind: Comment, Data: text, Offset: start}, p.count()
}

func (p *parser) procInst() (*Node, error) {
	start := p.i
	p.i += 2
	target := p.name()
	if target == "" || strings.EqualFold(target, "xml") || strings.Contains(target, ":") {
		return nil, p.fail("a processing instruction without a usable target")
	}
	end := strings.Index(p.rest(), "?>")
	if end < 0 {
		return nil, p.fail("a processing instruction without its end")
	}
	data := p.s[p.i : p.i+end]
	if data != "" && !isSpace(data[0]) {
		return nil, p.fail("a processing instruction target runs into its data")
	}
	data = strings.TrimLeft(data, " \t\n")
	if err := checkChars(data); err != nil {
		return nil, p.fail("%v", err)
	}
	p.i += end + 2
	return &Node{Kind: ProcInst, Target: target, Data: data, Offset: start}, p.count()
}

func isNameStart(r rune) bool {
	return r == '_' || r == ':' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r >= 0xc0
}

func isNameChar(r rune) bool {
	return isNameStart(r) || r == '-' || r == '.' || (r >= '0' && r <= '9') || r == 0xb7
}

func (p *parser) name() string {
	start := p.i
	for p.i < len(p.s) {
		r, size := utf8.DecodeRuneInString(p.s[p.i:])
		if p.i == start && !isNameStart(r) || p.i > start && !isNameChar(r) {
			break
		}
		p.i += size
	}
	return p.s[start:p.i]
}

// splitName splits prefix:local, refusing names with more than one colon or an empty part.
func splitName(name string) (prefix, local string, ok bool) {
	prefix, local, found := strings.Cut(name, ":")
	if !found {
		return "", name, name != ""
	}
	if prefix == "" || local == "" || strings.Contains(local, ":") {
		return "", "", false
	}
	return prefix, local, true
}

type rawAttr struct {
	prefix, local, value string
}

func (p *parser) element(parent *Node) (*Node, error) {
	start := p.i
	p.depth++
	if p.depth > MaxDepth {
		return nil, p.fail("elements nested more than %d deep", MaxDepth)
	}
	defer func() { p.depth-- }()
	if err := p.count(); err != nil {
		return nil, err
	}
	p.i++ // <
	qname := p.name()
	prefix, local, ok := splitName(qname)
	if !ok {
		return nil, p.fail("a bad element name %q", qname)
	}
	n := &Node{Kind: Element, Prefix: prefix, Local: local, Parent: parent, Offset: start}
	var raw []rawAttr
	seen := map[string]bool{}
	for {
		hadSpace := p.i < len(p.s) && isSpace(p.s[p.i])
		p.skipSpace()
		if p.i >= len(p.s) {
			return nil, p.fail("the document ends inside a tag")
		}
		if strings.HasPrefix(p.rest(), "/>") || p.s[p.i] == '>' {
			break
		}
		if !hadSpace {
			return nil, p.fail("attributes must be separated by white space")
		}
		aname := p.name()
		ap, al, ok := splitName(aname)
		if !ok {
			return nil, p.fail("a bad attribute name %q", aname)
		}
		if seen[aname] {
			return nil, p.fail("attribute %s appears twice", aname)
		}
		seen[aname] = true
		p.skipSpace()
		if p.i >= len(p.s) || p.s[p.i] != '=' {
			return nil, p.fail("attribute %s has no value", aname)
		}
		p.i++
		p.skipSpace()
		value, err := p.attrValue()
		if err != nil {
			return nil, err
		}
		raw = append(raw, rawAttr{ap, al, value})
	}
	for _, a := range raw {
		switch {
		case a.prefix == "" && a.local == "xmlns":
			n.NSDecls = append(n.NSDecls, NSDecl{"", a.value})
		case a.prefix == "xmlns":
			if a.value == "" {
				return nil, p.fail("xmlns:%s cannot be undeclared in XML 1.0", a.local)
			}
			if a.local == "xmlns" || (a.local == "xml") != (a.value == XMLNamespace) {
				return nil, p.fail("xmlns:%s cannot be bound to %q", a.local, a.value)
			}
			n.NSDecls = append(n.NSDecls, NSDecl{a.local, a.value})
		default:
			n.Attrs = append(n.Attrs, Attr{Prefix: a.prefix, Local: a.local, Value: a.value})
		}
	}
	space, err := n.Lookup(n.Prefix)
	if err != nil {
		return nil, p.fail("%v", err)
	}
	n.Space = space
	expanded := map[string]bool{}
	for i := range n.Attrs {
		a := &n.Attrs[i]
		if a.Prefix != "" {
			if a.Space, err = n.Lookup(a.Prefix); err != nil {
				return nil, p.fail("%v", err)
			}
		}
		key := a.Space + "\x00" + a.Local
		if expanded[key] {
			return nil, p.fail("two attributes named {%s}%s", a.Space, a.Local)
		}
		expanded[key] = true
	}
	if strings.HasPrefix(p.rest(), "/>") {
		p.i += 2
		return n, nil
	}
	p.i++ // >
	if err := p.content(n); err != nil {
		return nil, err
	}
	// The end tag.
	p.i += 2
	if end := p.name(); end != qname {
		return nil, p.fail("<%s> is closed by </%s>", qname, end)
	}
	p.skipSpace()
	if p.i >= len(p.s) || p.s[p.i] != '>' {
		return nil, p.fail("an end tag without its >")
	}
	p.i++
	return n, nil
}

// Lookup returns the namespace URI a prefix is bound to at this element, "" for an unbound
// default namespace, and an error for an unbound prefix.
func (n *Node) Lookup(prefix string) (string, error) {
	if prefix == "xml" {
		return XMLNamespace, nil
	}
	for e := n; e != nil; e = e.Parent {
		for i := len(e.NSDecls) - 1; i >= 0; i-- {
			if e.NSDecls[i].Prefix == prefix {
				return e.NSDecls[i].URI, nil
			}
		}
	}
	if prefix == "" {
		return "", nil
	}
	return "", fmt.Errorf("prefix %s is not declared", prefix)
}

func (p *parser) content(n *Node) error {
	var text strings.Builder
	textStart := p.i
	flush := func() error {
		if text.Len() == 0 {
			return nil
		}
		if err := p.count(); err != nil {
			return err
		}
		n.Children = append(n.Children, &Node{Kind: Text, Data: text.String(), Parent: n, Offset: textStart})
		text.Reset()
		return nil
	}
	for {
		if p.i >= len(p.s) {
			return p.fail("<%s> is not closed", qualified(n.Prefix, n.Local))
		}
		if text.Len() == 0 {
			textStart = p.i
		}
		rest := p.rest()
		switch {
		case strings.HasPrefix(rest, "</"):
			return flush()
		case strings.HasPrefix(rest, "<![CDATA["):
			end := strings.Index(rest, "]]>")
			if end < 0 {
				return p.fail("a CDATA section without its end")
			}
			data := rest[9:end]
			if err := checkChars(data); err != nil {
				return p.fail("%v", err)
			}
			// CDATA is text: it joins the text around it, as in the XPath data model.
			text.WriteString(data)
			p.i += end + 3
		case strings.HasPrefix(rest, "<!--"):
			if err := flush(); err != nil {
				return err
			}
			c, err := p.comment()
			if err != nil {
				return err
			}
			c.Parent = n
			n.Children = append(n.Children, c)
		case strings.HasPrefix(rest, "<!"):
			return p.fail("a declaration inside an element")
		case strings.HasPrefix(rest, "<?"):
			if err := flush(); err != nil {
				return err
			}
			pi, err := p.procInst()
			if err != nil {
				return err
			}
			pi.Parent = n
			n.Children = append(n.Children, pi)
		case rest[0] == '<':
			if err := flush(); err != nil {
				return err
			}
			child, err := p.element(n)
			if err != nil {
				return err
			}
			n.Children = append(n.Children, child)
		case rest[0] == '&':
			r, err := p.reference()
			if err != nil {
				return err
			}
			text.WriteString(r)
		default:
			end := strings.IndexAny(rest, "<&")
			if end < 0 {
				end = len(rest)
			}
			chunk := rest[:end]
			if strings.Contains(chunk, "]]>") {
				return p.fail("]]> in text")
			}
			if err := checkChars(chunk); err != nil {
				return p.fail("%v", err)
			}
			text.WriteString(chunk)
			p.i += end
		}
	}
}

func (p *parser) attrValue() (string, error) {
	if p.i >= len(p.s) || (p.s[p.i] != '"' && p.s[p.i] != '\'') {
		return "", p.fail("an attribute value must be quoted")
	}
	quote := p.s[p.i]
	p.i++
	var out strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", p.fail("an attribute value without its closing quote")
		}
		c := p.s[p.i]
		switch {
		case c == quote:
			p.i++
			return out.String(), nil
		case c == '<':
			return "", p.fail("< inside an attribute value")
		case c == '&':
			r, err := p.reference()
			if err != nil {
				return "", err
			}
			out.WriteString(r)
		case c == '\t' || c == '\n':
			// Attribute value normalization: a literal tab or line break is a space. A
			// character reference to one is not, which is why this parser exists.
			out.WriteByte(' ')
			p.i++
		default:
			r, size := utf8.DecodeRuneInString(p.s[p.i:])
			if !isChar(r) {
				return "", p.fail("character U+%04X is not allowed in XML", r)
			}
			out.WriteString(p.s[p.i : p.i+size])
			p.i += size
		}
	}
}

func (p *parser) reference() (string, error) {
	end := strings.IndexByte(p.rest(), ';')
	if end < 0 || end > 12 {
		return "", p.fail("& that does not start a reference")
	}
	ref := p.s[p.i+1 : p.i+end]
	p.i += end + 1
	switch ref {
	case "lt":
		return "<", nil
	case "gt":
		return ">", nil
	case "amp":
		return "&", nil
	case "apos":
		return "'", nil
	case "quot":
		return "\"", nil
	}
	if !strings.HasPrefix(ref, "#") {
		return "", p.fail("entity &%s; is not defined (there is no DTD)", ref)
	}
	var code int64
	var err error
	if strings.HasPrefix(ref, "#x") {
		_, err = fmt.Sscanf(ref[2:], "%x", &code)
		if len(ref) == 2 || strings.Trim(ref[2:], "0123456789abcdefABCDEF") != "" {
			err = errors.New("bad")
		}
	} else {
		_, err = fmt.Sscanf(ref[1:], "%d", &code)
		if len(ref) == 1 || strings.Trim(ref[1:], "0123456789") != "" {
			err = errors.New("bad")
		}
	}
	if err != nil || code > utf8.MaxRune || !isChar(rune(code)) {
		return "", p.fail("&%s; is not a character XML allows", ref)
	}
	return string(rune(code)), nil
}

// isChar is XML 1.0's Char production.
func isChar(r rune) bool {
	return r == 0x9 || r == 0xa || r == 0xd || (r >= 0x20 && r <= 0xd7ff) || (r >= 0xe000 && r <= 0xfffd) ||
		(r >= 0x10000 && r <= 0x10ffff)
}

func checkChars(s string) error {
	for _, r := range s {
		if !isChar(r) {
			return fmt.Errorf("character U+%04X is not allowed in XML", r)
		}
	}
	return nil
}

func qualified(prefix, local string) string {
	if prefix == "" {
		return local
	}
	return prefix + ":" + local
}

// QName is the element's name as written.
func (n *Node) QName() string { return qualified(n.Prefix, n.Local) }

// Attr returns the value of the attribute with this namespace and local name.
func (n *Node) Attr(space, local string) (string, bool) {
	for _, a := range n.Attrs {
		if a.Space == space && a.Local == local {
			return a.Value, true
		}
	}
	return "", false
}

// Is reports whether n is an element with this namespace and local name.
func (n *Node) Is(space, local string) bool {
	return n != nil && n.Kind == Element && n.Space == space && n.Local == local
}

// ChildElements returns the element children with this namespace and local name.
func (n *Node) ChildElements(space, local string) []*Node {
	var out []*Node
	for _, c := range n.Children {
		if c.Is(space, local) {
			out = append(out, c)
		}
	}
	return out
}

// Child returns the first element child with this namespace and local name, or nil.
func (n *Node) Child(space, local string) *Node {
	for _, c := range n.Children {
		if c.Is(space, local) {
			return c
		}
	}
	return nil
}

// Walk calls f for n and every node below it, in document order, stopping early if f
// returns false for a node (its descendants are then skipped too).
func (n *Node) Walk(f func(*Node) bool) {
	if !f(n) {
		return
	}
	for _, c := range n.Children {
		c.Walk(f)
	}
}

// TextContent is the concatenated text of n's text descendants, comments excluded: what a
// careful reader of an element's value gets.
func (n *Node) TextContent() string {
	var b strings.Builder
	n.Walk(func(c *Node) bool {
		if c.Kind == Text {
			b.WriteString(c.Data)
		}
		return true
	})
	return b.String()
}

// Path names an element by the chain of its ancestors, for messages: Response/Assertion[2].
func (n *Node) Path() string {
	var parts []string
	for e := n; e != nil; e = e.Parent {
		part := e.Local
		if e.Parent != nil {
			index, count := 0, 0
			for _, sibling := range e.Parent.Children {
				if sibling.Kind == Element && sibling.Space == e.Space && sibling.Local == e.Local {
					count++
					if sibling == e {
						index = count
					}
				}
			}
			if count > 1 {
				part = fmt.Sprintf("%s[%d]", part, index)
			}
		}
		parts = append([]string{part}, parts...)
	}
	return strings.Join(parts, "/")
}
