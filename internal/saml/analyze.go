// Package saml decides whether a SAML response is safe to act on: whether the assertion a
// service provider would read is the one a trusted signature covers, and whether what it says
// can be read only one way.
package saml

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sriharifortitude/samlsift/internal/dsig"
	"github.com/sriharifortitude/samlsift/internal/xmltree"
)

const (
	AssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"
	ProtocolNS  = "urn:oasis:names:tc:SAML:2.0:protocol"
	statusOK    = "urn:oasis:names:tc:SAML:2.0:status:Success"
)

// Severities, most serious first.
var Severities = []string{"critical", "high", "medium", "low", "info"}

// Rank orders severities: critical is 0.
func Rank(s string) int {
	for i, v := range Severities {
		if v == s {
			return i
		}
	}
	return len(Severities)
}

type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// Config is what the user knows about the exchange. Every field is optional; a check whose
// input is missing is not made.
type Config struct {
	Keys     []dsig.Key
	Audience string
	// ACS is the service provider's assertion consumer URL, for Recipient and Destination.
	ACS    string
	Issuer string
	Now    time.Time
}

// Reading is the assertion one way of finding "the" assertion arrives at, and whether a
// trusted signature covers it.
type Reading struct {
	Strategy  string
	Assertion *xmltree.Node
	CoveredBy *dsig.Result
}

type Analysis struct {
	Doc        *xmltree.Document
	Assertions []*xmltree.Node
	Encrypted  int
	Signatures []*dsig.Result
	Readings   []Reading
	Findings   []Finding
}

func (a *Analysis) add(id, sev, format string, args ...any) {
	a.Findings = append(a.Findings, Finding{ID: id, Severity: sev, Message: fmt.Sprintf(format, args...)})
}

// Analyze looks at a parsed SAML message.
func Analyze(doc *xmltree.Document, cfg Config) *Analysis {
	a := &Analysis{Doc: doc}
	root := doc.Root
	if !root.Is(ProtocolNS, "Response") && !root.Is(AssertionNS, "Assertion") {
		a.add("SS020", "high", "the document is a %s, not a SAML Response or Assertion", root.QName())
		return a
	}
	root.Walk(func(n *xmltree.Node) bool {
		switch {
		case n.Is(AssertionNS, "Assertion"):
			a.Assertions = append(a.Assertions, n)
		case n.Is(AssertionNS, "EncryptedAssertion"):
			a.Encrypted++
		}
		return true
	})

	ids := dsig.Index(doc)
	a.duplicateIDs(ids)
	for _, sig := range dsig.Find(doc) {
		a.Signatures = append(a.Signatures, dsig.Verify(doc, sig, cfg.Keys, ids))
	}
	a.readings(root)
	a.judgeSignatures(cfg)
	if root.Is(ProtocolNS, "Response") {
		a.status(root)
		a.destination(root, cfg)
	}
	for _, r := range a.distinctReadings() {
		a.assertion(r, cfg)
	}
	if len(a.Assertions) > 1 {
		a.add("SS010", "medium", "the message holds %d assertions; which one a service provider reads depends on how it looks", len(a.Assertions))
	}
	if a.Encrypted > 0 {
		a.add("SS011", "info", "%d encrypted assertion(s) are not decrypted, so what is inside them is not checked", a.Encrypted)
	}
	sort.SliceStable(a.Findings, func(i, j int) bool {
		if Rank(a.Findings[i].Severity) != Rank(a.Findings[j].Severity) {
			return Rank(a.Findings[i].Severity) < Rank(a.Findings[j].Severity)
		}
		return a.Findings[i].ID < a.Findings[j].ID
	})
	return a
}

func (a *Analysis) duplicateIDs(ids dsig.IDIndex) {
	var dup []string
	for id, nodes := range ids {
		if len(nodes) > 1 {
			dup = append(dup, fmt.Sprintf("%s (%d elements)", id, len(nodes)))
		}
	}
	sort.Strings(dup)
	if len(dup) > 0 {
		a.add("SS004", "high", "IDs used more than once: %s; a verifier and a reader can pick different elements", strings.Join(dup, ", "))
	}
}

// readings finds "the" assertion as service providers commonly do.
func (a *Analysis) readings(root *xmltree.Node) {
	if root.Is(AssertionNS, "Assertion") {
		a.Readings = append(a.Readings, Reading{Strategy: "the document itself", Assertion: root})
	} else {
		if first := root.Child(AssertionNS, "Assertion"); first != nil {
			a.Readings = append(a.Readings, Reading{Strategy: "the first Assertion child of the Response", Assertion: first})
		}
		if len(a.Assertions) > 0 {
			a.Readings = append(a.Readings, Reading{Strategy: "the first Assertion in the document", Assertion: a.Assertions[0]})
		}
	}
	for i := range a.Readings {
		a.Readings[i].CoveredBy = a.cover(a.Readings[i].Assertion, true)
	}
}

// cover returns a verified signature that covers n: one whose reference is the whole document
// or an ancestor-or-self of n. With trusted set, only a signature by a configured key counts.
func (a *Analysis) cover(n *xmltree.Node, trusted bool) *dsig.Result {
	for _, s := range a.Signatures {
		if !s.Verified || (trusted && !s.Key.Configured) {
			continue
		}
		for _, ref := range s.References {
			if ref.Target == nil || isAncestorOrSelf(ref.Target, n) {
				return s
			}
		}
	}
	return nil
}

func isAncestorOrSelf(ancestor, n *xmltree.Node) bool {
	for e := n; e != nil; e = e.Parent {
		if e == ancestor {
			return true
		}
	}
	return false
}

func describe(n *xmltree.Node) string {
	if id, ok := n.Attr("", "ID"); ok {
		return fmt.Sprintf("%s (ID %s)", n.Path(), id)
	}
	return n.Path()
}

func (a *Analysis) judgeSignatures(cfg Config) {
	if len(a.Signatures) == 0 {
		a.add("SS002", "high", "nothing in the message is signed")
		return
	}
	anyVerified, anyConfigured := false, false
	for _, s := range a.Signatures {
		where := describe(s.Node)
		for _, p := range s.Problems {
			a.add("SS012", "medium", "the signature at %s could not be checked: %s", where, p)
		}
		for _, ref := range s.References {
			if ref.Problem != "" {
				a.add("SS012", "medium", "the signature at %s, reference %q: %s", where, ref.URI, ref.Problem)
			}
			if ref.WeakHash {
				a.add("SS006", "medium", "the signature at %s digests with %s", where, ref.Digest)
			}
		}
		if s.WeakMethod {
			a.add("SS006", "medium", "the signature at %s uses %s", where, s.Method)
		}
		if s.Verified {
			anyVerified = true
			anyConfigured = anyConfigured || s.Key.Configured
		} else if len(s.Problems) == 0 {
			if s.Key == nil {
				a.add("SS002", "high", "the signature at %s does not verify with any key", where)
			}
		}
	}
	if anyVerified && !anyConfigured {
		if len(cfg.Keys) == 0 {
			a.add("SS003", "info", "no certificate was given, so signatures were checked with the certificate inside the message, which anyone can put there")
		} else {
			a.add("SS003", "high", "the message verifies only with a certificate it carries itself, not the configured one: anyone can produce that")
		}
	}
	if !anyVerified {
		if len(a.Signatures) > 0 && !hasFinding(a.Findings, "SS002") {
			a.add("SS002", "high", "no signature in the message verifies")
		}
		return
	}
	trusted := len(cfg.Keys) > 0
	for _, r := range a.Readings {
		covered := a.cover(r.Assertion, trusted)
		if covered != nil {
			continue
		}
		// Wrapping: something verifies, but not what this reader takes.
		if signedSomewhere := a.cover(r.Assertion, false); signedSomewhere == nil {
			a.add("SS001", "critical", "a service provider that takes %s reads %s, which no valid signature covers, although the message carries one that verifies: signature wrapping",
				r.Strategy, describe(r.Assertion))
		}
	}
}

func hasFinding(fs []Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

func (a *Analysis) distinctReadings() []Reading {
	var out []Reading
	seen := map[*xmltree.Node]bool{}
	for _, r := range a.Readings {
		if !seen[r.Assertion] {
			seen[r.Assertion] = true
			out = append(out, r)
		}
	}
	return out
}

func (a *Analysis) status(resp *xmltree.Node) {
	code := resp.Child(ProtocolNS, "Status")
	if code != nil {
		code = code.Child(ProtocolNS, "StatusCode")
	}
	if code == nil {
		return
	}
	if v, _ := code.Attr("", "Value"); v != statusOK {
		a.add("SS013", "info", "the response's status is %s, not Success", v)
	}
}

func (a *Analysis) destination(resp *xmltree.Node, cfg Config) {
	if cfg.ACS == "" {
		return
	}
	if d, ok := resp.Attr("", "Destination"); ok && d != cfg.ACS {
		a.add("SS009", "medium", "the response's Destination is %s, not %s", d, cfg.ACS)
	}
}

// Split text is how comment injection works: "alice@example.org<!---->.evil.example" is one
// value to a careful parser and "alice@example.org" to one that takes the first text node.
func splitByComment(n *xmltree.Node) (careful, firstNode string, split bool) {
	careful = n.TextContent()
	sawComment := false
	n.Walk(func(c *xmltree.Node) bool {
		if c.Kind == xmltree.Comment && c != n {
			sawComment = true
		}
		return true
	})
	for _, c := range n.Children {
		if c.Kind == xmltree.Text {
			firstNode = c.Data
			break
		}
	}
	return careful, firstNode, sawComment && firstNode != careful
}

func (a *Analysis) assertion(r Reading, cfg Config) {
	as := r.Assertion
	where := describe(as)
	issuer := as.Child(AssertionNS, "Issuer")
	if cfg.Issuer != "" && (issuer == nil || strings.TrimSpace(issuer.TextContent()) != cfg.Issuer) {
		got := "none"
		if issuer != nil {
			got = strings.TrimSpace(issuer.TextContent())
		}
		a.add("SS015", "medium", "%s is issued by %s, not %s", where, got, cfg.Issuer)
	}
	var values []*xmltree.Node
	if issuer != nil {
		values = append(values, issuer)
	}
	as.Walk(func(n *xmltree.Node) bool {
		if n.Is(AssertionNS, "NameID") || n.Is(AssertionNS, "AttributeValue") || n.Is(AssertionNS, "Audience") {
			values = append(values, n)
		}
		return true
	})
	for _, v := range values {
		if careful, first, split := splitByComment(v); split {
			a.add("SS005", "high", "%s in %s holds a comment: it reads %q in full, but %q to code that takes its first text node",
				v.Local, where, careful, first)
		}
	}

	if cfg.Now.IsZero() {
		cfg.Now = time.Now()
	}
	if cond := as.Child(AssertionNS, "Conditions"); cond != nil {
		a.window(where+" Conditions", cond, cfg.Now)
		if cfg.Audience != "" {
			var audiences []string
			for _, ar := range cond.ChildElements(AssertionNS, "AudienceRestriction") {
				for _, au := range ar.ChildElements(AssertionNS, "Audience") {
					audiences = append(audiences, strings.TrimSpace(au.TextContent()))
				}
			}
			if !contains(audiences, cfg.Audience) {
				a.add("SS008", "medium", "%s is not for audience %s (it names: %s)", where, cfg.Audience, listOrNone(audiences))
			}
		}
	} else if cfg.Audience != "" {
		a.add("SS008", "medium", "%s has no Conditions, so no audience restriction", where)
	}
	if subject := as.Child(AssertionNS, "Subject"); subject != nil {
		for _, sc := range subject.ChildElements(AssertionNS, "SubjectConfirmation") {
			data := sc.Child(AssertionNS, "SubjectConfirmationData")
			if data == nil {
				continue
			}
			a.window(where+" SubjectConfirmationData", data, cfg.Now)
			if cfg.ACS != "" {
				if rec, ok := data.Attr("", "Recipient"); ok && rec != cfg.ACS {
					a.add("SS009", "medium", "%s is for recipient %s, not %s", where, rec, cfg.ACS)
				}
			}
		}
	}
}

func (a *Analysis) window(where string, n *xmltree.Node, now time.Time) {
	for _, attr := range []string{"NotBefore", "NotOnOrAfter"} {
		v, ok := n.Attr("", attr)
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			a.add("SS007", "medium", "%s %s=%q is not a time", where, attr, v)
			continue
		}
		if attr == "NotBefore" && now.Before(t) {
			a.add("SS007", "medium", "%s is not valid until %s", where, v)
		}
		if attr == "NotOnOrAfter" && !now.Before(t) {
			a.add("SS007", "medium", "%s expired at %s", where, v)
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func listOrNone(xs []string) string {
	if len(xs) == 0 {
		return "none"
	}
	return strings.Join(xs, ", ")
}
