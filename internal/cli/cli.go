// Package cli is samlsift's command line.
package cli

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sriharifortitude/samlsift/internal/dsig"
	"github.com/sriharifortitude/samlsift/internal/saml"
	"github.com/sriharifortitude/samlsift/internal/xmltree"
)

// Version is set at build time for releases.
var Version = "0.1.0"

// MaxInput is the largest message read.
const MaxInput = 10 << 20

const usage = `samlsift: is the assertion a service provider would read the one a trusted signature covers?

usage: samlsift [flags] MESSAGE      a file holding XML, base64, or a SAMLResponse= form body; - for stdin

flags:
  --cert FILE      the identity provider's signing certificate: PEM, or the provider's metadata XML
                   (repeatable). Without one, signatures are checked with the certificate the message
                   carries, which shows the signature is intact but not who made it
  --audience ID    the service provider's entity ID, checked against AudienceRestriction
  --acs URL        the assertion consumer URL, checked against Destination and Recipient
  --issuer ID      the identity provider's entity ID, checked against Issuer
  --now TIME       the time to check validity windows at, RFC 3339 (default: now)
  --fail-on LEVEL  exit 1 at or above: critical, high, medium (default), low, info, none
  --json           machine-readable output
  --version

exit status: 0 nothing at or above --fail-on, 1 at least one finding is, 2 usage error or unreadable input
`

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("samlsift", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var certs multi
	fs.Var(&certs, "cert", "")
	audience := fs.String("audience", "", "")
	acs := fs.String("acs", "", "")
	issuer := fs.String("issuer", "", "")
	now := fs.String("now", "", "")
	failOn := fs.String("fail-on", "medium", "")
	asJSON := fs.Bool("json", false, "")
	version := fs.Bool("version", false, "")
	help := fs.Bool("help", false, "")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "samlsift: %v\n\n%s", err, usage)
		return 2
	}
	if *help {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if *version {
		fmt.Fprintf(stdout, "samlsift %s\n", Version)
		return 0
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(stderr, "samlsift: name one message\n\n%s", usage)
		return 2
	}
	threshold := -1 // none: no finding fails
	if *failOn != "none" {
		threshold = saml.Rank(*failOn)
		if threshold == len(saml.Severities) {
			fmt.Fprintf(stderr, "samlsift: --fail-on must be one of %s, none\n", strings.Join(saml.Severities, ", "))
			return 2
		}
	}
	cfg := saml.Config{Audience: *audience, ACS: *acs, Issuer: *issuer}
	if *now != "" {
		t, err := time.Parse(time.RFC3339, *now)
		if err != nil {
			fmt.Fprintf(stderr, "samlsift: --now: %v\n", err)
			return 2
		}
		cfg.Now = t
	}
	for _, path := range certs {
		keys, err := loadKeys(path)
		if err != nil {
			fmt.Fprintf(stderr, "samlsift: %s: %v\n", path, err)
			return 2
		}
		cfg.Keys = append(cfg.Keys, keys...)
	}
	name := fs.Arg(0)
	raw, err := readInput(name, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "samlsift: %s: %v\n", name, err)
		return 2
	}
	xml, err := Decode(raw)
	if err != nil {
		fmt.Fprintf(stderr, "samlsift: %s: %v\n", name, err)
		return 2
	}
	doc, err := xmltree.Parse(xml)
	if err != nil {
		fmt.Fprintf(stderr, "samlsift: %s: %v\n", name, err)
		return 2
	}
	a := saml.Analyze(doc, cfg)
	if *asJSON {
		writeJSON(stdout, name, a)
	} else {
		writeText(stdout, name, a)
	}
	for _, f := range a.Findings {
		if saml.Rank(f.Severity) <= threshold {
			return 1
		}
	}
	return 0
}

func readInput(name string, stdin io.Reader) ([]byte, error) {
	var r io.Reader = stdin
	if name != "-" {
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, MaxInput+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxInput {
		return nil, fmt.Errorf("larger than %d bytes", MaxInput)
	}
	return data, nil
}

// Decode turns what was given into XML: XML as it is, base64 decoded, and a form body's
// SAMLResponse (or SAMLRequest) field URL-decoded first.
func Decode(raw []byte) ([]byte, error) {
	s := strings.TrimSpace(strings.TrimPrefix(string(raw), "\ufeff"))
	if strings.HasPrefix(s, "<") {
		return []byte(s), nil
	}
	if strings.Contains(s, "=") && (strings.Contains(s, "SAMLResponse") || strings.Contains(s, "SAMLRequest")) {
		form, err := url.ParseQuery(s)
		if err == nil {
			for _, field := range []string{"SAMLResponse", "SAMLRequest"} {
				if v := form.Get(field); v != "" {
					s = v
					break
				}
			}
		}
	}
	s = strings.Join(strings.Fields(s), "")
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("neither XML nor base64")
	}
	if !strings.HasPrefix(strings.TrimSpace(string(out)), "<") {
		return nil, errors.New("base64, but not of XML (an HTTP-Redirect message is also deflated, and is not read)")
	}
	return out, nil
}

// loadKeys reads certificates from PEM, or from SAML metadata's signing key descriptors.
func loadKeys(path string) ([]dsig.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	if strings.HasPrefix(strings.TrimSpace(string(data)), "<") {
		certs, err = metadataCerts(data)
	} else {
		certs, err = pemCerts(data)
	}
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate in it")
	}
	keys := make([]dsig.Key, 0, len(certs))
	for _, c := range certs {
		keys = append(keys, dsig.Key{Public: c.PublicKey, Configured: true, Cert: c})
	}
	return keys, nil
}

func pemCerts(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return out, nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
}

const metadataNS = "urn:oasis:names:tc:SAML:2.0:metadata"

func metadataCerts(data []byte) ([]*x509.Certificate, error) {
	doc, err := xmltree.Parse(data)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	doc.Root.Walk(func(n *xmltree.Node) bool {
		if !n.Is(metadataNS, "KeyDescriptor") {
			return true
		}
		if use, ok := n.Attr("", "use"); ok && use != "signing" {
			return false
		}
		n.Walk(func(c *xmltree.Node) bool {
			if c.Is(dsig.Namespace, "X509Certificate") {
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(c.TextContent()), ""))
				if err == nil {
					if cert, err := x509.ParseCertificate(der); err == nil {
						out = append(out, cert)
					}
				}
			}
			return true
		})
		return false
	})
	return out, nil
}

func id(n *xmltree.Node) string {
	if n == nil {
		return ""
	}
	v, _ := n.Attr("", "ID")
	return v
}

func where(n *xmltree.Node) string {
	if v := id(n); v != "" {
		return fmt.Sprintf("%s (ID %s)", n.Path(), v)
	}
	return n.Path()
}

func keyName(k *dsig.Key) string {
	switch {
	case k == nil:
		return "no key"
	case k.Configured:
		return "the configured certificate"
	default:
		return "the certificate in the message"
	}
}

func writeText(w io.Writer, name string, a *saml.Analysis) {
	fmt.Fprintln(w, name)
	for i, s := range a.Signatures {
		state := "does not verify"
		if s.Verified {
			state = "verifies with " + keyName(s.Key)
		}
		var covers []string
		for _, r := range s.References {
			if r.Target == nil && r.Problem == "" {
				covers = append(covers, "the whole document")
			} else if r.Target != nil {
				covers = append(covers, where(r.Target))
			}
		}
		method := s.Method
		if method == "" {
			method = "unknown method"
		}
		fmt.Fprintf(w, "  signature %d  %s: %s (%s), over %s\n", i+1, where(s.Node), state, method, orNothing(covers))
	}
	for _, r := range a.Readings {
		signed := "no trusted signature covers it"
		if r.CoveredBy != nil {
			signed = "signed"
		}
		fmt.Fprintf(w, "  read as      %s: %s, %s\n", r.Strategy, where(r.Assertion), signed)
	}
	for _, r := range distinct(a.Readings) {
		if nameID := findNameID(r); nameID != nil {
			fmt.Fprintf(w, "  NameID       %s\n", printable(nameID.TextContent()))
		}
	}
	for _, f := range a.Findings {
		fmt.Fprintf(w, "  %s %-8s %s\n", f.ID, f.Severity, f.Message)
	}
	fmt.Fprintf(w, "\n%s\n", summary(a.Findings))
}

func distinct(rs []saml.Reading) []saml.Reading {
	var out []saml.Reading
	seen := map[*xmltree.Node]bool{}
	for _, r := range rs {
		if !seen[r.Assertion] {
			seen[r.Assertion] = true
			out = append(out, r)
		}
	}
	return out
}

func findNameID(r saml.Reading) *xmltree.Node {
	subject := r.Assertion.Child(saml.AssertionNS, "Subject")
	if subject == nil {
		return nil
	}
	return subject.Child(saml.AssertionNS, "NameID")
}

func orNothing(xs []string) string {
	if len(xs) == 0 {
		return "nothing"
	}
	return strings.Join(xs, ", ")
}

func summary(fs []saml.Finding) string {
	if len(fs) == 0 {
		return "no findings"
	}
	counts := map[string]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	var parts []string
	for _, s := range saml.Severities {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	return fmt.Sprintf("%d finding(s): %s", len(fs), strings.Join(parts, ", "))
}

// printable escapes what a terminal would act on: the values come from whoever sent the message.
func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

type jsonReference struct {
	URI      string `json:"uri"`
	Target   string `json:"target,omitempty"`
	TargetID string `json:"target_id,omitempty"`
	DigestOK bool   `json:"digest_ok"`
	Problem  string `json:"problem,omitempty"`
}

type jsonSignature struct {
	Path       string          `json:"path"`
	Method     string          `json:"method,omitempty"`
	Verified   bool            `json:"verified"`
	Key        string          `json:"key,omitempty"`
	References []jsonReference `json:"references"`
	Problems   []string        `json:"problems,omitempty"`
}

type jsonReading struct {
	Strategy    string `json:"strategy"`
	Assertion   string `json:"assertion"`
	AssertionID string `json:"assertion_id,omitempty"`
	Signed      bool   `json:"signed"`
	NameID      string `json:"name_id,omitempty"`
}

func writeJSON(w io.Writer, name string, a *saml.Analysis) {
	out := struct {
		Message    string          `json:"message"`
		Signatures []jsonSignature `json:"signatures"`
		Readings   []jsonReading   `json:"readings"`
		Findings   []saml.Finding  `json:"findings"`
	}{Message: name, Signatures: []jsonSignature{}, Readings: []jsonReading{}, Findings: a.Findings}
	if out.Findings == nil {
		out.Findings = []saml.Finding{}
	}
	for _, s := range a.Signatures {
		js := jsonSignature{Path: s.Node.Path(), Method: s.Method, Verified: s.Verified, Problems: s.Problems, References: []jsonReference{}}
		if s.Key != nil {
			js.Key = keyName(s.Key)
		}
		for _, r := range s.References {
			jr := jsonReference{URI: r.URI, DigestOK: r.DigestOK, Problem: r.Problem}
			if r.Target != nil {
				jr.Target, jr.TargetID = r.Target.Path(), id(r.Target)
			}
			js.References = append(js.References, jr)
		}
		out.Signatures = append(out.Signatures, js)
	}
	for _, r := range a.Readings {
		jr := jsonReading{Strategy: r.Strategy, Assertion: r.Assertion.Path(), AssertionID: id(r.Assertion), Signed: r.CoveredBy != nil}
		if n := findNameID(r); n != nil {
			jr.NameID = n.TextContent()
		}
		out.Readings = append(out.Readings, jr)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
