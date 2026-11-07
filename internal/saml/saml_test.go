package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sriharifortitude/samlsift/internal/c14n"
	"github.com/sriharifortitude/samlsift/internal/dsig"
	"github.com/sriharifortitude/samlsift/internal/xmltree"
)

const corpus = "../../testdata/corpus"

var at = time.Date(2026, 1, 1, 10, 1, 0, 0, time.UTC)

func keyFrom(t *testing.T, path string) dsig.Key {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return dsig.Key{Public: cert.PublicKey, Configured: true, Cert: cert}
}

func ids(fs []Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range fs {
		out[f.ID] = true
	}
	return out
}

// The corpus is made by scripts/make_corpus.py with signxml; expected.json says what each
// message must and must not produce.
func TestTheCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(corpus, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string]struct {
		Cert          string   `json:"cert"`
		MustReport    []string `json:"must_report"`
		MustNotReport []string `json:"must_not_report"`
		Refused       bool     `json:"refused"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 15 {
		t.Fatalf("only %d cases", len(cases))
	}
	for name, c := range cases {
		data, err := os.ReadFile(filepath.Join(corpus, name))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := xmltree.Parse(data)
		if c.Refused {
			if err == nil {
				t.Errorf("%s: should be refused", name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		a := Analyze(doc, Config{
			Keys:     []dsig.Key{keyFrom(t, filepath.Join(corpus, c.Cert))},
			Audience: "https://sp.example.org/metadata",
			ACS:      "https://sp.example.org/saml/acs",
			Issuer:   "https://idp.example.org/metadata",
			Now:      at,
		})
		got := ids(a.Findings)
		for _, want := range c.MustReport {
			if !got[want] {
				t.Errorf("%s: %s missing; got %v", name, want, a.Findings)
			}
		}
		for _, unwanted := range c.MustNotReport {
			if got[unwanted] {
				t.Errorf("%s: %s reported: %v", name, unwanted, a.Findings)
			}
		}
	}
}

func load(t *testing.T, name string) *xmltree.Document {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(corpus, name))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := xmltree.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestAGoodResponseIsReadTheSameWayByBothReaders(t *testing.T) {
	a := Analyze(load(t, "good-assertion-signed.xml"), Config{Keys: []dsig.Key{keyFrom(t, filepath.Join(corpus, "idp.pem"))}, Now: at})
	if len(a.Findings) != 0 || len(a.Readings) != 2 {
		t.Fatalf("%+v", a.Findings)
	}
	for _, r := range a.Readings {
		if r.CoveredBy == nil || r.Assertion != a.Assertions[0] {
			t.Errorf("%+v", r)
		}
	}
}

func TestWithoutACertificateTheMessagesOwnIsUsedAndSaidToProveNothing(t *testing.T) {
	a := Analyze(load(t, "good-assertion-signed.xml"), Config{Now: at})
	if !ids(a.Findings)["SS003"] || a.Findings[0].Severity != "info" {
		t.Fatalf("%+v", a.Findings)
	}
	if a.Signatures[0].Key == nil || a.Signatures[0].Key.Configured {
		t.Fatal("the embedded key verifies, as an untrusted one")
	}
	// Wrapping is still found, by the embedded key.
	a = Analyze(load(t, "xsw-evil-assertion-first.xml"), Config{Now: at})
	if !ids(a.Findings)["SS001"] {
		t.Fatalf("%+v", a.Findings)
	}
}

func TestTheWrongCertificate(t *testing.T) {
	a := Analyze(load(t, "good-assertion-signed.xml"), Config{Keys: []dsig.Key{keyFrom(t, filepath.Join(corpus, "attacker.pem"))}, Now: at})
	found := ids(a.Findings)
	if !found["SS003"] || found["SS001"] || a.Findings[0].Severity != "high" {
		t.Fatalf("verifies only with the message's own certificate: %+v", a.Findings)
	}
	for _, r := range a.Readings {
		if r.CoveredBy != nil {
			t.Fatalf("an untrusted key's signature does not make the assertion signed: %+v", r)
		}
	}
}

func TestADuplicatedIDIsNotVerifiedAgainst(t *testing.T) {
	a := Analyze(load(t, "xsw-duplicate-id.xml"), Config{Keys: []dsig.Key{keyFrom(t, filepath.Join(corpus, "idp.pem"))}, Now: at})
	ref := a.Signatures[0].References[0]
	if a.Signatures[0].Verified || ref.Target != nil || !strings.Contains(ref.Problem, "share the ID") {
		t.Fatalf("%+v", ref)
	}
}

func TestASignatureNeedNotSitInsideWhatItSigns(t *testing.T) {
	// The assertion's signature moved up to the Response, still naming the assertion: the
	// assertion that is read is the one signed.
	doc := load(t, "good-assertion-signed.xml")
	assertion := doc.Root.Child(AssertionNS, "Assertion")
	sig := assertion.Child(dsig.Namespace, "Signature")
	var kept []*xmltree.Node
	for _, c := range assertion.Children {
		if c != sig {
			kept = append(kept, c)
		}
	}
	assertion.Children = kept
	sig.Parent = doc.Root
	doc.Root.Children = append(doc.Root.Children, sig)
	a := Analyze(doc, Config{Keys: []dsig.Key{keyFrom(t, filepath.Join(corpus, "idp.pem"))}, Now: at})
	if len(a.Findings) != 0 || !a.Signatures[0].Verified {
		t.Fatalf("%+v", a.Findings)
	}
}

// --- messages made here, for what the corpus does not cover --------------------------------

const template = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Destination="https://sp.example.org/acs">
<saml:Issuer>https://idp.example.org</saml:Issuer>
<samlp:Status><samlp:StatusCode Value="STATUS"/></samlp:Status>
<saml:Assertion ID="_a"><saml:Issuer>ISSUER</saml:Issuer>SIGNATURE<saml:Subject><saml:NameID>alice</saml:NameID>
<saml:SubjectConfirmation><saml:SubjectConfirmationData NotOnOrAfter="2026-01-01T10:05:00Z" Recipient="RECIPIENT"/></saml:SubjectConfirmation></saml:Subject>
<saml:Conditions NotBefore="2026-01-01T09:59:00Z" NotOnOrAfter="2026-01-01T10:05:00Z">AUDIENCE</saml:Conditions>
<saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue>user</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
</saml:Assertion></samlp:Response>`

// message fills in the template; replace's pairs come first, since a Replacer uses the first
// pair that matches.
func message(replace ...string) string {
	r := strings.NewReplacer(append(replace,
		"STATUS", "urn:oasis:names:tc:SAML:2.0:status:Success",
		"ISSUER", "https://idp.example.org",
		"RECIPIENT", "https://sp.example.org/acs",
		"AUDIENCE", "<saml:AudienceRestriction><saml:Audience>https://sp.example.org</saml:Audience></saml:AudienceRestriction>",
	)...)
	return r.Replace(template)
}

type signer struct {
	key    crypto.Signer
	method string
	digest string
	hash   crypto.Hash
	// transform is written into the Reference; empty means the usual pair.
	transform string
}

// sign puts an enveloped signature over the assertion where SIGNATURE stands, the way an
// identity provider would, using samlsift's own canonicalization to make it.
func (s signer) sign(t *testing.T, msg string) string {
	t.Helper()
	unsigned := strings.Replace(msg, "SIGNATURE", "", 1)
	doc, err := xmltree.Parse([]byte(unsigned))
	if err != nil {
		t.Fatal(err)
	}
	assertion := doc.Root.Child(AssertionNS, "Assertion")
	data := c14n.Subtree(assertion, nil, c14n.Options{Exclusive: true})
	h := s.hash.New()
	h.Write(data)
	transforms := `<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`
	if s.transform != "" {
		transforms = s.transform
	}
	info := `<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>` +
		`<ds:SignatureMethod Algorithm="` + s.method + `"/><ds:Reference URI="#_a"><ds:Transforms>` + transforms + `</ds:Transforms>` +
		`<ds:DigestMethod Algorithm="` + s.digest + `"/><ds:DigestValue>` + base64.StdEncoding.EncodeToString(h.Sum(nil)) +
		`</ds:DigestValue></ds:Reference></ds:SignedInfo>`
	sigXML := `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` + info + `<ds:SignatureValue>VALUE</ds:SignatureValue></ds:Signature>`
	withSig := strings.Replace(msg, "SIGNATURE", sigXML, 1)
	doc, err = xmltree.Parse([]byte(withSig))
	if err != nil {
		t.Fatal(err)
	}
	si := dsig.Find(doc)[0].Child(dsig.Namespace, "SignedInfo")
	canon := c14n.Subtree(si, nil, c14n.Options{Exclusive: true})
	hh := s.hash.New()
	hh.Write(canon)
	sum := hh.Sum(nil)
	var value []byte
	switch k := s.key.(type) {
	case *rsa.PrivateKey:
		value, err = rsa.SignPKCS1v15(rand.Reader, k, s.hash, sum)
	case *ecdsa.PrivateKey:
		var r, ss *big.Int
		r, ss, err = ecdsa.Sign(rand.Reader, k, sum)
		size := (k.Curve.Params().BitSize + 7) / 8
		value = append(r.FillBytes(make([]byte, size)), ss.FillBytes(make([]byte, size))...)
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Replace(withSig, "VALUE", base64.StdEncoding.EncodeToString(value), 1)
}

var rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048)

func rsaSigner() signer {
	return signer{key: rsaKey, method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", digest: "http://www.w3.org/2001/04/xmlenc#sha256", hash: crypto.SHA256}
}

func analyze(t *testing.T, msg string, cfg Config) *Analysis {
	t.Helper()
	doc, err := xmltree.Parse([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Now.IsZero() {
		cfg.Now = at
	}
	return Analyze(doc, cfg)
}

func trusted(pub crypto.PublicKey) []dsig.Key { return []dsig.Key{{Public: pub, Configured: true}} }

func TestASignatureMadeHereVerifies(t *testing.T) {
	a := analyze(t, rsaSigner().sign(t, message()), Config{Keys: trusted(&rsaKey.PublicKey)})
	if len(a.Findings) != 0 || !a.Signatures[0].Verified {
		t.Fatalf("%+v %+v", a.Findings, a.Signatures[0])
	}
}

func TestSHA1IsWeak(t *testing.T) {
	s := signer{key: rsaKey, method: "http://www.w3.org/2000/09/xmldsig#rsa-sha1", digest: "http://www.w3.org/2000/09/xmldsig#sha1", hash: crypto.SHA1}
	a := analyze(t, s.sign(t, message()), Config{Keys: trusted(&rsaKey.PublicKey)})
	n := 0
	for _, f := range a.Findings {
		if f.ID == "SS006" {
			n++
		}
	}
	if n != 2 || !a.Signatures[0].Verified {
		t.Fatalf("the method and the digest are both SHA-1: %+v", a.Findings)
	}
	_ = sha1.New
}

func TestAlgorithmConfusionIsRefused(t *testing.T) {
	// An ECDSA signature labelled RSA-SHA256, and an RSA one labelled ECDSA-SHA256. The hash is
	// the same, so only the method's key type stands between these and a verified signature.
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecAsRSA := signer{key: ecKey, method: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", digest: "http://www.w3.org/2001/04/xmlenc#sha256", hash: crypto.SHA256}
	if a := analyze(t, ecAsRSA.sign(t, message()), Config{Keys: trusted(&ecKey.PublicKey)}); a.Signatures[0].Verified {
		t.Error("an ECDSA signature under an RSA method")
	}
	rsaAsEC := rsaSigner()
	rsaAsEC.method = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	if a := analyze(t, rsaAsEC.sign(t, message()), Config{Keys: trusted(&rsaKey.PublicKey)}); a.Signatures[0].Verified {
		t.Error("an RSA signature under an ECDSA method")
	}
}

func TestReferencesDropCommentsEvenWithACommentsTransform(t *testing.T) {
	// XML Signature 4.4.3.3: an ID reference selects the node-set without comments, so a comment
	// added after signing does not break it, whatever the transform is called. The signer here
	// digests without comments, as a conforming one does.
	s := rsaSigner()
	s.transform = `<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>`
	commented := strings.Replace(s.sign(t, message()), "<saml:NameID>alice", "<saml:NameID>al<!--x-->ice", 1)
	a := analyze(t, commented, Config{Keys: trusted(&rsaKey.PublicKey)})
	if !a.Signatures[0].Verified || !ids(a.Findings)["SS005"] {
		t.Fatalf("%+v %+v", a.Signatures[0], a.Findings)
	}
}

func TestECDSAAndTheWrongKindOfKey(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := signer{key: ecKey, method: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", digest: "http://www.w3.org/2001/04/xmlenc#sha256", hash: crypto.SHA256}
	msg := s.sign(t, message())
	if a := analyze(t, msg, Config{Keys: trusted(&ecKey.PublicKey)}); len(a.Findings) != 0 {
		t.Fatalf("%+v", a.Findings)
	}
	if a := analyze(t, msg, Config{Keys: trusted(&rsaKey.PublicKey)}); !ids(a.Findings)["SS002"] {
		t.Fatalf("an RSA key does not verify an ECDSA signature: %+v", a.Findings)
	}
}

func TestTransformsThatAreRefused(t *testing.T) {
	s := rsaSigner()
	s.transform = `<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>1</ds:XPath></ds:Transform>`
	a := analyze(t, s.sign(t, message()), Config{Keys: trusted(&rsaKey.PublicKey)})
	if !ids(a.Findings)["SS012"] || a.Signatures[0].Verified {
		t.Fatalf("%+v", a.Findings)
	}
}

func TestWhatTheConfigurationChecks(t *testing.T) {
	signed := func(replace ...string) string { return rsaSigner().sign(t, message(replace...)) }
	cfg := Config{Keys: trusted(&rsaKey.PublicKey), Audience: "https://sp.example.org", ACS: "https://sp.example.org/acs", Issuer: "https://idp.example.org"}
	if a := analyze(t, signed(), cfg); len(a.Findings) != 0 {
		t.Fatalf("all as configured: %+v", a.Findings)
	}
	for _, c := range []struct {
		msg  string
		cfg  Config
		want string
	}{
		{signed("ISSUER", "https://other.example"), cfg, "SS015"},
		{signed("RECIPIENT", "https://evil.example/acs"), cfg, "SS009"},
		{strings.Replace(signed(), `Destination="https://sp.example.org/acs"`, `Destination="https://evil.example"`, 1), cfg, "SS009"},
		{signed("AUDIENCE", "<saml:AudienceRestriction><saml:Audience>https://other.example</saml:Audience></saml:AudienceRestriction>"), cfg, "SS008"},
		{signed("AUDIENCE", ""), cfg, "SS008"},
		{signed("STATUS", "urn:oasis:names:tc:SAML:2.0:status:Requester"), cfg, "SS013"},
		{signed(), Config{Keys: cfg.Keys, Now: at.Add(time.Hour)}, "SS007"},
		{signed(), Config{Keys: cfg.Keys, Now: at.Add(-time.Hour)}, "SS007"},
		{signed(), Config{Keys: cfg.Keys, Now: time.Date(2026, 1, 1, 10, 5, 0, 0, time.UTC)}, "SS007"},
		{signed("2026-01-01T10:05:00Z", "soon"), Config{Keys: cfg.Keys}, "SS007"},
	} {
		if a := analyze(t, c.msg, c.cfg); !ids(a.Findings)[c.want] {
			t.Errorf("want %s, got %+v", c.want, a.Findings)
		}
	}
}

func TestNoConditionsMeansNoAudienceRestriction(t *testing.T) {
	msg := message(`<saml:Conditions NotBefore="2026-01-01T09:59:00Z" NotOnOrAfter="2026-01-01T10:05:00Z">AUDIENCE</saml:Conditions>`, "")
	a := analyze(t, rsaSigner().sign(t, msg), Config{Keys: trusted(&rsaKey.PublicKey), Audience: "https://sp.example.org"})
	if !ids(a.Findings)["SS008"] {
		t.Fatalf("%+v", a.Findings)
	}
}

func TestCommentsInEveryValueThatMatters(t *testing.T) {
	for _, field := range []string{"<saml:Issuer>https://idp.example.org</saml:Issuer>SIGNATURE", "<saml:AttributeValue>user</saml:AttributeValue>"} {
		split := strings.Replace(field, "example.org</", "example<!---->.org</", 1)
		split = strings.Replace(split, ">user<", ">us<!---->er<", 1)
		msg := strings.Replace(message(), field, split, 1)
		a := analyze(t, strings.Replace(msg, "SIGNATURE", "", 1), Config{})
		if !ids(a.Findings)["SS005"] {
			t.Errorf("%s: %+v", field, a.Findings)
		}
	}
	// A comment before the text, not inside it, changes nothing a reader sees.
	msg := strings.Replace(message(), "<saml:NameID>alice", "<saml:NameID><!--note-->alice", 1)
	if a := analyze(t, strings.Replace(msg, "SIGNATURE", "", 1), Config{}); ids(a.Findings)["SS005"] {
		t.Errorf("%+v", a.Findings)
	}
}

func TestOtherDocuments(t *testing.T) {
	if a := analyze(t, `<r/>`, Config{}); !ids(a.Findings)["SS020"] {
		t.Fatalf("%+v", a.Findings)
	}
	// A bare assertion is read as itself.
	bare := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_x"><saml:Issuer>i</saml:Issuer></saml:Assertion>`
	a := analyze(t, bare, Config{})
	if len(a.Readings) != 1 || a.Readings[0].Strategy != "the document itself" || !ids(a.Findings)["SS002"] {
		t.Fatalf("%+v %+v", a.Readings, a.Findings)
	}
	enc := strings.Replace(message(), "SIGNATURE", "", 1)
	enc = strings.Replace(enc, "</samlp:Response>", `<saml:EncryptedAssertion/></samlp:Response>`, 1)
	if a := analyze(t, enc, Config{}); !ids(a.Findings)["SS011"] {
		t.Fatalf("%+v", a.Findings)
	}
}

func TestAnXPointerIsNotTakenForAnID(t *testing.T) {
	good := rsaSigner().sign(t, message())
	a := analyze(t, strings.Replace(good, `URI="#_a"`, `URI="#xpointer(id('_a'))"`, 1), Config{Keys: trusted(&rsaKey.PublicKey)})
	if p := a.Signatures[0].References[0].Problem; !strings.Contains(p, "not a same-document ID") {
		t.Fatalf("%q", p)
	}
}

func TestBrokenSignatures(t *testing.T) {
	good := rsaSigner().sign(t, message())
	cfg := Config{Keys: trusted(&rsaKey.PublicKey)}
	for name, msg := range map[string]string{
		"no SignedInfo":      replaceBetween(good, "<ds:SignedInfo>", "</ds:SignedInfo>", ""),
		"unknown method":     strings.Replace(good, "xmldsig-more#rsa-sha256", "xmldsig-more#rsa-md5", 1),
		"unknown digest":     strings.Replace(good, "xmlenc#sha256", "xmlenc#sha9", 1),
		"unknown c14n":       strings.Replace(good, `CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"`, `CanonicalizationMethod Algorithm="urn:x"`, 1),
		"no such ID":         strings.Replace(good, `URI="#_a"`, `URI="#_nope"`, 1),
		"an external URI":    strings.Replace(good, `URI="#_a"`, `URI="https://evil.example/x"`, 1),
		"an XPointer":        strings.Replace(good, `URI="#_a"`, `URI="#xpointer(/)"`, 1),
		"bad signature b64":  replaceBetween(good, "<ds:SignatureValue>", "</ds:SignatureValue>", "!!!"),
		"bad digest b64":     replaceBetween(good, "<ds:DigestValue>", "</ds:DigestValue>", "!!!"),
		"no reference":       replaceBetween(good, "<ds:Reference", "</ds:Reference>", ""),
		"no c14n method":     replaceBetween(good, "<ds:CanonicalizationMethod", "/>", ""),
		"changed SignedInfo": strings.Replace(good, `<ds:SignedInfo>`, `<ds:SignedInfo Id="x">`, 1),
	} {
		a := analyze(t, msg, cfg)
		if a.Signatures[0].Verified {
			t.Errorf("%s: verified", name)
		}
		if f := ids(a.Findings); !f["SS012"] && !f["SS002"] {
			t.Errorf("%s: %+v", name, a.Findings)
		}
	}
}

// replaceBetween replaces from the first start through the first end after it.
func replaceBetween(s, start, end, with string) string {
	i := strings.Index(s, start)
	j := strings.Index(s[i:], end)
	return s[:i] + with + s[i+j+len(end):]
}

func TestDigestsUseTheirOwnHash(t *testing.T) {
	// SHA-256 over the canonical form, as an independent check of the digest the signer wrote.
	msg := strings.Replace(message(), "SIGNATURE", "", 1)
	doc, _ := xmltree.Parse([]byte(msg))
	sum := sha256.Sum256(c14n.Subtree(doc.Root.Child(AssertionNS, "Assertion"), nil, c14n.Options{Exclusive: true}))
	if !strings.Contains(rsaSigner().sign(t, message()), base64.StdEncoding.EncodeToString(sum[:])) {
		t.Fatal("the reference's digest is SHA-256 of the canonical assertion")
	}
}
