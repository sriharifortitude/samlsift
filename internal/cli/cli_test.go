package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const corpus = "../../testdata/corpus"

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func file(name string) string { return filepath.Join(corpus, name) }

var fixed = []string{"--now", "2026-01-01T10:01:00Z"}

func TestAGoodResponse(t *testing.T) {
	code, out, _ := run(t, "", append(fixed, "--cert", file("idp.pem"), file("good-assertion-signed.xml"))...)
	if code != 0 || !strings.Contains(out, "verifies with the configured certificate (RSA-SHA256), over Response/Assertion (ID _a1)") ||
		!strings.Contains(out, "NameID       alice@example.org") || !strings.HasSuffix(out, "no findings\n") {
		t.Fatalf("%d\n%s", code, out)
	}
}

func TestWrappingIsCritical(t *testing.T) {
	code, out, _ := run(t, "", append(fixed, "--cert", file("idp.pem"), file("xsw-evil-assertion-first.xml"))...)
	if code != 1 || !strings.Contains(out, "SS001 critical") || !strings.Contains(out, "no trusted signature covers it") {
		t.Fatalf("%d\n%s", code, out)
	}
	if code, _, _ := run(t, "", append(fixed, "--cert", file("idp.pem"), "--fail-on", "none", file("xsw-evil-assertion-first.xml"))...); code != 0 {
		t.Fatal("--fail-on none")
	}
}

func TestInputForms(t *testing.T) {
	xml, err := os.ReadFile(file("good-response-signed.xml"))
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(xml)
	wrapped := ""
	for i := 0; i < len(b64); i += 76 {
		wrapped += b64[i:min(i+76, len(b64))] + "\r\n"
	}
	for name, input := range map[string]string{
		"XML":         string(xml),
		"base64":      b64,
		"wrapped":     wrapped,
		"a form body": "RelayState=%2Fhome&SAMLResponse=" + url.QueryEscape(b64),
	} {
		code, out, errOut := run(t, input, append(fixed, "--cert", file("idp.pem"), "-")...)
		if code != 0 || !strings.Contains(out, "no findings") {
			t.Errorf("%s: %d %s %s", name, code, out, errOut)
		}
	}
	for name, input := range map[string]string{
		"neither":         "not base64 at all!",
		"base64 of text":  base64.StdEncoding.EncodeToString([]byte("hello")),
		"a DTD":           `<!DOCTYPE r [<!ENTITY x "y">]><r/>`,
		"malformed":       "<samlp:Response>",
		"empty form":      "SAMLResponse=",
		"other form data": "a=b&c=d",
	} {
		if code, _, errOut := run(t, input, "-"); code != 2 || errOut == "" {
			t.Errorf("%s: %d", name, code)
		}
	}
}

func TestCertificatesFromMetadata(t *testing.T) {
	pemData, err := os.ReadFile(file("idp.pem"))
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimSpace(string(pemData))
	body = strings.TrimPrefix(body, "-----BEGIN CERTIFICATE-----")
	body = strings.TrimSuffix(body, "-----END CERTIFICATE-----")
	metadata := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.org/metadata">
<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>bm90IGEgY2VydA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + body + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
</md:IDPSSODescriptor></md:EntityDescriptor>`
	path := filepath.Join(t.TempDir(), "metadata.xml")
	if err := os.WriteFile(path, []byte(metadata), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "", append(fixed, "--cert", path, file("good-assertion-signed.xml"))...)
	if code != 0 || !strings.Contains(out, "the configured certificate") {
		t.Fatalf("%d %s", code, out)
	}
	encryptionOnly := strings.Replace(metadata, `use="signing"`, `use="encryption"`, 1)
	if err := os.WriteFile(path, []byte(encryptionOnly), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run(t, "", "--cert", path, file("good-assertion-signed.xml")); code != 2 || !strings.Contains(errOut, "no certificate") {
		t.Fatalf("an encryption key is not a signing key: %d %s", code, errOut)
	}
}

func TestJSON(t *testing.T) {
	code, out, _ := run(t, "", append(fixed, "--json", "--cert", file("idp.pem"), file("good-both-signed.xml"))...)
	var got struct {
		Signatures []struct {
			Path       string `json:"path"`
			Verified   bool   `json:"verified"`
			Key        string `json:"key"`
			References []struct {
				TargetID string `json:"target_id"`
				DigestOK bool   `json:"digest_ok"`
			} `json:"references"`
		} `json:"signatures"`
		Readings []struct {
			AssertionID string `json:"assertion_id"`
			Signed      bool   `json:"signed"`
			NameID      string `json:"name_id"`
		} `json:"readings"`
		Findings []any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil || code != 0 {
		t.Fatalf("%v %s", err, out)
	}
	if len(got.Signatures) != 2 || got.Signatures[0].Path != "Response/Signature" || got.Signatures[1].References[0].TargetID != "_a1" ||
		!got.Signatures[1].Verified || got.Signatures[1].Key != "the configured certificate" || !got.Signatures[0].References[0].DigestOK {
		t.Fatalf("%+v", got.Signatures)
	}
	if len(got.Readings) != 2 || !got.Readings[0].Signed || got.Readings[0].NameID != "alice@example.org" || got.Findings == nil {
		t.Fatalf("%+v", got)
	}
}

func TestAHostileNameIDCannotReachTheTerminal(t *testing.T) {
	// XML refuses ESC (U+001B) even as a reference, but allows the 8-bit CSI (U+009B) and DEL,
	// which some terminals act on.
	xml := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_x"><saml:Subject><saml:NameID>evil&#x9b;2J&#x7f;\x</saml:NameID></saml:Subject></saml:Assertion>`
	_, out, errOut := run(t, xml, "-")
	if strings.ContainsAny(out, "\u009b\u007f") || !strings.Contains(out, `evil\x9b2J\x7f\\x`) {
		t.Fatalf("%q %q", out, errOut)
	}
	if printable("é ☃") != "é ☃" {
		t.Fatal("printable text is left alone")
	}
}

func TestUsageAndErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no message":      {},
		"two messages":    {"a", "b"},
		"bad fail-on":     {"--fail-on", "nope", "x"},
		"bad now":         {"--now", "yesterday", "x"},
		"unknown flag":    {"--nope", "x"},
		"missing cert":    {"--cert", "no-such.pem", file("unsigned.xml")},
		"missing message": {"no-such.xml"},
		"not a cert":      {"--cert", file("unsigned.xml"), file("unsigned.xml")},
	} {
		if code, _, errOut := run(t, "", args...); code != 2 || errOut == "" {
			t.Errorf("%s: %d %q", name, code, errOut)
		}
	}
	if code, out, _ := run(t, "", "--help"); code != 0 || !strings.Contains(out, "usage:") {
		t.Fatal("help")
	}
	if code, out, _ := run(t, "", "--version"); code != 0 || !strings.HasPrefix(out, "samlsift ") {
		t.Fatal("version")
	}
	big := strings.Repeat("A", MaxInput+1)
	if code, _, errOut := run(t, big, "-"); code != 2 || !strings.Contains(errOut, "larger than") {
		t.Fatalf("%d %s", code, errOut)
	}
}
