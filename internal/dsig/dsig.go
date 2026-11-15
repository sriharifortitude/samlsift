// Package dsig verifies XML signatures the way SAML uses them: enveloped signatures over an
// element named by its ID, or over the whole document. It accepts only the transforms SAML
// needs. An XPath or XSLT transform is refused rather than run, since running one is itself an
// attack surface.
package dsig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1" // SHA-1 is reported as weak, but signatures using it must still be read
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"hash"
	"math/big"
	"strings"

	"github.com/sriharifortitude/samlsift/internal/c14n"
	"github.com/sriharifortitude/samlsift/internal/xmltree"
)

// Namespace is the XML Signature namespace.
const Namespace = "http://www.w3.org/2000/09/xmldsig#"

const (
	exclusiveNamespace = "http://www.w3.org/2001/10/xml-exc-c14n#"
	transformEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

type algorithm struct {
	name string
	hash crypto.Hash
	ec   bool
	weak bool
}

var digests = map[string]algorithm{
	"http://www.w3.org/2000/09/xmldsig#sha1":        {"SHA-1", crypto.SHA1, false, true},
	"http://www.w3.org/2001/04/xmlenc#sha256":       {"SHA-256", crypto.SHA256, false, false},
	"http://www.w3.org/2001/04/xmldsig-more#sha384": {"SHA-384", crypto.SHA384, false, false},
	"http://www.w3.org/2001/04/xmlenc#sha512":       {"SHA-512", crypto.SHA512, false, false},
}

var signatures = map[string]algorithm{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":          {"RSA-SHA1", crypto.SHA1, false, true},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   {"RSA-SHA256", crypto.SHA256, false, false},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   {"RSA-SHA384", crypto.SHA384, false, false},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   {"RSA-SHA512", crypto.SHA512, false, false},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": {"ECDSA-SHA256", crypto.SHA256, true, false},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": {"ECDSA-SHA384", crypto.SHA384, true, false},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": {"ECDSA-SHA512", crypto.SHA512, true, false},
}

func newHash(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.SHA1:
		return sha1.New()
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	}
	return sha256.New()
}

// Key is a public key the verifier may use, with where it came from.
type Key struct {
	Public crypto.PublicKey
	// Configured is true for a key the user supplied, false for one taken from the message.
	Configured bool
	Cert       *x509.Certificate
}

// Reference is one ds:Reference and what became of it.
type Reference struct {
	URI string
	// Target is the element the reference names; nil for the whole document.
	Target     *xmltree.Node
	Digest     string
	DigestOK   bool
	WeakHash   bool
	Transforms []string
	Problem    string
	// InsideOwnSignature is true when the referenced element sits inside the signature, as in
	// the XSW7 attack. The enveloped transform then leaves nothing to digest.
	InsideOwnSignature bool
}

// Result is what verifying one signature found.
type Result struct {
	Node       *xmltree.Node
	Method     string
	WeakMethod bool
	References []Reference
	// Verified is true when the signature over SignedInfo checks out with some key and every
	// reference's digest matches.
	Verified bool
	// Key is the key that verified SignedInfo, if one did.
	Key *Key
	// Problems are reasons the signature could not be checked at all.
	Problems []string
}

// IDIndex finds elements by the attributes SAML and XML Signature use as IDs: ID, Id and id,
// unprefixed. Every element carrying a value is kept, so that duplicates can be seen.
type IDIndex map[string][]*xmltree.Node

func Index(doc *xmltree.Document) IDIndex {
	idx := IDIndex{}
	doc.Root.Walk(func(n *xmltree.Node) bool {
		if n.Kind != xmltree.Element {
			return true
		}
		for _, name := range []string{"ID", "Id", "id"} {
			if v, ok := n.Attr("", name); ok {
				idx[v] = append(idx[v], n)
			}
		}
		return true
	})
	return idx
}

// Find returns every ds:Signature element in the document, in document order.
func Find(doc *xmltree.Document) []*xmltree.Node {
	var out []*xmltree.Node
	doc.Root.Walk(func(n *xmltree.Node) bool {
		if n.Is(Namespace, "Signature") {
			out = append(out, n)
			return false
		}
		return true
	})
	return out
}

func text(n *xmltree.Node) string {
	if n == nil {
		return ""
	}
	return strings.Join(strings.Fields(n.TextContent()), "")
}

func decode(n *xmltree.Node) ([]byte, error) {
	return base64.StdEncoding.DecodeString(text(n))
}

// Certificates returns the X.509 certificates in a signature's KeyInfo.
func Certificates(sig *xmltree.Node) []*x509.Certificate {
	var out []*x509.Certificate
	info := sig.Child(Namespace, "KeyInfo")
	if info == nil {
		return nil
	}
	for _, data := range info.ChildElements(Namespace, "X509Data") {
		for _, c := range data.ChildElements(Namespace, "X509Certificate") {
			der, err := decode(c)
			if err != nil {
				continue
			}
			if cert, err := x509.ParseCertificate(der); err == nil {
				out = append(out, cert)
			}
		}
	}
	return out
}

func canonicalization(method *xmltree.Node) (c14n.Options, string, error) {
	if method == nil {
		return c14n.Options{}, "", fmt.Errorf("SignedInfo has no CanonicalizationMethod")
	}
	uri, _ := method.Attr("", "Algorithm")
	opt, ok := c14n.ForAlgorithm(uri)
	if !ok {
		return opt, uri, fmt.Errorf("canonicalization %s is not supported", uri)
	}
	if opt.Exclusive {
		if inc := method.Child(exclusiveNamespace, "InclusiveNamespaces"); inc != nil {
			list, _ := inc.Attr("", "PrefixList")
			opt.InclusivePrefixes = strings.Fields(list)
		}
	}
	return opt, uri, nil
}

// Verify checks one ds:Signature element against the given keys and the keys in its own
// KeyInfo, which are tried last and reported as not configured.
func Verify(doc *xmltree.Document, sig *xmltree.Node, keys []Key, ids IDIndex) *Result {
	r := &Result{Node: sig}
	info := sig.Child(Namespace, "SignedInfo")
	if info == nil {
		r.Problems = append(r.Problems, "the signature has no SignedInfo")
		return r
	}
	siOpt, _, err := canonicalization(info.Child(Namespace, "CanonicalizationMethod"))
	if err != nil {
		r.Problems = append(r.Problems, err.Error())
		return r
	}
	methodNode := info.Child(Namespace, "SignatureMethod")
	methodURI := ""
	if methodNode != nil {
		methodURI, _ = methodNode.Attr("", "Algorithm")
	}
	method, ok := signatures[methodURI]
	if !ok {
		r.Problems = append(r.Problems, fmt.Sprintf("signature method %q is not supported", methodURI))
		return r
	}
	r.Method, r.WeakMethod = method.name, method.weak
	value, err := decode(sig.Child(Namespace, "SignatureValue"))
	if err != nil || len(value) == 0 {
		r.Problems = append(r.Problems, "the SignatureValue is not base64")
		return r
	}
	refs := info.ChildElements(Namespace, "Reference")
	if len(refs) == 0 {
		r.Problems = append(r.Problems, "SignedInfo has no Reference")
		return r
	}
	allDigests := true
	for _, ref := range refs {
		res := reference(doc, sig, ref, ids)
		allDigests = allDigests && res.DigestOK
		r.References = append(r.References, res)
	}

	signed := c14n.Subtree(info, nil, siOpt)
	h := newHash(method.hash)
	h.Write(signed)
	sum := h.Sum(nil)
	candidates := append([]Key{}, keys...)
	for _, cert := range Certificates(sig) {
		candidates = append(candidates, Key{Public: cert.PublicKey, Cert: cert})
	}
	for i := range candidates {
		if verifyWith(candidates[i].Public, method, sum, value) {
			k := candidates[i]
			r.Key = &k
			break
		}
	}
	r.Verified = r.Key != nil && allDigests
	return r
}

func verifyWith(key crypto.PublicKey, method algorithm, sum, value []byte) bool {
	switch k := key.(type) {
	case *rsa.PublicKey:
		if method.ec {
			return false
		}
		return rsa.VerifyPKCS1v15(k, method.hash, sum, value) == nil
	case *ecdsa.PublicKey:
		if !method.ec || len(value)%2 != 0 {
			return false
		}
		// XML Signature writes r and s side by side, not as DER.
		half := len(value) / 2
		rr, ss := new(big.Int).SetBytes(value[:half]), new(big.Int).SetBytes(value[half:])
		return ecdsa.Verify(k, sum, rr, ss)
	}
	return false
}

func reference(doc *xmltree.Document, sig, ref *xmltree.Node, ids IDIndex) Reference {
	uri, _ := ref.Attr("", "URI")
	res := Reference{URI: uri}
	switch {
	case uri == "":
		res.Target = nil
	case strings.HasPrefix(uri, "#") && !strings.Contains(uri, "("):
		matches := ids[uri[1:]]
		switch len(matches) {
		case 0:
			res.Problem = fmt.Sprintf("no element has the ID %s", uri[1:])
			return res
		case 1:
			res.Target = matches[0]
		default:
			res.Problem = fmt.Sprintf("%d elements share the ID %s, so which one is signed depends on the verifier", len(matches), uri[1:])
			return res
		}
	default:
		res.Problem = fmt.Sprintf("reference URI %q is not a same-document ID", uri)
		return res
	}

	opt := c14n.Options{}
	enveloped := false
	if transforms := ref.Child(Namespace, "Transforms"); transforms != nil {
		for _, t := range transforms.ChildElements(Namespace, "Transform") {
			alg, _ := t.Attr("", "Algorithm")
			res.Transforms = append(res.Transforms, alg)
			if alg == transformEnveloped {
				enveloped = true
				continue
			}
			o, ok := c14n.ForAlgorithm(alg)
			if !ok {
				res.Problem = fmt.Sprintf("transform %s is not supported", alg)
				return res
			}
			if o.Exclusive {
				if inc := t.Child(exclusiveNamespace, "InclusiveNamespaces"); inc != nil {
					list, _ := inc.Attr("", "PrefixList")
					o.InclusivePrefixes = strings.Fields(list)
				}
			}
			opt = o
		}
	}
	// A same-document reference selects the node-set without comments, whatever the
	// canonicalization's name says (XML Signature section 4.4.3.3).
	opt.WithComments = false
	var exclude *xmltree.Node
	if enveloped {
		exclude = sig
	}
	var data []byte
	inside := res.Target != nil && isWithin(res.Target, sig)
	res.InsideOwnSignature = inside
	switch {
	case inside && enveloped:
		// The enveloped transform removes the signature and everything in it from the node-set
		// (XML Signature section 6.6.4), the referenced element included: nothing is left. A
		// verifier that only drops the signature from the referenced subtree would accept this.
		data = nil
	case res.Target == nil:
		data = c14n.Document(doc, exclude, opt)
	default:
		data = c14n.Subtree(res.Target, exclude, opt)
	}

	methodNode := ref.Child(Namespace, "DigestMethod")
	methodURI := ""
	if methodNode != nil {
		methodURI, _ = methodNode.Attr("", "Algorithm")
	}
	digest, ok := digests[methodURI]
	if !ok {
		res.Problem = fmt.Sprintf("digest method %q is not supported", methodURI)
		return res
	}
	res.Digest, res.WeakHash = digest.name, digest.weak
	want, err := decode(ref.Child(Namespace, "DigestValue"))
	if err != nil {
		res.Problem = "the DigestValue is not base64"
		return res
	}
	h := newHash(digest.hash)
	h.Write(data)
	res.DigestOK = bytes.Equal(h.Sum(nil), want)
	switch {
	case !res.DigestOK && inside && enveloped:
		res.Problem = "the referenced element is inside the signature, so the enveloped transform leaves nothing to digest"
	case !res.DigestOK:
		res.Problem = "the digest does not match: the signed content was changed"
	}
	return res
}

// isWithin reports whether n is the given ancestor or below it.
func isWithin(n, ancestor *xmltree.Node) bool {
	for e := n; e != nil; e = e.Parent {
		if e == ancestor {
			return true
		}
	}
	return false
}
