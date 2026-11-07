# 1. Parse and canonicalize XML here, not with encoding/xml or a C library

Status: accepted

## Context

To say whether a SAML signature covers what a service provider reads, the tool has to verify
the signature itself, and verifying an XML signature means canonicalizing XML exactly: one byte
different and the digest does not match.

Go's `encoding/xml` is not enough for that. It decodes `&#9;` and a literal tab to the same
character, but XML normalizes a literal tab in an attribute to a space and keeps a referenced
one, so the two canonicalize differently. It reports prefixes only before resolving them, and it
does not keep namespace declarations as written. Go's XML signature libraries bring an XML
tree and canonicalization of their own for these reasons, and SAML libraries in every language have
a history of signature bypasses that come from the parser and the verifier seeing a document
differently: ruby-saml's CVE-2024-45409 and CVE-2025-25291 among the recent ones.

The other choice is to call libxml2 and xmlsec from Go. That brings their correctness, and also
cgo, a C toolchain for every build, and their parser's long feature list (DTDs, entities, XInclude
in some configurations) to switch off one by one.

## Decision

Write a small XML parser that accepts what a SAML message can contain and refuses the rest, a DTD
first of all, which removes entity expansion and external entities without configuration. Write
Canonical XML 1.0 and Exclusive XML Canonicalization 1.0 over its tree. Use only the standard
library.

Treat both as hypotheses to test against libxml2: `scripts/compare_c14n.py` generates documents
built to be awkward and compares canonical forms byte for byte through lxml, and
`scripts/check_corpus.py` asks signxml and xmlsec1 whether each signature verifies. The fuzz
target checks that canonicalization is a fixed point: the canonical form of a canonical form is
itself, so the parser and the writer cannot disagree about a character.

## Consequences

- Where this and libxml2 differ, someone has to decide which is right. Three cases came up, and
  each is written down in the README with the reason. lxml serializes an element as a document of
  its own, which keeps redundant namespace declarations and drops inherited `xml:*` attributes,
  and its libxml2 ignores `#default` in an InclusiveNamespaces list. In each case this follows the
  specification, and lxml's own whole-document output agrees.
- Canonical XML 1.1 and the rarer transforms (XPath filter, XSLT, base64) are not implemented. A
  signature that uses one is reported as not checkable rather than checked approximately.
- Encrypted assertions are not decrypted, since that needs the service provider's private key.
