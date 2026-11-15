# samlsift

[![CI](https://github.com/sriharifortitude/samlsift/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/samlsift/actions/workflows/ci.yml)

Reads a SAML response and answers the question that signature wrapping attacks are built
around: is the assertion a service provider would read the one a trusted signature covers? It
verifies every XML signature itself, works out which assertion the common ways of reading a
response arrive at, and reports where those differ, along with comment-split NameIDs, duplicate
IDs, signatures by keys the message carries itself, weak algorithms and the usual audience, time
and recipient checks. Go, standard library only, MIT.

## What it is for

A SAML login is a signed XML document posted through the user's browser, so the user can change
it. The signature check and the code that reads the assertion afterwards often look at different
elements. Add an unsigned assertion where the reader looks and leave the signed one where the
verifier looks, and both are satisfied. That is signature wrapping, and it keeps coming back:
ruby-saml's CVE-2024-45409 and the parser differential of CVE-2025-25291 are recent examples, and
so is the CVE-2017-11427 family, where a comment inside a NameID changes what some parsers read
without changing the signature.

samlsift is for checking a response from an identity provider you are integrating, for testing a
service provider (generate the attack, see whether it gets in), and for triaging a login an
incident review turned up. The messages below are from `testdata/corpus`, signed by signxml:

<!-- demo:start -->
```
$ samlsift --cert testdata/corpus/idp.pem --now 2026-01-01T10:01:00Z testdata/corpus/good-assertion-signed.xml
testdata/corpus/good-assertion-signed.xml
  signature 1  Response/Assertion/Signature: verifies with the configured certificate (RSA-SHA256), over Response/Assertion (ID _a1)
  read as      the first Assertion child of the Response: Response/Assertion (ID _a1), signed
  read as      the first Assertion in the document: Response/Assertion (ID _a1), signed
  NameID       alice@example.org

no findings

$ samlsift --cert testdata/corpus/idp.pem --now 2026-01-01T10:01:00Z testdata/corpus/xsw-evil-assertion-first.xml
testdata/corpus/xsw-evil-assertion-first.xml
  signature 1  Response/Assertion[2]/Signature: verifies with the configured certificate (RSA-SHA256), over Response/Assertion[2] (ID _a1)
  read as      the first Assertion child of the Response: Response/Assertion[1] (ID _evil), no trusted signature covers it
  read as      the first Assertion in the document: Response/Assertion[1] (ID _evil), no trusted signature covers it
  NameID       admin@example.org
  SS001 critical a service provider that takes the first Assertion child of the Response reads Response/Assertion[1] (ID _evil), which no valid signature covers, although the message carries one that verifies: signature wrapping
  SS001 critical a service provider that takes the first Assertion in the document reads Response/Assertion[1] (ID _evil), which no valid signature covers, although the message carries one that verifies: signature wrapping
  SS010 medium   the message holds 2 assertions; which one a service provider reads depends on how it looks

3 finding(s): 2 critical, 1 medium

$ samlsift --cert testdata/corpus/idp.pem --now 2026-01-01T10:01:00Z testdata/corpus/comment-in-nameid.xml
testdata/corpus/comment-in-nameid.xml
  signature 1  Response/Assertion/Signature: verifies with the configured certificate (RSA-SHA256), over Response/Assertion (ID _a1)
  read as      the first Assertion child of the Response: Response/Assertion (ID _a1), signed
  read as      the first Assertion in the document: Response/Assertion (ID _a1), signed
  NameID       admin@example.org.evil.example
  SS005 high     NameID in Response/Assertion (ID _a1) holds a comment: it reads "admin@example.org.evil.example" in full, but "admin@example.org" to code that takes its first text node

1 finding(s): 1 high
```
<!-- demo:end -->

The first is an ordinary signed response. In the second, an attacker took a signed response and
put an unsigned assertion for `admin@example.org` in front of the signed one: the signature still
verifies, and both common readers take the attacker's assertion. In the third, the identity
provider signed `admin@example.org.evil.example`, an account the attacker registered, and the
attacker then put a comment inside it. The signature still verifies, because canonicalization
drops comments, and code that takes the NameID's first text node logs in `admin@example.org`.

## Usage

```bash
go install github.com/sriharifortitude/samlsift/cmd/samlsift@v0.1.0

samlsift --cert idp.pem response.xml
samlsift --cert idp-metadata.xml --audience https://sp.example/metadata --acs https://sp.example/acs response.b64
pbpaste | samlsift --cert idp.pem -          # a SAMLResponse= form body, base64 or XML
samlsift --json --cert idp.pem response.xml  # every signature, what it covers, and how each reader reads it
```

The message can be raw XML, base64, or a whole `SAMLResponse=...` form body copied from a
browser's network panel. `--cert` takes a PEM certificate or the identity provider's metadata, and
can be given more than once. Without it, signatures are checked with the certificate inside the
message, which still finds wrapping and tampering but cannot say who signed.

Exit codes: 0 nothing at or above `--fail-on` (default medium), 1 at least one finding is, 2 a
usage error or a message that could not be read.

## Checks

| ID | Severity | What it finds |
|---|---|---|
| SS001 | critical | signature wrapping: a signature verifies, but not over the assertion a service provider reads |
| SS002 | high | nothing is signed, or no signature verifies |
| SS003 | high / info | the message verifies only with a certificate it carries itself (high with `--cert`, info without) |
| SS004 | high | an ID used by more than one element |
| SS005 | high | a comment inside a NameID, AttributeValue, Audience or Issuer |
| SS006 | medium | SHA-1 in a signature or digest |
| SS007 | medium | outside the assertion's or subject confirmation's validity window |
| SS008 | medium | not for the `--audience` given, or no audience restriction at all |
| SS009 | medium | Destination or Recipient not the `--acs` given |
| SS010 | medium | more than one assertion |
| SS011 | info | an encrypted assertion, which is not decrypted |
| SS012 | medium | a signature that cannot be checked: an unsupported transform or algorithm, a missing ID |
| SS013 | info | a status other than Success |
| SS015 | medium | an Issuer other than the `--issuer` given |
| SS016 | high | a signed element inside its own signature (XSW7): invalid to a conforming verifier, accepted by a lax one |
| SS020 | high | not a SAML Response or Assertion |

A document with a DTD is refused before anything else happens: SAML messages have no use for one,
and it is where entity expansion and external entity attacks live.
[ADR 2](docs/adr/0002-what-a-service-provider-reads.md) explains how the readers are chosen and
what "covers" means; [ADR 1](docs/adr/0001-parse-and-canonicalize-here.md) why the XML parser and
the canonicalization are written here.

## Tested

```bash
go test ./...                                       # unit tests, and the corpus against expected.json
python3 scripts/check_corpus.py                     # each signature against signxml and xmlsec1
python3 scripts/compare_c14n.py                     # canonicalization against libxml2
python3 scripts/make_corpus.py                      # new keys, new signatures, same expectations
```

**The corpus.** `scripts/make_corpus.py` signs responses with signxml, with fresh keys each time:
assertion signed, response signed, both, ECDSA, inclusive canonicalization, an InclusiveNamespaces
prefix list, unusual prefixes. From those it makes the attacks: an unsigned assertion before the
signed one, the signed one moved inside an unsigned one or its Advice, the signature moved and the
signed assertion hidden in its `ds:Object`, an unsigned Response wrapping the signed one, a
duplicate ID, the comment-in-NameID trick, a changed NameID, a signature by the attacker's own key,
an unsigned message and one with a DTD. `expected.json` says what each must and must not produce.
The private keys are never written down.

**Against signxml and xmlsec1.** `scripts/check_corpus.py` asks two other verifiers about every
signature samlsift reports: signxml (Python, built on lxml) which element each one signs, and
xmlsec1 (C, libxml2) whether it verifies with the identity provider's certificate. Locally, with signxml 5.2.0,
the two agree on every message: 18 compared, the 19th refused for its DTD by both. xmlsec1
runs in CI; this paragraph will say what it found.

**Canonicalization against libxml2.** `scripts/compare_c14n.py` generates documents built to be
awkward: prefixes declared, redeclared and left unused, a default namespace set and undone,
attribute values with literal and referenced tabs and line breaks, CDATA, comments, processing
instructions, `xml:lang`. It canonicalizes each document and some of its elements both ways, with
and without comments, and with InclusiveNamespaces prefix lists, and compares with libxml2 through
lxml. Over 800 documents, 12,396 comparisons, the two agree byte for byte except in four, and
those were looked at one by one.

The four, and everything skipped, come from lxml rather than libxml2's algorithm. To
canonicalize an element below the root, lxml serializes it as a document of its own, and that is
not quite what the specification calls a document subset. It keeps a redeclaration of a namespace
already in force, it adds `xmlns=""` under elements whose default namespace is already empty, and
it drops `xml:*` attributes inherited from above, which Canonical XML 1.0 carries down to a
subset's apex. For the root element, where lxml's document serializer can be used instead, its
document output and its element output differ in exactly those ways, and its document output
agrees with samlsift's. So the comparison uses the document serializer for the root, skips
elements below it in documents with a redundant redeclaration (1,854) or under an inherited
`xml:*` attribute (378), and accepts the extra `xmlns=""` only when removing it gives samlsift's
output exactly. One more difference is libxml2's own: it ignores `#default` in an
InclusiveNamespaces list, which the specification defines, so that case is left to the tests.
None of these touch SAML's usual case, exclusive canonicalization of an assertion.

**Fuzzing.** CI fuzzes parsing and canonicalization for 60 seconds. The target requires more than
not crashing: the canonical form of a document must parse again to the same canonical form.
Locally that held over 2.7 million inputs.

**Mutation testing.** I broke the code in 56 places on purpose. On the first run, 9 mutants
survived, 4 did not compile and 2 did not match the source; I rewrote those six. Eight survivors
were tests that could not fail, and the most important was algorithm confusion: an ECDSA signature
labelled RSA-SHA256, or the other way round, verifies if the method's key type is not checked,
because the hash is the same, and no test tried it. Others: a signature by an untrusted key was
never checked to leave the assertion unsigned, `NotOnOrAfter` was never tried at its exact
instant, and no test had a comments transform. The ninth marked a rule that was wrong rather than
untested: a signature had to sit inside what it signed to count, which adds nothing (the reference
must already contain the assertion being read) and would have called a legitimate signature
elsewhere in the document wrapping. That rule is gone. The second run left one mutant whose only
effect was a less precise message, and a test now pins the message. All 55 mutants of the current
code are caught.

Writing the tests also found a bug in the CLI: `--fail-on none` still failed on any finding.

## Not tested, and not done

- No real identity provider's messages are in the corpus: they are built from a hand-written
  response and signed by signxml. Real providers differ in prefixes, whitespace and which elements
  they sign, and none of that variety has been tried.
- SHA-1 signatures are made by the tests themselves, since signxml refuses to make them, so that
  path has no outside check.
- Only enveloped signatures over an ID or the whole document are checked, with the transforms SAML
  uses. Canonical XML 1.1, XPath and XSLT transforms, and encrypted assertions are not.
- A service provider that finds its assertion some other way than the two modelled here is not
  modelled; `--json` lists what every signature covers, so it can be checked by hand.
- HTTP-Redirect messages (deflated, signed in the query string) are not read.
