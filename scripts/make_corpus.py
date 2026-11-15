#!/usr/bin/env python3
"""Writes testdata/corpus: SAML responses signed by signxml, and attacks made from them.

The signing keys live only in this process; what is written is the messages, the certificates
that verify them, and expected.json, which says what samlsift must report for each message.
Running it again makes new keys and new signatures, and the same expectations must still hold.

    python scripts/make_corpus.py
"""

import copy
import datetime
import json
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import SignatureConstructionMethod, XMLSigner

OUT = pathlib.Path(__file__).resolve().parent.parent / "testdata" / "corpus"
SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
DS = "http://www.w3.org/2000/09/xmldsig#"
EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"
INC = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
ACS = "https://sp.example.org/saml/acs"
AUDIENCE = "https://sp.example.org/metadata"
IDP = "https://idp.example.org/metadata"


def make_key(kind: str, name: str):
    key = rsa.generate_private_key(65537, 2048) if kind == "rsa" else ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    start = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return key_pem, cert.public_bytes(serialization.Encoding.PEM)


def response(name_id: str = "alice@example.org", prefixes: tuple[str, str] = ("samlp", "saml"), assertion_id: str = "_a1") -> etree._Element:
    p, a = prefixes
    text = f"""<{p}:Response xmlns:{p}="{SAMLP}" xmlns:{a}="{SAML}" ID="_r1" Version="2.0"
    IssueInstant="2026-01-01T10:00:00Z" Destination="{ACS}" InResponseTo="_req1">
  <{a}:Issuer>{IDP}</{a}:Issuer>
  <{p}:Status><{p}:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></{p}:Status>
  <{a}:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="2026-01-01T10:00:00Z">
    <{a}:Issuer>{IDP}</{a}:Issuer>
    <{a}:Subject>
      <{a}:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</{a}:NameID>
      <{a}:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <{a}:SubjectConfirmationData NotOnOrAfter="2026-01-01T10:05:00Z" Recipient="{ACS}" InResponseTo="_req1"/>
      </{a}:SubjectConfirmation>
    </{a}:Subject>
    <{a}:Conditions NotBefore="2026-01-01T09:59:00Z" NotOnOrAfter="2026-01-01T10:05:00Z">
      <{a}:AudienceRestriction><{a}:Audience>{AUDIENCE}</{a}:Audience></{a}:AudienceRestriction>
    </{a}:Conditions>
    <{a}:AuthnStatement AuthnInstant="2026-01-01T10:00:00Z">
      <{a}:AuthnContext><{a}:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</{a}:AuthnContextClassRef></{a}:AuthnContext>
    </{a}:AuthnStatement>
  </{a}:Assertion>
</{p}:Response>"""
    return etree.fromstring(text.encode())


def placeholder(el: etree._Element) -> None:
    """Where SAML wants the signature: right after the Issuer."""
    sig = etree.Element(f"{{{DS}}}Signature", nsmap={"ds": DS})
    sig.set("Id", "placeholder")
    el.insert(1, sig)


def sign(el: etree._Element, key, cert, alg="rsa-sha256", digest="sha256", c14n=EXC, prefixes=None) -> etree._Element:
    placeholder(el)
    signer = XMLSigner(method=SignatureConstructionMethod.enveloped, signature_algorithm=alg, digest_algorithm=digest, c14n_algorithm=c14n)
    if prefixes:
        signer.inclusive_ns_prefixes = prefixes
    return signer.sign(el, key=key, cert=cert, reference_uri=el.get("ID"), id_attribute="ID", always_add_key_value=False)


def sign_assertion(resp: etree._Element, key, cert, **kw) -> etree._Element:
    a = resp.find(f"{{{SAML}}}Assertion")
    signed = sign(copy.deepcopy(a), key, cert, **kw)
    resp.replace(a, signed)
    return resp


def evil_assertion(signed_assertion: etree._Element, assertion_id: str = "_evil") -> etree._Element:
    evil = copy.deepcopy(signed_assertion)
    evil.set("ID", assertion_id)
    for sig in evil.findall(f"{{{DS}}}Signature"):
        evil.remove(sig)
    evil.find(f"{{{SAML}}}Subject/{{{SAML}}}NameID").text = "admin@example.org"
    return evil


def write(name: str, el, cases: dict, expect: list[str], note: str, cert: str = "idp.pem", absent: list[str] | None = None) -> None:
    data = el if isinstance(el, bytes) else etree.tostring(el)
    (OUT / name).write_bytes(data)
    cases[name] = {"cert": cert, "must_report": expect, "must_not_report": absent or [], "note": note}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    idp_key, idp_cert = make_key("rsa", "idp.example.org")
    ec_key, ec_cert = make_key("ec", "idp-ec.example.org")
    evil_key, evil_cert = make_key("rsa", "attacker.example")
    for name, cert in (("idp.pem", idp_cert), ("idp-ec.pem", ec_cert), ("attacker.pem", evil_cert)):
        (OUT / name).write_bytes(cert)
    cases: dict = {}
    safe = ["SS001", "SS002", "SS003", "SS004", "SS005", "SS012"]

    # --- what an identity provider sends -------------------------------------------------------
    signed_a = sign_assertion(response(), idp_key, idp_cert)
    write("good-assertion-signed.xml", signed_a, cases, [], "the assertion is signed", absent=safe)
    resp = sign(response(), idp_key, idp_cert)
    write("good-response-signed.xml", resp, cases, [], "the response is signed", absent=safe)
    both = sign(sign_assertion(response(), idp_key, idp_cert), idp_key, idp_cert)
    write("good-both-signed.xml", both, cases, [], "the assertion and the response are signed", absent=safe)
    write("good-ecdsa.xml", sign_assertion(response(), ec_key, ec_cert, alg="ecdsa-sha256"), cases, [],
          "ECDSA P-256", cert="idp-ec.pem", absent=safe)
    write("good-inclusive-c14n.xml", sign(response(), idp_key, idp_cert, c14n=INC), cases, [],
          "inclusive canonicalization over the whole response", absent=safe)
    write("good-prefix-list.xml", sign_assertion(response(), idp_key, idp_cert, prefixes=["saml", "xs"]), cases, [],
          "exclusive canonicalization with an InclusiveNamespaces PrefixList", absent=safe)
    write("good-other-prefixes.xml", sign_assertion(response(prefixes=("p2", "a2")), idp_key, idp_cert), cases, [],
          "unusual prefixes", absent=safe)
    try:
        sha1 = sign_assertion(response(), idp_key, idp_cert, alg="rsa-sha1", digest="sha1")
        write("weak-sha1.xml", sha1, cases, ["SS006"], "RSA-SHA1 and a SHA-1 digest", absent=safe)
    except Exception as err:  # noqa: BLE001 - signxml may refuse to make SHA-1 signatures at all
        print("skipped SHA-1:", err)

    # --- attacks on an assertion signature -----------------------------------------------------
    signed = signed_a.find(f"{{{SAML}}}Assertion")
    # XSW3: an unsigned assertion before the signed one.
    r = copy.deepcopy(signed_a)
    r.insert(2, evil_assertion(signed))
    write("xsw-evil-assertion-first.xml", r, cases, ["SS001", "SS010"], "an unsigned assertion is placed before the signed one")
    # XSW4: the signed assertion is moved inside the unsigned one.
    r = copy.deepcopy(signed_a)
    original = r.find(f"{{{SAML}}}Assertion")
    evil = evil_assertion(original)
    r.replace(original, evil)
    evil.append(original)
    write("xsw-evil-wraps-signed.xml", r, cases, ["SS001"], "the signed assertion is moved inside an unsigned one")
    # The signed assertion hidden in the evil assertion's Advice.
    r = copy.deepcopy(signed_a)
    original = r.find(f"{{{SAML}}}Assertion")
    evil = evil_assertion(original)
    advice = etree.SubElement(evil, f"{{{SAML}}}Advice")
    r.replace(original, evil)
    advice.append(original)
    write("xsw-signed-in-advice.xml", r, cases, ["SS001"], "the signed assertion is hidden in an unsigned one's Advice")
    # XSW5: the signature moves to the evil assertion and the element it signs is gone, so it
    # no longer verifies.
    r = copy.deepcopy(signed_a)
    original = r.find(f"{{{SAML}}}Assertion")
    sig = original.find(f"{{{DS}}}Signature")
    evil = evil_assertion(original)
    original.remove(sig)
    evil.insert(1, sig)
    r.replace(original, evil)
    write("xsw-signature-moved.xml", r, cases, ["SS002"],
          "the signature is moved to an unsigned assertion, and what it signed is gone")
    # XSW7: as above, with the signed assertion kept inside the signature's ds:Object.
    r = copy.deepcopy(signed_a)
    resp_assertion = r.find(f"{{{SAML}}}Assertion")
    sig = resp_assertion.find(f"{{{DS}}}Signature")
    evil = evil_assertion(resp_assertion)
    resp_assertion.remove(sig)
    r.replace(resp_assertion, evil)
    obj = etree.SubElement(sig, f"{{{DS}}}Object")
    obj.append(resp_assertion)
    evil.insert(1, sig)
    write("xsw-signed-in-object.xml", r, cases, ["SS002", "SS016"],
          "XSW7: the signature sits in the unsigned assertion, and the element it signs is in its ds:Object, "
          "so a conforming verifier finds nothing left to digest", absent=["SS001"])
    # Two elements with the signed ID.
    r = copy.deepcopy(signed_a)
    r.insert(2, evil_assertion(signed, assertion_id="_a1"))
    write("xsw-duplicate-id.xml", r, cases, ["SS004"], "an unsigned assertion reuses the signed one's ID")

    # --- attacks on a response signature -------------------------------------------------------
    # XSW1: a new Response around the original, signed one.
    signed_resp = resp
    outer = copy.deepcopy(signed_resp)
    for child in list(outer):
        if child.tag in (f"{{{DS}}}Signature", f"{{{SAML}}}Assertion"):
            outer.remove(child)
    outer.set("ID", "_evilresponse")
    outer.append(evil_assertion(signed_resp.find(f"{{{SAML}}}Assertion")))
    ext = etree.SubElement(outer, f"{{{SAMLP}}}Extensions")
    ext.append(copy.deepcopy(signed_resp))
    write("xsw-response-wrapped.xml", outer, cases, ["SS001"], "XSW1: an unsigned Response wraps the signed one")

    # --- other ways to lie ---------------------------------------------------------------------
    # CVE-2017-11427: the attacker gets admin@example.org.evil.example signed, then puts a comment
    # inside it. Canonicalization drops comments, so it still verifies; code that reads the first
    # text node gets admin@example.org.
    signed_evil = sign_assertion(response(name_id="admin@example.org.evil.example"), idp_key, idp_cert)
    data = etree.tostring(signed_evil).replace(b">admin@example.org.evil.example<", b">admin@example.org<!---->.evil.example<")
    write("comment-in-nameid.xml", data, cases, ["SS005"], "CVE-2017-11427: a comment truncates the NameID for some parsers",
          absent=["SS001", "SS002"])
    data = etree.tostring(signed_a).replace(b">alice@example.org<", b">admin@example.org<")
    write("tampered-nameid.xml", data, cases, ["SS002"], "the NameID is changed after signing")
    write("attacker-key.xml", sign_assertion(response(), evil_key, evil_cert), cases, ["SS003"],
          "signed with a key the message carries, not the identity provider's")
    write("unsigned.xml", response(), cases, ["SS002"], "nothing is signed")
    dtd = b'<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>\n' + etree.tostring(signed_a)
    (OUT / "dtd.xml").write_bytes(dtd)
    cases["dtd.xml"] = {"cert": "idp.pem", "refused": True, "note": "a DTD with an external entity is refused, not parsed"}

    (OUT / "expected.json").write_text(json.dumps(cases, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {len(cases)} messages to {OUT}")


if __name__ == "__main__":
    main()
