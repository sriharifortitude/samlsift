#!/usr/bin/env python3
"""Checks samlsift against testdata/corpus, and each signature against signxml and xmlsec1.

For every message it requires the findings expected.json lists, and the absence of the ones it
rules out. For every signature samlsift reports, it asks other verifiers the same question:
does this signature verify with the identity provider's certificate, and over which element?
signxml (Python, lxml) is asked when it is installed, xmlsec1 (C, libxml2) when it is on PATH.

    python scripts/check_corpus.py [--samlsift BIN]
"""

import argparse
import collections
import json
import pathlib
import shutil
import subprocess
import sys

CORPUS = pathlib.Path(__file__).resolve().parent.parent / "testdata" / "corpus"
FLAGS = [
    "--now", "2026-01-01T10:01:00Z",
    "--audience", "https://sp.example.org/metadata",
    "--acs", "https://sp.example.org/saml/acs",
    "--issuer", "https://idp.example.org/metadata",
]


# Where signxml and samlsift are known to differ: message -> (samlsift's signed IDs, signxml's).
# In the XSW7 shape the signed assertion sits inside its own signature. The enveloped transform
# removes the signature and everything in it (XML Signature section 6.6.4), so nothing is left to
# digest and the signature is invalid; xmlsec1 rejects it too. signxml accepts it, and returns the
# hidden assertion as what was signed, which is safe only for code that reads what it returns.
SIGNXML_KNOWN = {"xsw-signed-in-object.xml": (set(), {"_a1"})}


def samlsift(binary: str, message: pathlib.Path, cert: pathlib.Path) -> tuple[int, dict | None, str]:
    run = subprocess.run([binary, "--json", "--cert", str(cert), *FLAGS, str(message)], capture_output=True, text=True, check=False)
    if run.returncode == 2:
        return 2, None, run.stderr.strip()
    return run.returncode, json.loads(run.stdout), run.stderr


def signxml_view(message: pathlib.Path, cert: pathlib.Path) -> set[str] | None:
    """The IDs of the elements signxml says are signed, or None when it refuses the message."""
    try:
        from lxml import etree
        from signxml import XMLVerifier
    except ImportError:
        return None
    doc = etree.fromstring(message.read_bytes())
    ds = "{http://www.w3.org/2000/09/xmldsig#}Signature"
    signed = set()
    sigs = list(doc.iter(ds))
    for i in range(len(sigs)):
        # signxml checks the first signature in the document, so the ones before this one are
        # taken out of a copy. Later ones stay: an outer signature covers an inner one.
        copy = etree.fromstring(message.read_bytes())
        for j, s in enumerate(list(copy.iter(ds))):
            if j < i:
                s.getparent().remove(s)
        try:
            result = XMLVerifier().verify(copy, x509_cert=cert.read_text(), id_attribute="ID", ignore_ambiguous_key_info=True)
        except Exception:  # noqa: BLE001 - any refusal means: not verified
            continue
        signed.add(result.signed_xml.get("ID") or "(document)")
    return signed


def samlsift_signed(report: dict) -> set[str]:
    out = set()
    for sig in report["signatures"]:
        if sig["verified"] and sig.get("key") == "the configured certificate":
            for ref in sig["references"]:
                out.add(ref.get("target_id") or "(document)")
    return out


def xmlsec_view(message: pathlib.Path, cert: pathlib.Path, report: dict) -> list[tuple[str, bool, str]]:
    """For each signature samlsift found, whether xmlsec1 verifies it with the certificate, and
    what xmlsec1 said. The messages carry their certificate in KeyInfo, so xmlsec1 is told to
    trust the identity provider's certificate rather than given it as a bare key: then a
    certificate an attacker put in the message is not trusted, which is the question asked."""
    out = []
    for sig in report["signatures"]:
        steps = sig["path"].split("/")
        xpath = "".join(f"/*[local-name()='{s.split('[')[0]}']" + (f"[{s.split('[')[1]}" if "[" in s else "") for s in steps)
        run = subprocess.run(
            ["xmlsec1", "--verify", "--trusted-pem", str(cert),
             "--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:protocol:Response",
             "--id-attr:ID", "urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
             "--node-xpath", xpath, str(message)],
            capture_output=True, text=True, check=False,
        )
        said = " | ".join(line.strip() for line in run.stderr.strip().splitlines()[-3:])
        out.append((sig["path"], run.returncode == 0, said))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samlsift", default="bin/samlsift")
    args = ap.parse_args()
    args.samlsift = str(pathlib.Path(args.samlsift).resolve())
    expected = json.loads((CORPUS / "expected.json").read_text(encoding="utf-8"))
    have_xmlsec = shutil.which("xmlsec1") is not None
    totals = collections.Counter()
    for name, case in sorted(expected.items()):
        message, cert = CORPUS / name, CORPUS / case["cert"]
        code, report, err = samlsift(args.samlsift, message, cert)
        totals["messages"] += 1
        if case.get("refused"):
            if code == 2:
                totals["refused as expected"] += 1
            else:
                totals["wrong"] += 1
                print(f"{name}: should be refused, exit {code}")
            continue
        if report is None:
            totals["wrong"] += 1
            print(f"{name}: samlsift could not read it: {err}")
            continue
        ids = {f["id"] for f in report["findings"]}
        for want in case["must_report"]:
            if want not in ids:
                totals["wrong"] += 1
                print(f"{name}: {want} missing ({case['note']}); got {sorted(ids)}")
        for unwanted in case["must_not_report"]:
            if unwanted in ids:
                totals["wrong"] += 1
                print(f"{name}: {unwanted} reported, but should not be ({case['note']})")
        mine = samlsift_signed(report)
        theirs = signxml_view(message, cert)
        if theirs is not None:
            totals["compared with signxml"] += 1
            if name in SIGNXML_KNOWN and (mine, theirs) == SIGNXML_KNOWN[name]:
                totals["documented differences with signxml"] += 1
            elif mine != theirs:
                totals["signxml disagrees"] += 1
                print(f"{name}: signed elements: samlsift {sorted(mine)}, signxml {sorted(theirs)}")
        if have_xmlsec:
            for path, ok, said in xmlsec_view(message, cert, report):
                totals["signatures compared with xmlsec1"] += 1
                sig = next(s for s in report["signatures"] if s["path"] == path)
                mine_ok = sig["verified"] and sig.get("key") == "the configured certificate"
                if ok != mine_ok:
                    totals["xmlsec1 disagrees"] += 1
                    print(f"{name}: {path}: samlsift {'verifies' if mine_ok else 'rejects'}, xmlsec1 {'verifies' if ok else 'rejects'}: {said[:300]}")
    for k, v in sorted(totals.items()):
        print(f"{k}: {v}")
    return 1 if totals["wrong"] or totals["signxml disagrees"] or totals["xmlsec1 disagrees"] else 0


if __name__ == "__main__":
    sys.exit(main())
