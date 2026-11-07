#!/usr/bin/env python3
"""Compares samlsift's canonicalization with libxml2's, through lxml, byte for byte.

It writes generated documents built to be awkward (prefixes declared, redeclared and unused,
a default namespace set and undone, attribute values with literal and referenced whitespace,
CDATA, comments, processing instructions, xml:lang), then canonicalizes each one, and each
element in it, both ways: inclusive and exclusive, with and without comments, and exclusive
with InclusiveNamespaces prefix lists.

    python scripts/compare_c14n.py [--count N] [--seed S] [--keep DIR]

Needs lxml, and a Go toolchain to build scripts/c14ndump.
"""

import argparse
import collections
import os
import pathlib
import random
import subprocess
import sys
import tempfile

from lxml import etree

URIS = ["urn:a", "urn:b", "http://example.org/c", "urn:oasis:names:tc:SAML:2.0:assertion"]
PREFIXES = ["a", "b", "saml", "ds", "x"]
TEXTS = ["plain", " spaced  out ", "a & b", "less < more > done", "tab\there", "line\nbreak", "été ☃", "]]"]
ATTR_VALUES = ["v", "a&amp;b", "q&quot;uote", "lt&lt;gt>", "tab&#9;ref", "nl&#10;ref", "cr&#13;ref", "literal\ttab", "literal\nnl", "it's"]


class Builder:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.next_id = 0
        # Whether some element redeclares a prefix with the value it already has.
        self.redundant = False

    def element(self, depth: int, scope: dict[str, str]) -> str:
        r = self.rng
        decls = {}
        for _ in range(r.randint(0, 2)):
            p = r.choice(PREFIXES + [""])
            decls[p] = r.choice(URIS)
        if "" not in decls and scope.get("") and r.random() < 0.15:
            decls[""] = ""  # undo the default namespace
        if any(scope.get(p, "" if p == "" else None) == uri for p, uri in decls.items()):
            self.redundant = True
        here = dict(scope)
        here.update(decls)
        usable = [p for p in here if p and here[p]]
        prefix = r.choice(usable) if usable and r.random() < 0.6 else ""
        name = (prefix + ":" if prefix else "") + r.choice(["e", "item", "Assertion", "x-y", "n.m"])
        self.next_id += 1
        attrs = [f'id="n{self.next_id}"']
        if r.random() < 0.15:
            attrs.append('xml:lang="en"')
        for i in range(r.randint(0, 3)):
            ap = r.choice(usable) if usable and r.random() < 0.4 else ""
            local = r.choice(["z", "b", "a", "m"]) + str(i)
            attrs.append(f'{ap + ":" if ap else ""}{local}="{r.choice(ATTR_VALUES)}"')
        for p, uri in decls.items():
            attrs.append(f'xmlns{":" + p if p else ""}="{uri}"')
        r.shuffle(attrs)
        children = []
        if depth < 4:
            for _ in range(r.randint(0, 4)):
                kind = r.random()
                if kind < 0.45:
                    children.append(self.element(depth + 1, here))
                elif kind < 0.7:
                    children.append(escape(r.choice(TEXTS)))
                elif kind < 0.8:
                    children.append("<![CDATA[" + r.choice(["x < y", "a & b", "plain"]) + "]]>")
                elif kind < 0.9:
                    children.append("<!--" + r.choice(["c", " note ", ""]) + "-->")
                else:
                    children.append("<?pi " + r.choice(["data", "", "a=b"]) + "?>")
        sep = r.choice([" ", "\n  ", "\t"])
        head = f"<{name}{sep}{sep.join(attrs)}"
        if not children and r.random() < 0.5:
            return head + "/>"
        return head + ">" + "".join(children) + f"</{name}>"

    def document(self) -> str:
        r = self.rng
        prolog = r.choice(["", '<?xml version="1.0" encoding="UTF-8"?>\n', "<!--before-->", "<?top x?>\n"])
        epilog = r.choice(["", "<!--after-->", "\n<?end?>"])
        return prolog + self.element(0, {}) + epilog


def escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def inherits_xml_attributes(el) -> bool:
    for ancestor in el.iterancestors():
        if any(name.startswith("{http://www.w3.org/XML/1998/namespace}") for name in ancestor.attrib):
            return True
    return False


def lxml_c14n(doc: etree._ElementTree, el, exclusive: bool, comments: bool, prefixes) -> bytes:
    if el is None or el is doc.getroot():
        # lxml's document serializer, which is libxml2's own algorithm. For the root element, the
        # canonical document less what is outside the root is the root's canonical form.
        whole = etree.tostring(doc, method="c14n", exclusive=exclusive, with_comments=comments, inclusive_ns_prefixes=prefixes)
        if el is None:
            return whole
        root = doc.getroot()
        name = (root.prefix + ":" if root.prefix else "") + etree.QName(root).localname
        start = whole.index(b"<" + name.encode())
        end = whole.rindex(b"</" + name.encode() + b">") + len(name) + 3
        return whole[start:end]
    # Below the root, only lxml's element serializer is available. It treats the element as a
    # document of its own, which is not quite a document subset; see the skips below.
    return etree.tostring(el, method="c14n", exclusive=exclusive, with_comments=comments, inclusive_ns_prefixes=prefixes)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=300)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--keep", type=pathlib.Path)
    ap.add_argument("--show", type=int, default=5)
    args = ap.parse_args()
    root = pathlib.Path(__file__).resolve().parent.parent
    work = pathlib.Path(tempfile.mkdtemp())
    tool = work / ("c14ndump.exe" if os.name == "nt" else "c14ndump")
    subprocess.run(["go", "build", "-o", str(tool), "./scripts/c14ndump"], cwd=root, check=True)
    rng = random.Random(args.seed)
    counts = collections.Counter()
    shown = 0
    for n in range(args.count):
        builder = Builder(rng)
        text = builder.document()
        path = work / f"doc{n}.xml"
        path.write_bytes(text.encode("utf-8"))
        doc = etree.parse(str(path))
        ids = [e.get("id") for e in doc.iter() if isinstance(e.tag, str) and e.get("id")]
        targets = [None] + rng.sample(ids, min(3, len(ids)))
        for target in targets:
            el = None if target is None else doc.xpath(f"//*[@id='{target}']")[0]
            for exclusive in (False, True):
                for comments in (False, True):
                    lists = [None]
                    if exclusive:
                        # Not "#default": the libxml2 behind lxml ignores it, though the
                        # specification defines it. samlsift's tests and the signature
                        # comparison cover it instead.
                        lists.append(rng.sample(PREFIXES, 2))
                    for prefixes in lists:
                        below_root = el is not None and el is not doc.getroot()
                        if below_root and builder.redundant:
                            # lxml's element serializer keeps a redeclaration of a binding already
                            # in force; its document serializer drops it, as the specification
                            # says and samlsift does. Whole-document comparisons cover these.
                            counts["skipped: subtree of a document with a redundant redeclaration"] += 1
                            continue
                        if below_root and not exclusive and inherits_xml_attributes(el):
                            # Canonical XML 1.0 carries xml:* attributes down to a subset's apex
                            # (section 2.4); lxml serializes an element as a document of its own
                            # and does not. The signature comparison with xmlsec covers this case.
                            counts["skipped: inclusive subset under an xml:* attribute"] += 1
                            continue
                        want = lxml_c14n(doc, el, exclusive, comments, prefixes)
                        cmd = [str(tool), str(path), "exc" if exclusive else "inc", "comments" if comments else "nocomments",
                               target or "-", ",".join(prefixes) if prefixes else ""]
                        got = subprocess.run(cmd, capture_output=True, check=False).stdout
                        counts["comparisons"] += 1
                        if got == want:
                            continue
                        if below_root and want.replace(b' xmlns=""', b"") == got.replace(b' xmlns=""', b"") and want.count(b' xmlns=""') > got.count(b' xmlns=""'):
                            # lxml's element serializer adds xmlns="" under elements where the default
                            # namespace is already empty. At the root, where its document serializer
                            # can be used instead, it does not, and agrees with samlsift.
                            counts['known: lxml\'s element serializer adds xmlns=""'] += 1
                            continue
                        counts["differ"] += 1
                        counts[f"differ, exclusive={exclusive}, below the root={el is not None and el is not doc.getroot()}"] += 1
                        if shown < args.show:
                            shown += 1
                            print(f"--- {path.name} target={target} exclusive={exclusive} comments={comments} prefixes={prefixes}")
                            at = next((i for i, (x, y) in enumerate(zip(want, got)) if x != y), min(len(want), len(got)))
                            lo = max(0, at - 120)
                            print(f"  first difference at byte {at}")
                            print("  lxml:     " + want[lo:at + 80].decode("utf-8", "replace"))
                            print("  samlsift: " + got[lo:at + 80].decode("utf-8", "replace"))
                            if args.keep:
                                args.keep.mkdir(parents=True, exist_ok=True)
                                (args.keep / path.name).write_text(text, encoding="utf-8")
    for k, v in sorted(counts.items()):
        print(f"{k}: {v}")
    return 1 if counts["differ"] else 0


if __name__ == "__main__":
    sys.exit(main())
