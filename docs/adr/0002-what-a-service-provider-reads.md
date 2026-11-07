# 2. Judge a signature by what a service provider reads

Status: accepted

## Context

Signature wrapping works because "the signature verifies" and "the assertion I am about to log
in is the one that was signed" are separate questions, and most code answers only the first. A
verifier finds the element a reference's ID names; the code that reads the assertion afterwards
finds an Assertion element by position. An attacker who adds an unsigned assertion where the
reader looks, and leaves the signed one where the verifier looks, gets both answers they want.

There is no single way service providers find "the" assertion. The common ones, in libraries and
in hand-written code, are the first Assertion child of the Response and the first Assertion in the
document; a careful library returns the element the signature names and has the caller read that.

## Decision

Verify every signature independently, then work out the assertion each common way of reading
arrives at, and require a trusted signature to cover each of them. A signature covers an assertion
when its reference names the assertion or an element containing it, or the whole document. Where
the signature itself sits does not matter: a first version also required it to be inside what it
references, which mutation testing showed adds nothing, since the reference must already contain
the assertion being read, and it would call a legitimate signature placed elsewhere wrapping.

When the readings differ from what is signed, the finding names the reading, the element it
arrives at, and that a valid signature exists elsewhere: that combination is wrapping, which is
critical, and different from a message nobody signed, which is high.

A certificate carried in the message proves only that the message was signed by whoever put it
there. Without `--cert` the signature is still checked with it, so wrapping and tampering are
still found, and the result says the signer is unknown. With `--cert`, only the configured
certificate counts.

## Consequences

- A service provider that reads assertions some other way (the last one, one chosen by an
  attribute) is not modelled. The JSON output names every signature's target, so such a reader can
  still be checked by hand.
- Values are read as a careful parser would, with comments left out, and a value a comment splits
  is reported (CVE-2017-11427 and its relatives), since some readers take the first text node.
- Time windows are checked exactly, without clock skew; a service provider usually allows a
  minute or two, so a finding at the edge of a window deserves a look rather than alarm.
