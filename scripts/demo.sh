#!/usr/bin/env bash
# Prints the README's example: each command, then what it prints. Run from anywhere.
set -u
cd "$(dirname "$0")/.."
bin=${SAMLSIFT:-./bin/samlsift}
c=testdata/corpus
run() {
  echo "\$ samlsift $*"
  "$bin" "$@" 2>&1 | tr -d '\r'
}
run --cert $c/idp.pem --now 2026-01-01T10:01:00Z $c/good-assertion-signed.xml
echo
run --cert $c/idp.pem --now 2026-01-01T10:01:00Z $c/xsw-evil-assertion-first.xml
echo
run --cert $c/idp.pem --now 2026-01-01T10:01:00Z $c/comment-in-nameid.xml
