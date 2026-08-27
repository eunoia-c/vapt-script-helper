#!/usr/bin/env python3
"""
anonymize.py - deterministic, reversible scrubber for engagement artifacts.

Built for decompiled APKs (smali/java/xml/json) and JS bundles, but works on
any tree of text files.

Design notes:
  * Never edits in place. Copies the tree to --out and rewrites the copy.
  * Deterministic: the same term always maps to the same token, across runs
    and across files, so cross-file analysis still works.
  * Reversible: mapping.json lets you translate model output back to real
    names before it goes in the report. Keep that file OUT of the output dir.
  * Component-wise: you list atomic words ("acme"), not full package names.
    That way com.acme.app, com/acme/app, Lcom/acme/app;, com_acme_app and
    AcmeActivity all get caught by one rule.

Usage:
    python3 anonymize.py init                      # write a starter config
    python3 anonymize.py scan  -c cfg.json -i ./apk_out
    python3 anonymize.py run   -c cfg.json -i ./apk_out -o ./apk_clean
    python3 anonymize.py deanon -m mapping.json -f findings.md
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from collections import Counter

# ---------------------------------------------------------------- constants

BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svgz",
    ".so", ".dex", ".arsc", ".apk", ".jar", ".zip", ".gz", ".bz2", ".7z",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".pdf", ".keystore", ".jks",
}

MAX_BYTES = 25 * 1024 * 1024  # skip anything bigger; nothing useful is

# Auto-detected patterns. Order matters: longest/most specific first, because
# replacement happens sequentially and a greedy early rule can eat a later one.
AUTO_PATTERNS = [
    ("PRIVKEY", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
        r"[\s\S]{1,8000}?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("AWSKEY", re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("GOOGLEKEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("SLACKTOK", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("GHTOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("BEARER", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("IPV4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("FIREBASE", re.compile(r"\bhttps?://[A-Za-z0-9-]+\.firebaseio\.com\b")),
    ("HOST", re.compile(
        r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"(?:com|net|org|io|co|dev|app|cloud|internal|corp|local|lan|gov|edu|"
        r"uk|de|fr|jp|cn|au|ca|in|br|nl|se|ph|sg)\b")),
    ("PHONE", re.compile(r"(?<![\d.])\+?\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?![\d.])")),
]

# Things the HOST/IPV4 rules would otherwise mangle into uselessness.
DEFAULT_ALLOWLIST = [
    "android.com", "google.com", "googleapis.com", "gstatic.com",
    "schemas.android.com", "apache.org", "w3.org", "github.com",
    "npmjs.com", "jquery.com", "mozilla.org", "json.org", "oracle.com",
    "kotlinlang.org", "jetbrains.com", "squareup.com", "bumptech.github.io",
    "0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8",
    "10.0.2.2", "192.168.1.1",
]

STARTER_CONFIG = {
    "_comment": "terms = atomic words, not full package names. 'substring' catches acmebank.",
    "terms": [
        {"value": "acme", "kind": "ORG", "substring": True},
        {"value": "acmebank", "kind": "ORG", "substring": True},
        {"value": "jdoe", "kind": "USER", "substring": False},
    ],
    "allowlist": DEFAULT_ALLOWLIST,
    "auto": ["PRIVKEY", "JWT", "AWSKEY", "GOOGLEKEY", "SLACKTOK",
             "GHTOKEN", "BEARER", "EMAIL", "IPV4", "FIREBASE", "HOST"],
    "rename_paths": True,
    "skip_dirs": [".git", "node_modules", "build", ".gradle", "original"],
}

# ---------------------------------------------------------------- utilities


def stable_tag(value, kind, salt):
    """Deterministic short token. Same value+salt -> same token, always."""
    h = hashlib.sha256((salt + "\x00" + kind + "\x00" + value.lower()).encode()).hexdigest()
    return "{}_{}".format(kind, h[:8].upper())


def match_case(original, replacement):
    """Keep the shape of the original so code stays readable."""
    if original.isupper():
        return replacement.upper()
    if original.islower():
        return replacement.lower()
    if original[:1].isupper() and original[1:].islower():
        return replacement.capitalize()
    return replacement


def is_probably_text(path):
    if os.path.splitext(path)[1].lower() in BINARY_EXT:
        return False
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return False
        with open(path, "rb") as fh:
            chunk = fh.read(4096)
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    return True


def iter_files(root, skip_dirs):
    skip = set(skip_dirs)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            yield os.path.join(dirpath, name)


# ---------------------------------------------------------------- core


class Anonymizer:
    def __init__(self, config, salt):
        self.salt = salt
        self.mapping = {}        # token -> original
        self.reverse = {}        # original -> token
        self.counts = Counter()
        self.allow = {a.lower() for a in config.get("allowlist", DEFAULT_ALLOWLIST)}
        self.rename_paths = config.get("rename_paths", True)
        self.skip_dirs = config.get("skip_dirs", [])

        enabled = set(config.get("auto", []))
        self.auto = [(n, p) for n, p in AUTO_PATTERNS if n in enabled]

        # Longest terms first so "acmebank" wins over "acme".
        terms = sorted(config.get("terms", []),
                       key=lambda t: len(t["value"]), reverse=True)
        self.term_rules = []
        for t in terms:
            val = t["value"]
            kind = t.get("kind", "TERM")
            if t.get("substring"):
                pat = re.compile(re.escape(val), re.IGNORECASE)
            else:
                pat = re.compile(r"(?<![A-Za-z0-9])" + re.escape(val) + r"(?![A-Za-z0-9])",
                                 re.IGNORECASE)
            self.term_rules.append((pat, val, kind))

    def token_for(self, value, kind):
        key = (kind, value.lower())
        if key in self.reverse:
            return self.reverse[key]
        tok = stable_tag(value, kind, self.salt)
        # Collision guard.
        while tok in self.mapping and self.mapping[tok].lower() != value.lower():
            tok = tok + "X"
        self.mapping[tok] = value
        self.reverse[key] = tok
        return tok

    def _allowed(self, text):
        low = text.lower()
        return low in self.allow or any(low.endswith("." + a) for a in self.allow)

    def scrub(self, text):
        # 1. Explicit terms first -- they are the ones you actually care about,
        #    and running them before HOST means acme.com becomes CLIENT.com
        #    rather than an opaque HOST_ token you cannot correlate.
        for pat, val, kind in self.term_rules:
            def sub_term(m, val=val, kind=kind):
                self.counts[kind] += 1
                return match_case(m.group(0), self.token_for(val, kind))
            text = pat.sub(sub_term, text)

        # 2. Generic detectors.
        for name, pat in self.auto:
            def sub_auto(m, name=name):
                found = m.group(0)
                if name in ("HOST", "IPV4") and self._allowed(found):
                    return found
                if found.startswith(tuple(self.mapping.keys())):
                    return found
                self.counts[name] += 1
                return self.token_for(found, name)
            text = pat.sub(sub_auto, text)
        return text

    def scrub_path_component(self, comp):
        for pat, val, kind in self.term_rules:
            comp = pat.sub(lambda m, v=val, k=kind: match_case(m.group(0), self.token_for(v, k)),
                           comp)
        return comp


# ---------------------------------------------------------------- commands


def cmd_scan(args):
    cfg = json.load(open(args.config))
    an = Anonymizer(cfg, args.salt)
    hits = Counter()
    files = 0
    for path in iter_files(args.input, an.skip_dirs):
        if not is_probably_text(path):
            continue
        files += 1
        try:
            text = open(path, "r", encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        an.scrub(text)
    print("scanned {} text files".format(files))
    for k, v in an.counts.most_common():
        print("  {:<12} {}".format(k, v))
    print("\nunique values that would be replaced: {}".format(len(an.mapping)))
    if args.show:
        for tok, val in sorted(an.mapping.items(), key=lambda x: x[0]):
            print("  {} <- {}".format(tok, val))


def cmd_run(args):
    cfg = json.load(open(args.config))
    an = Anonymizer(cfg, args.salt)

    if os.path.exists(args.out):
        if not args.force:
            sys.exit("output dir exists; pass --force to overwrite")
        shutil.rmtree(args.out)

    copied = scrubbed = skipped = 0
    for src in iter_files(args.input, an.skip_dirs):
        rel = os.path.relpath(src, args.input)
        if an.rename_paths:
            parts = [an.scrub_path_component(p) for p in rel.split(os.sep)]
            rel = os.sep.join(parts)
        dst = os.path.join(args.out, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)

        if not is_probably_text(src):
            if args.keep_binary:
                shutil.copy2(src, dst)
                copied += 1
            else:
                skipped += 1
            continue

        try:
            text = open(src, "r", encoding="utf-8", errors="replace").read()
        except OSError:
            skipped += 1
            continue
        cleaned = an.scrub(text)
        with open(dst, "w", encoding="utf-8") as fh:
            fh.write(cleaned)
        scrubbed += 1

    with open(args.mapping, "w", encoding="utf-8") as fh:
        json.dump({"salt_hint": hashlib.sha256(args.salt.encode()).hexdigest()[:12],
                   "counts": dict(an.counts),
                   "mapping": an.mapping}, fh, indent=2, sort_keys=True)

    print("scrubbed {} files, copied {} binaries, skipped {}".format(scrubbed, copied, skipped))
    for k, v in an.counts.most_common():
        print("  {:<12} {}".format(k, v))
    print("\noutput:  {}".format(args.out))
    print("mapping: {}  <-- keep this local, it is the whole secret".format(args.mapping))


def cmd_deanon(args):
    data = json.load(open(args.mapping))
    mapping = data["mapping"] if "mapping" in data else data
    text = open(args.file, "r", encoding="utf-8", errors="replace").read()
    # Longest tokens first to avoid partial hits.
    for tok in sorted(mapping, key=len, reverse=True):
        text = re.sub(re.escape(tok), mapping[tok].replace("\\", "\\\\"), text,
                      flags=re.IGNORECASE)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text)
        print("wrote {}".format(args.out))
    else:
        sys.stdout.write(text)


def cmd_init(args):
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(STARTER_CONFIG, fh, indent=2)
    print("wrote {} -- edit the terms list before running".format(args.out))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="write a starter config")
    p.add_argument("-o", "--out", default="anon-config.json")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("scan", help="dry run, report what would change")
    p.add_argument("-c", "--config", required=True)
    p.add_argument("-i", "--input", required=True)
    p.add_argument("-s", "--salt", default="change-me")
    p.add_argument("--show", action="store_true", help="print the full mapping")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("run", help="write a scrubbed copy of the tree")
    p.add_argument("-c", "--config", required=True)
    p.add_argument("-i", "--input", required=True)
    p.add_argument("-o", "--out", required=True)
    p.add_argument("-m", "--mapping", default="mapping.json")
    p.add_argument("-s", "--salt", default="change-me")
    p.add_argument("--keep-binary", action="store_true",
                   help="copy binaries through (they are NOT scrubbed)")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("deanon", help="translate model output back to real names")
    p.add_argument("-m", "--mapping", required=True)
    p.add_argument("-f", "--file", required=True)
    p.add_argument("-o", "--out")
    p.set_defaults(func=cmd_deanon)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
