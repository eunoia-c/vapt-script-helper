# anonymize

Two tools for scrubbing client-identifying data out of engagement artifacts
before they touch a third-party or self-hosted LLM.

| | `anonymize.sh` | `anonymize.py` |
|---|---|---|
| Scope | one file, text, or stdin | a whole directory tree |
| Speed | instant, no setup | seconds on a decompiled APK |
| camelCase-aware boundaries | yes | no (whole-token only) |
| Renames file/directory paths | no | yes |
| Auto-detects secrets, IPs, hosts, JWTs | no | yes |
| Reversible mapping file | no | yes |
| Deterministic across runs | no | yes (salted hash) |
| Dependencies | bash, perl | python3 stdlib |

Rule of thumb: **`.sh` for a snippet you're about to paste into a chat,
`.py` for a tree you're about to upload or index.**

Neither tool is a substitute for reading the diff before you send anything.

---

## anonymize.sh

Shell function. Redacts a comma-separated keyword list, with boundary logic
that understands camelCase and SCREAMING_SNAKE identifiers.

### Install

```bash
cat anonymize.sh >> ~/.bashrc && source ~/.bashrc
```

### Use

```bash
anonymize -k acme,jdoe -t "getAcmeToken() ACME_KEY acmebank"
# get<<T1>>Token() <<T1>>_KEY acmebank

cat bundle.min.js | anonymize -k acme,acmebank | pbcopy

anonymize -k acme -f app.js          # writes app.js, keeps app.js.bak
anonymize -k acme -F -f app.js       # no backup
anonymize -k acme,jdoe -r REDACTED -t "acme and jdoe"   # single token
```

### Flags

| Flag | Meaning |
|---|---|
| `-k` | comma-separated keywords (required) |
| `-f` | edit a file in place, `.bak` kept unless `-F` |
| `-t` | anonymize a literal string |
| `-r` | use one fixed token for everything instead of `<<T1>>`, `<<T2>>` |
| `-F` | skip the backup on `-f` |

Order doesn't matter. With no `-f`/`-t` it reads stdin.

### How the boundary works

```
(?: (?<![a-zA-Z0-9]) | (?<=[a-z0-9])(?=[A-Z]) )
( (?i: keyword|keyword|... ) )
(?: (?![a-zA-Z0-9]) | (?=[A-Z]) )
```

A match may start either at a non-alphanumeric boundary **or** at a
lower→upper camelCase hump, and end the same way. So `acme` matches inside
`getAcmeToken` and `ACME_KEY`, but not inside `acmebank` — list `acmebank`
separately if you want it. Keywords are sorted longest-first, so `acmebank`
wins over `acme` regardless of the order you type them.

To make `acme2` stop matching, remove `0-9` from both lookaround classes.

### Safety properties

The Perl program is a fixed string literal; keywords are passed via
`$ENV{ANON_KEYWORDS}` and run through `quotemeta` inside Perl. Consequences:

- No keyword can inject Perl code or escape the `s///` delimiter.
- `admin@acme.com` and `price$` work as literals instead of being silently
  interpolated to nothing. (Silent non-redaction was the failure mode this
  design exists to prevent.)
- `acme.com` matches `acme.com`, not `acmeXcom`.
- Empty keywords (`acme,` or `a,,b`) are rejected rather than producing an
  alternation that matches the empty string at every position.
- Files containing NUL bytes are refused, so you can't corrupt a `.so`
  or `.dex` by pointing `-f` at it.

---

## anonymize.py

Copies a directory tree and rewrites the copy. Built for decompiled APKs
(smali, java, XML, JSON, JS assets) but works on any tree of text files.

### Workflow

```bash
python3 anonymize.py init -o cfg.json
$EDITOR cfg.json                       # fill in the terms list

python3 anonymize.py scan -c cfg.json -i ./apk_out --show
python3 anonymize.py run  -c cfg.json -i ./apk_out -o ./apk_clean \
                          -s "$(openssl rand -hex 8)" -m mapping.json

# ... work on ./apk_clean, feed it to the model, write findings ...

python3 anonymize.py deanon -m mapping.json -f findings.md -o findings-real.md
```

Always `scan` first. It reports counts by category and, with `--show`, the
full list of values that would be replaced — that's your chance to catch a
rule matching far more or far less than you intended.

### Config

```json
{
  "terms": [
    {"value": "acme",     "kind": "ORG",  "substring": true},
    {"value": "acmebank", "kind": "ORG",  "substring": true},
    {"value": "jdoe",     "kind": "USER", "substring": false}
  ],
  "allowlist": ["schemas.android.com", "8.8.8.8", "..."],
  "auto": ["PRIVKEY", "JWT", "AWSKEY", "GOOGLEKEY", "SLACKTOK",
           "GHTOKEN", "BEARER", "EMAIL", "IPV4", "FIREBASE", "HOST"],
  "rename_paths": true,
  "skip_dirs": [".git", "node_modules", "build", ".gradle", "original"]
}
```

**terms** — list atomic words, not full package names. One rule for `acme`
catches `com.acme.app`, `com/acme/app`, `Lcom/acme/app;`, `com_acme_app`,
`AcmeActivity`, and `ACME_KEY`, because separators do the boundary work.
Longest term wins. `substring: true` also matches inside larger words;
`false` requires non-alphanumeric boundaries on both sides.

**kind** — becomes the token prefix (`ORG_1823F0B1`). Use it to keep entity
classes distinguishable in the model's view.

**allowlist** — hostnames and IPs the `HOST`/`IPV4` detectors leave alone.
Without it, `schemas.android.com` in every manifest becomes noise. Matching
is on exact value or dotted suffix.

**auto** — which generic detectors to enable. `PHONE` exists but is off by
default; it false-positives on version strings and smali offsets.

### Tokens

`sha256(salt + kind + value)` truncated to 8 hex chars. The same input always
produces the same token, across files and across runs with the same salt, so
the model can correlate `ORG_1823F0B1` between a manifest and a smali class.
Use a fresh random salt per engagement.

Named terms run *before* the generic detectors, deliberately. `api.acme.com`
becomes `api.ORG_1823F0B1.com` — structure preserved, attribution gone. If
you'd rather destroy the hostname entirely, drop the term rule and let `HOST`
catch it.

Case is preserved: `Acme` → `Org_1823f0b1`, `ACME` → `ORG_1823F0B1`.

### Path renaming

With `rename_paths: true`, `smali/com/acme/app/Login.smali` becomes
`smali/com/org_1823f0b1/app/Login.smali`. Directory structure in a decompiled
APK leaks the package name just as loudly as the code does.

---

## Limits

Read these before you rely on either tool.

- **Binaries are not scrubbed.** `anonymize.py` skips them by default;
  `--keep-binary` copies them through untouched. `resources.arsc`, `.so`
  files, and embedded images routinely contain hostnames and API keys.
  Usually the right answer is to leave them out entirely.
- **`HOST` only matches a fixed TLD list.** Add `.corp`, `.internal`, or
  whatever the client uses. Anything not on the list passes through.
- **Detection is best-effort.** A hardcoded secret in an unusual format,
  a hostname split across string concatenations, or a client name spelled
  differently than your terms list will not be caught.
- **`mapping.json` is the whole secret.** It maps every token back to the
  real value. Keep it out of the output directory, out of version control,
  and off anything you upload.
- **Structure survives anonymization.** Endpoint layouts, class hierarchies,
  and API shapes can be identifying on their own. Scrubbing names does not
  make an artifact safe to share publicly — it reduces incidental exposure
  when you send it to a model.
- **Check your contract.** Many pentest MSAs now have explicit clauses about
  third-party AI processing of engagement data. Anonymization may reduce the
  risk without changing the obligation.
