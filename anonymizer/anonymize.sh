# anonymize -- hardened. Keeps the original camelCase-aware boundary logic.
#
#
# usage:
#   anonymize -k acme,jdoe -t "getAcmeToken()"
#   anonymize -k acme,jdoe -f app.js
#   cat bundle.js | anonymize -k acme
#   anonymize -k acme -r REDACTED -t "..."      # single token, old behaviour

anonymize() {
    local keywords="" file="" text="" mode="" fixed_repl="" force=0 use_stdin=0

    while (( $# )); do
        case "$1" in
            -k) keywords="$2"; shift 2 ;;
            -f) file="$2"; mode="file"; shift 2 ;;
            -t) text="$2"; mode="text"; shift 2 ;;
            -r) fixed_repl="$2"; shift 2 ;;
            -F) force=1; shift ;;
            -h|--help)
                echo "usage: anonymize -k <csv-keywords> [-f file | -t text | < stdin] [-r token] [-F]"
                return 0 ;;
            *)  echo "[-] unknown arg: $1" >&2; return 1 ;;
        esac
    done

    if [[ -z "$keywords" ]]; then
        echo "[-] -k <keywords> is required" >&2; return 1
    fi
    # Reject empty elements -- "acme," used to build (?i:acme|) which matches
    # the empty string at every position and destroys the input.
    if [[ "$keywords" == *,,* || "$keywords" == ,* || "$keywords" == *, ]]; then
        echo "[-] empty keyword in list (leading/trailing/double comma)" >&2; return 1
    fi

    # The perl program is a fixed literal. Nothing from the user reaches it as
    # code -- only as $ENV{} data.
    local prog='
        my @kw = split /,/, $ENV{ANON_KEYWORDS};
        my $repl = $ENV{ANON_REPL};
        my %tok;
        for my $i (0 .. $#kw) {
            $tok{lc $kw[$i]} = length($repl) ? $repl : sprintf("<<T%d>>", $i + 1);
        }
        # longest first so "acmebank" wins over "acme"
        my $alt = join "|", map { quotemeta } sort { length($b) <=> length($a) } @kw;
        my $re = qr/
            (?: (?<![a-zA-Z0-9]) | (?<=[a-z0-9])(?=[A-Z]) )
            ( (?i: $alt ) )
            (?: (?![a-zA-Z0-9]) | (?=[A-Z]) )
        /x;
        while (<>) { s/$re/$tok{lc $1}/g; print; }
    '

    if [[ "$mode" == "file" ]]; then
        [[ -f "$file" ]] || { echo "[-] file not found: $file" >&2; return 1; }
        if LC_ALL=C grep -qP '\x00' "$file" 2>/dev/null; then
            echo "[-] refusing binary file: $file" >&2; return 1
        fi
        local suffix=".bak"
        (( force )) && suffix=""
        ANON_KEYWORDS="$keywords" ANON_REPL="$fixed_repl" \
            perl -CSD -i"$suffix" -e "$prog" "$file" || return 1
        if (( force )); then
            echo "[+] anonymized in place (no backup): $file"
        else
            echo "[+] anonymized: $file  (original at ${file}.bak)"
        fi

    elif [[ "$mode" == "text" ]]; then
        printf '%s\n' "$text" | ANON_KEYWORDS="$keywords" ANON_REPL="$fixed_repl" \
            perl -CSD -e "$prog"

    elif [[ ! -t 0 ]]; then
        ANON_KEYWORDS="$keywords" ANON_REPL="$fixed_repl" perl -CSD -e "$prog"

    else
        echo "[-] no input. use -f <file>, -t <text>, or pipe stdin." >&2
        return 1
    fi
}
