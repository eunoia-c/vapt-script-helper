#!/usr/bin/env bash
#
# find_signing_logic.sh
#
# Helps locate request-signing / integrity-check logic in a decompiled
# mobile app (Java/Kotlin/Smali source tree from jadx/apktool, and/or
# raw .so libraries for Flutter/native apps where source isn't readable).
#
# Usage:
#   ./find_signing_logic.sh /path/to/decompiled_apk_dir
#
# Output:
#   - Printed to terminal, grouped by category
#   - Also written to signing_findings_<timestamp>.txt in the current dir
#
# Requires: grep, strings (binutils), find. All standard on Linux/macOS.

set -uo pipefail

TARGET_DIR="${1:-}"

if [[ -z "$TARGET_DIR" || ! -d "$TARGET_DIR" ]]; then
    echo "Usage: $0 /path/to/decompiled_apk_dir"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT_FILE="signing_findings_${TIMESTAMP}.txt"

# Keywords likely to appear near request-signing / HMAC / integrity logic.
# Grouped so you can scan the report by category.
declare -A KEYWORD_GROUPS=(
  [GENERAL_SIGNING]="signature|signRequest|signPayload|requestSign|apiSign|generateSignature|verifySignature|X-Signature|X-Sign|X-Sig|sig="
  [CRYPTO_PRIMITIVES]="HMAC|Mac\.getInstance|MessageDigest|SecretKeySpec|SHA256|SHA-256|SHA1|MD5|Cipher\.getInstance|KeyGenerator|PBKDF2"
  [KEY_MATERIAL]="secretKey|apiKey|api_key|clientSecret|signingKey|hmacKey|privateKey|SECRET_KEY|API_SECRET"
  [REPLAY_PROTECTION]="nonce|timestamp|X-Timestamp|X-Nonce|X-Request-ID|requestId"
  [NATIVE_JNI]="System\.loadLibrary|native |JNI_OnLoad|external fun|@Keep"
  [HEADERS_GENERIC]="X-Auth|X-Token|X-Checksum|Authorization|okhttp3\.Interceptor|addHeader|Interceptor"
)

echo "=== Signing/Integrity Logic Scan ===" | tee "$OUT_FILE"
echo "Target: $TARGET_DIR" | tee -a "$OUT_FILE"
echo "Date:   $(date)" | tee -a "$OUT_FILE"
echo "" | tee -a "$OUT_FILE"

# ---------------------------------------------------------
# 1. Source-level scan (Java/Kotlin/Smali) — file + line number
# ---------------------------------------------------------
echo "----------------------------------------" | tee -a "$OUT_FILE"
echo "[1] Source-level matches (java/kt/smali/xml)" | tee -a "$OUT_FILE"
echo "----------------------------------------" | tee -a "$OUT_FILE"

for GROUP in "${!KEYWORD_GROUPS[@]}"; do
    PATTERN="${KEYWORD_GROUPS[$GROUP]}"
    echo "" | tee -a "$OUT_FILE"
    echo ">> Category: $GROUP" | tee -a "$OUT_FILE"

    # -r recursive, -n line numbers, -I skip binaries, -E extended regex
    # Includes java, kt, smali, xml (for manifest/network-security-config hints)
    grep -rnIE \
        --include="*.java" \
        --include="*.kt" \
        --include="*.smali" \
        --include="*.xml" \
        "$PATTERN" "$TARGET_DIR" 2>/dev/null | \
        awk -F: '{ file=$1; line=$2; $1=""; $2=""; printf "  %s:%s  ->%s\n", file, line, $0 }' | \
        tee -a "$OUT_FILE"
done

# ---------------------------------------------------------
# 2. Native library scan (.so) — for Flutter/NDK-heavy apps
#    where jadx/apktool source won't show the actual logic.
#    strings doesn't give line numbers (it's a binary), so we
#    report byte offset instead, which you can jump to in
#    Ghidra/IDA/radare2.
# ---------------------------------------------------------
echo "" | tee -a "$OUT_FILE"
echo "----------------------------------------" | tee -a "$OUT_FILE"
echo "[2] Native library (.so) string matches" | tee -a "$OUT_FILE"
echo "    (Flutter apps: check libapp.so / libflutter.so -- logic is" | tee -a "$OUT_FILE"
echo "     compiled, so these are just string refs; load offsets into" | tee -a "$OUT_FILE"
echo "     Ghidra to find xrefs to the actual signing function.)" | tee -a "$OUT_FILE"
echo "----------------------------------------" | tee -a "$OUT_FILE"

if command -v strings >/dev/null 2>&1; then
    SO_FILES=$(find "$TARGET_DIR" -type f -name "*.so" 2>/dev/null)
    if [[ -z "$SO_FILES" ]]; then
        echo "  No .so files found under $TARGET_DIR" | tee -a "$OUT_FILE"
    else
        while IFS= read -r SO; do
            echo "" | tee -a "$OUT_FILE"
            echo ">> $SO" | tee -a "$OUT_FILE"
            for GROUP in "${!KEYWORD_GROUPS[@]}"; do
                PATTERN="${KEYWORD_GROUPS[$GROUP]}"
                # -t x prints byte offset in hex before each matching string
                MATCHES=$(strings -t x "$SO" 2>/dev/null | grep -iE "$PATTERN")
                if [[ -n "$MATCHES" ]]; then
                    echo "   [$GROUP]" | tee -a "$OUT_FILE"
                    echo "$MATCHES" | sed 's/^/     offset /' | tee -a "$OUT_FILE"
                fi
            done
        done <<< "$SO_FILES"
    fi
else
    echo "  'strings' not found on this system — install binutils." | tee -a "$OUT_FILE"
fi

# ---------------------------------------------------------
# 3. Quick pointer for Flutter-specific detection
# ---------------------------------------------------------
echo "" | tee -a "$OUT_FILE"
echo "----------------------------------------" | tee -a "$OUT_FILE"
echo "[3] Flutter indicator check" | tee -a "$OUT_FILE"
echo "----------------------------------------" | tee -a "$OUT_FILE"
if find "$TARGET_DIR" -iname "libflutter.so" 2>/dev/null | grep -q .; then
    echo "  This IS a Flutter app -> Dart logic is AOT-compiled into libapp.so." | tee -a "$OUT_FILE"
    echo "  Recommended: use 'blutter' or 'reFlutter' to recover Dart snapshot" | tee -a "$OUT_FILE"
    echo "  symbols/strings for better function-level visibility than raw strings." | tee -a "$OUT_FILE"
else
    echo "  No libflutter.so detected — likely native Android/iOS, source scan (section 1) is primary." | tee -a "$OUT_FILE"
fi

echo "" | tee -a "$OUT_FILE"
echo "=== Done. Full report saved to: $OUT_FILE ===" | tee -a "$OUT_FILE"
