#!/usr/bin/env bash
#
# find_signing_logic.sh
#
# v2: filters out known third-party/framework noise (Google Tink, Play
# Services, Guava, okio, kotlinx, AndroidX, the Flutter engine itself)
# so results focus on the APP'S OWN code. Also specifically surfaces
# package:*.dart / pub-cache path strings inside .so files, since for
# Flutter apps that's the highest-signal category (it reveals exact
# source file names like get_app_signature_function.dart).
#
# Usage:
#   ./find_signing_logic.sh /path/to/decompiled_apk_dir
#
# Output:
#   signing_findings_<timestamp>.txt

set -uo pipefail

TARGET_DIR="${1:-}"

if [[ -z "$TARGET_DIR" || ! -d "$TARGET_DIR" ]]; then
    echo "Usage: $0 /path/to/decompiled_apk_dir"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT_FILE="signing_findings_${TIMESTAMP}.txt"

declare -A KEYWORD_GROUPS=(
  [GENERAL_SIGNING]="signature|signRequest|signPayload|requestSign|apiSign|generateSignature|verifySignature|X-Signature|X-Sign|X-Sig|appseal|appSeal|sig="
  [CRYPTO_PRIMITIVES]="HMAC|Mac\.getInstance|MessageDigest|SecretKeySpec|SHA256|SHA-256|SHA1|MD5|Cipher\.getInstance|KeyGenerator|PBKDF2|Hmac\(|Sha256\(|Sha1\("
  [KEY_MATERIAL]="secretKey|_signatureKey|apiKey|api_key|clientSecret|signingKey|hmacKey|privateKey|SECRET_KEY|API_SECRET"
  [REPLAY_PROTECTION]="nonce|timestamp|X-Timestamp|X-Nonce|X-Request-ID|requestId"
  [HEADERS_GENERIC]="X-Auth|X-Token|X-Checksum|Authorization|addHeader|Interceptor"
)

# Package/path prefixes that are known third-party libraries, not app code.
# Extend this list as you identify more noise sources in your target.
NOISE_PATTERN='(com/google/crypto/tink|com/google/android/gms|com/google/common|com/google/protobuf|com/google/firebase|com/google/android/material|androidx/|kotlin/|kotlinx/|kotlinx/coroutines|okio/|okhttp3/internal|com/squareup/okhttp|retrofit2/internal|io/flutter/embedding|io/flutter/plugin|io/flutter/util|io/flutter/view|org/jetbrains/annotations|javax/|java/security|java/util|org/apache/|com/facebook/|io/grpc/|dagger/|rx/internal|io/reactivex/internal|com\.google\.crypto\.tink|com\.google\.android\.gms)'

echo "=== Signing/Integrity Logic Scan v2 (filtered) ===" | tee "$OUT_FILE"
echo "Target: $TARGET_DIR" | tee -a "$OUT_FILE"
echo "Date:   $(date)" | tee -a "$OUT_FILE"
echo "" | tee -a "$OUT_FILE"

# ---------------------------------------------------------
# 1. Source-level scan, filtered to exclude known noisy libs
# ---------------------------------------------------------
echo "----------------------------------------" | tee -a "$OUT_FILE"
echo "[1] Source-level matches (java/kt/smali/xml) -- APP CODE ONLY" | tee -a "$OUT_FILE"
echo "    (filtered: Tink, GMS, Guava/protobuf, AndroidX, Kotlin stdlib," | tee -a "$OUT_FILE"
echo "     okio/okhttp internals, Flutter engine itself, Dagger, RxJava)" | tee -a "$OUT_FILE"
echo "----------------------------------------" | tee -a "$OUT_FILE"

for GROUP in "${!KEYWORD_GROUPS[@]}"; do
    PATTERN="${KEYWORD_GROUPS[$GROUP]}"
    MATCHES=$(grep -rnIE \
        --include="*.java" \
        --include="*.kt" \
        --include="*.smali" \
        --include="*.xml" \
        "$PATTERN" "$TARGET_DIR" 2>/dev/null | grep -vE "$NOISE_PATTERN")

    if [[ -n "$MATCHES" ]]; then
        echo "" | tee -a "$OUT_FILE"
        echo ">> Category: $GROUP" | tee -a "$OUT_FILE"
        echo "$MATCHES" | awk -F: '{ file=$1; line=$2; $1=""; $2=""; printf "  %s:%s  ->%s\n", file, line, $0 }' | tee -a "$OUT_FILE"
    fi
done

# Report noise volume so you know how much was cut
RAW_COUNT=$(grep -rnIE --include="*.java" --include="*.kt" --include="*.smali" --include="*.xml" \
    "$(IFS='|'; echo "${KEYWORD_GROUPS[*]}")" "$TARGET_DIR" 2>/dev/null | wc -l)
FILTERED_COUNT=$(grep -rnIE --include="*.java" --include="*.kt" --include="*.smali" --include="*.xml" \
    "$(IFS='|'; echo "${KEYWORD_GROUPS[*]}")" "$TARGET_DIR" 2>/dev/null | grep -vcE "$NOISE_PATTERN")
echo "" | tee -a "$OUT_FILE"
echo "  [stats] raw matches: $RAW_COUNT | after noise filter: $FILTERED_COUNT" | tee -a "$OUT_FILE"

# ---------------------------------------------------------
# 2. Native library scan -- prioritized: app's own lib first,
#    then flag Flutter's libapp.so as the highest-value target,
#    and specifically pull package:*.dart / pub-cache strings.
# ---------------------------------------------------------
echo "" | tee -a "$OUT_FILE"
echo "----------------------------------------" | tee -a "$OUT_FILE"
echo "[2] Native library (.so) scan" | tee -a "$OUT_FILE"
echo "----------------------------------------" | tee -a "$OUT_FILE"

if command -v strings >/dev/null 2>&1; then
    SO_FILES=$(find "$TARGET_DIR" -type f -name "*.so" 2>/dev/null)
    if [[ -z "$SO_FILES" ]]; then
        echo "  No .so files found under $TARGET_DIR" | tee -a "$OUT_FILE"
    else
        while IFS= read -r SO; do
            BASENAME=$(basename "$SO")
            echo "" | tee -a "$OUT_FILE"
            echo ">> $SO" | tee -a "$OUT_FILE"

            if [[ "$BASENAME" == "libapp.so" ]]; then
                echo "   *** This is the Flutter Dart AOT snapshot -- highest-value target. ***" | tee -a "$OUT_FILE"
                echo "   [DART_SOURCE_PATHS]" | tee -a "$OUT_FILE"
                strings -t x "$SO" 2>/dev/null | grep -E 'package:|pub-cache|\.dart' | tee -a "$OUT_FILE"
            fi

            for GROUP in "${!KEYWORD_GROUPS[@]}"; do
                PATTERN="${KEYWORD_GROUPS[$GROUP]}"
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

echo "" | tee -a "$OUT_FILE"
echo "=== Done. Full report saved to: $OUT_FILE ===" | tee -a "$OUT_FILE"
echo "" | tee -a "$OUT_FILE"
echo "TIP: if [1] is still noisy, add more prefixes to NOISE_PATTERN at the top" | tee -a "$OUT_FILE"
echo "     of the script once you spot other bundled libs (e.g. analytics SDKs," | tee -a "$OUT_FILE"
echo "     ad SDKs, crash reporters -- these often false-positive on 'signature'" | tee -a "$OUT_FILE"
echo "     and 'nonce' too)." | tee -a "$OUT_FILE"
