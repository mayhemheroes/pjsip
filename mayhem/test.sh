#!/usr/bin/env bash
#
# pjsip/mayhem/test.sh — PATCH-grade golden oracle over the FUZZED parse paths.
#
# Why a custom oracle and not `make pjsip-test`/`pjlib-test`: pjproject's bundled unit-test
# binaries pull in transport/transaction suites that open UDP/TCP loopback sockets and spin the
# ioqueue (network/device dependent — they hang or fail in a sandboxed build). So we build a small
# SELF-CONTAINED driver (mayhem/oracle.c) that calls the exact parsers the harnesses fuzz —
# pjsip_parse_msg / pjsip_parse_uri (fuzz-sip), pjmedia_sdp_parse (fuzz-sdp),
# pj_stun_msg_decode (fuzz-stun), pj_xml_parse/pj_xml_print (fuzz-xml) — with known-GOOD inputs
# that MUST parse and known-BAD inputs that MUST be rejected. A no-op patch that always accepts or
# always rejects flips at least one case, so this is a real oracle, not a stub.
#
# The pjproject libs are already built (by mayhem/build.sh, with sanitizer flags). To keep this an
# honest oracle we relink the driver here against those libs; the driver itself is compiled with
# the lib's own PJ_CFLAGS (sanitizers come along, which is fine — we only assert PARSE RESULTS, and
# any sanitizer abort would also be a real failure). exit 0 iff every case passes.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${CC:=clang}" ; : "${CXX:=clang++}"
: "${SRC:=$(cd "$(dirname "$0")/.." && pwd)}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -f build.mak ]; then
  echo "missing build.mak — run mayhem/build.sh first" >&2
  emit_ctrf "pjsip-oracle" 0 1 0; exit 2
fi

# Pull pjproject's own include/lib flags out of build.mak.
FLAGS_MK="$(mktemp)"
cat > "$FLAGS_MK" <<'MK'
include build.mak
show:
	@printf 'PJ_CFLAGS=%s\n' "$(PJ_CFLAGS)"
	@printf 'PJ_LDFLAGS=%s\n' "$(PJ_LDFLAGS)"
	@printf 'PJ_LDLIBS=%s\n' "$(PJ_LDLIBS)"
MK
PJ_CFLAGS=$(make -f "$FLAGS_MK" show 2>/dev/null | sed -n 's/^PJ_CFLAGS=//p')
PJ_LDFLAGS=$(make -f "$FLAGS_MK" show 2>/dev/null | sed -n 's/^PJ_LDFLAGS=//p')
PJ_LDLIBS=$(make -f "$FLAGS_MK" show 2>/dev/null | sed -n 's/^PJ_LDLIBS=//p')
rm -f "$FLAGS_MK"

if [ -z "$PJ_CFLAGS" ]; then
  echo "could not read PJ_CFLAGS from build.mak" >&2
  emit_ctrf "pjsip-oracle" 0 1 0; exit 2
fi

ORACLE_BIN="$SRC/mayhem-build/oracle"
mkdir -p "$SRC/mayhem-build"
echo "=== compiling oracle ==="
# NOTE on the -fno-sanitize=function relaxation (also applied to the libs in build.sh): pjproject's
# lock.c calls pj_mutex_lock through a generic `int(*)(void*)` typedef (lock.c:179). Under the base
# image's halting UBSan that benign function-pointer-type mismatch would abort before any parse
# assertion runs — it is NOT a parser bug. We compile the oracle the same way for consistency; all
# other ASan/UBSan checks over the parser code stay halting.
ORACLE_CFLAGS="$PJ_CFLAGS -fno-sanitize=function"
# Compile in C mode ($CC, NOT clang++ which mis-detects .c), link with $CXX (pjproject needs libstdc++).
if ! $CC $ORACLE_CFLAGS -c "$SRC/mayhem/oracle.c" -o "$SRC/mayhem-build/oracle.o" 2>&1; then
  echo "oracle compile failed" >&2
  emit_ctrf "pjsip-oracle" 0 1 0; exit 2
fi
if ! $CXX $PJ_CFLAGS "$SRC/mayhem-build/oracle.o" $PJ_LDFLAGS $PJ_LDLIBS -o "$ORACLE_BIN" 2>&1; then
  echo "oracle link failed" >&2
  emit_ctrf "pjsip-oracle" 0 1 0; exit 2
fi

echo "=== running oracle ==="
# Don't let ASan leak accounting (pjproject pools are intentionally not all freed) fail the parse oracle.
out="$(ASAN_OPTIONS=detect_leaks=0 "$ORACLE_BIN" 2>&1)"; rc=$?
echo "$out"

PASSED=$(printf '%s\n' "$out" | grep -c '^PASS ')
FAILED=$(printf '%s\n' "$out" | grep -c '^FAIL ')
: "${PASSED:=0}" "${FAILED:=0}"

# If the binary crashed (sanitizer abort / signal) without printing the summary, count it as a failure.
if ! printf '%s\n' "$out" | grep -q '^ORACLE_SUMMARY '; then
  echo "oracle did not complete (rc=$rc)" >&2
  [ "$FAILED" -lt 1 ] && FAILED=$(( FAILED + 1 ))
fi

emit_ctrf "pjsip-oracle" "$PASSED" "$FAILED"
