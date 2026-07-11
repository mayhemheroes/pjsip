#!/usr/bin/env bash
#
# pjsip/mayhem/build.sh — build pjproject's OSS-Fuzz protocol-parser harnesses as sanitized
# libFuzzer targets (+ standalone reproducers).
#
# Fuzzed surface (attacker-controlled wire bytes parsed by pjsip's own parsers):
#   fuzz-sip  — pjsip_parse_msg / header + URI parsers (SIP request/response messages, pjsip).
#   fuzz-sdp  — pjmedia_sdp_parse + SDP negotiation (SDP offer/answer bodies, pjmedia).
#   fuzz-stun — pj_stun_msg_decode + STUN/TURN attribute handling (binary STUN/TURN, pjnath).
#   fuzz-xml  — pj_xml_parse / pj_xml_print (PIDF / watcherinfo / XCAP XML, pjlib-util).
#
# Layout follows OSS-Fuzz (projects/pjsip): a full ./configure + make builds the static
# pjproject libraries, then each harness in tests/fuzz/ is compiled and linked against them.
# We scope to the four protocol parsers above (no codecs/SSL/ffmpeg) so the build is small and
# deterministic; the static libs are compiled WITH $SANITIZER_FLAGS so the parser code itself
# (not just the harness) is instrumented.
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN/OUT).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS: DWARF ≤ 3 required (§6.2 item 10); clang-19 plain -g emits DWARF-5, be explicit.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
export DEBUG_FLAGS
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=$(cd "$(dirname "$0")/.." && pwd)}"
: "${OUT:=/mayhem}"
export SANITIZER_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS SRC OUT

cd "$SRC"

# libFuzzer needs the link-time coverage instrumentation present in the libs (-fsanitize=fuzzer-no-link)
# so the engine sees edges in the parser code, not just the harness.
#
# -fno-sanitize=function: pjproject's lock.c calls pj_mutex_lock through a generic `int(*)(void*)`
# typedef (lock.c:179). Under the base image's halting UBSan (-fno-sanitize-recover=all) that benign
# function-pointer-type mismatch fires on the very first mutex lock — it is NOT a memory/parser bug,
# it would just abort every fuzz target immediately. We relax exactly that one (otherwise benign) UB
# check; all other ASan/UBSan checks over the parser code remain halting.
FUZZ_BUILD_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fno-sanitize=function -fsanitize=fuzzer-no-link -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"

# ── 1) Configure + build the pjproject static libraries (no SSL / codecs / ffmpeg) ────────────────
# The fuzzed parsers (pjsip msg/uri, pjmedia sdp, pjnath stun, pjlib-util xml) need none of those.
export CFLAGS="$FUZZ_BUILD_FLAGS"
export CXXFLAGS="$FUZZ_BUILD_FLAGS"
export LDFLAGS="$FUZZ_BUILD_FLAGS"

./configure \
  --disable-ffmpeg --disable-ssl \
  --disable-speex-aec --disable-speex-codec --disable-g7221-codec \
  --disable-gsm-codec --disable-ilbc-codec \
  --disable-resample --disable-libsrtp --disable-libwebrtc --disable-libyuv

# Skip `make dep` — it can produce corrupt .depend files; `make` regenerates deps itself.
find . -name "*.depend" -delete 2>/dev/null || true
make -j"$MAYHEM_JOBS" --ignore-errors

# ── 2) Resolve pjproject's own build flags (include paths, lib search paths, lib list) ────────────
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

[ -n "$PJ_CFLAGS" ] || { echo "ERROR: could not read PJ_CFLAGS from build.mak" >&2; exit 1; }

# ── 3) Build the standalone driver object once (provides main() for the -standalone reproducers) ──
BUILD="$SRC/mayhem-build"
mkdir -p "$BUILD"
$CC $FUZZ_BUILD_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"

# ── 4) Build each protocol-parser harness twice: libFuzzer (-> $OUT/<name>) + standalone ──────────
# Final link uses $CXX because $LIB_FUZZING_ENGINE / pjproject pull in the C++ runtime.
HARNESS_DIR="$SRC/tests/fuzz"
for harness in fuzz-sip fuzz-sdp fuzz-stun fuzz-xml; do
  obj="$BUILD/$harness.o"
  $CC $FUZZ_BUILD_FLAGS $PJ_CFLAGS -c "$HARNESS_DIR/$harness.c" -o "$obj"

  # libFuzzer target -> $OUT/<name>
  $CXX $FUZZ_BUILD_FLAGS $PJ_CFLAGS "$obj" \
       $PJ_LDFLAGS $PJ_LDLIBS $LIB_FUZZING_ENGINE \
       -o "$OUT/$harness"

  # standalone reproducer (no libFuzzer runtime) -> $OUT/<name>-standalone
  $CXX $FUZZ_BUILD_FLAGS $PJ_CFLAGS "$obj" "$BUILD/standalone_main.o" \
       $PJ_LDFLAGS $PJ_LDLIBS \
       -o "$OUT/$harness-standalone"

  echo "built $harness (+ standalone)"
done

echo "build.sh complete:"
ls -la "$OUT"/fuzz-sip "$OUT"/fuzz-sdp "$OUT"/fuzz-stun "$OUT"/fuzz-xml \
       "$OUT"/fuzz-sip-standalone "$OUT"/fuzz-sdp-standalone \
       "$OUT"/fuzz-stun-standalone "$OUT"/fuzz-xml-standalone 2>&1 || true
