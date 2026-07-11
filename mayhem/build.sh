#!/usr/bin/env bash
#
# wt/mayhem/build.sh — build Emweb's Wt (C++ web toolkit) with its 7 OSS-Fuzz targets
# as sanitized libFuzzer targets (+ standalone reproducers), AND Wt's own KAT oracle
# (mayhem/test.sh compiles/runs its own small program; no library test build needed here).
#
# Wt is a large C++ toolkit with many optional features (SSL, Dbo, etc.). The fuzz
# targets exercise key parsers: JSON, XML, CSS, URIs, HTTP, CGI, and expression eval.
#
# ROOT CAUSE of the original link failure ("undefined reference to typeinfo for
# Wt::WServer"): Wt::WServer's key function (`WServer::~WServer()`, the class's first
# out-of-line virtual) is defined ONLY in the connector-specific WServer.C (src/http,
# src/fcgi, src/isapi) — never in the core src/Wt/WServer.C. Per the Itanium C++ ABI,
# the vtable+typeinfo for a class are emitted only alongside its key function's
# definition. So WServer's typeinfo/vtable live ONLY in libwthttp.a, yet code that IS
# in the core libwt.a (WLogger.C, WString.C, WInteractWidget.C, http/Client.C — all of
# which call WServer::instance()/reference the type) needs that typeinfo at link time.
# Wt's own upstream fuzz/CMakeLists.txt only links libwthttp into fuzz-http — the other
# 6 targets link libwt ALONE and can never satisfy that reference (this reproduces
# under plain `cmake --build`; OSS-Fuzz's build.sh masks it with `make --ignore-errors`,
# which likely means upstream OSS-Fuzz silently ships only fuzz-http). FIX: link every
# harness against `libwt.a libwthttp.a libwt.a` (wt repeated on both sides of wthttp,
# the same trick CMake already uses for fuzz-http) — verified working for all 7 targets.
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN). We compile the Wt library ITSELF with $SANITIZER_FLAGS so the
# parsed/evaluated code (not just the harness) is instrumented.

set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

BUILD="$SRC/mayhem-build"
mkdir -p "$BUILD"

# ── 1) Configure and build the Wt core + connector libraries WITH sanitizers ────────
# BUILD_FUZZ is OFF here — Wt's own fuzz/CMakeLists.txt only links libwthttp into the
# fuzz-http target (see ROOT CAUSE above), so letting CMake drive fuzz-target linking
# fails for 6 of 7 targets. Instead we build just the libraries via CMake (reliable) and
# link every harness ourselves in step 2, in the one order that actually resolves
# Wt::WServer's typeinfo for every target: libwt.a, libwthttp.a, libwt.a again.
cmake -B "$BUILD" -S "$SRC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DSHARED_LIBS=OFF \
  -DBUILD_EXAMPLES=OFF \
  -DBUILD_FUZZ=OFF \
  -DENABLE_PANGO=OFF \
  -DENABLE_HARU=OFF \
  -DENABLE_LIBWTTEST=OFF \
  -DENABLE_LIBWTDBO=ON \
  -DENABLE_OPENGL=OFF \
  -DENABLE_UNWIND=OFF \
  -DBoost_USE_STATIC_LIBS=ON

cmake --build "$BUILD" -j "$MAYHEM_JOBS" --target wt --target wthttp

WT_LIB="$BUILD/src/libwt.a"
WTHTTP_LIB="$BUILD/src/http/libwthttp.a"
[ -f "$WT_LIB" ]     || { echo "✗ libwt.a not built" >&2; exit 1; }
[ -f "$WTHTTP_LIB" ] || { echo "✗ libwthttp.a not built" >&2; exit 1; }

# ── 2) Manually compile+link each harness (libFuzzer target + standalone reproducer) ─
# CXX_DEFINES/flags below mirror exactly what CMake generates for these TUs (captured
# from fuzz/CMakeFiles/*/flags.make); -DHTTP_WITH_SSL/-DWTHTTP_WITH_ZLIB only apply to
# fuzz-http.C, which reaches into libwthttp's internal headers whose layout depends on
# them (see fuzz/CMakeLists.txt's own comment on this).
HARNESSES=(fuzz-cgi fuzz-css fuzz-eval fuzz-http fuzz-json fuzz-uri fuzz-xml)
HARNESS_DIR="$SRC/mayhem/harnesses"

COMMON_DEFS="-DBOOST_ATOMIC_NO_LIB -DBOOST_FILESYSTEM_NO_LIB -DBOOST_SPIRIT_THREADSAFE -DBOOST_THREAD_NO_LIB -DWT_WITH_OLD_INTERNALPATH_API -D_REENTRANT"
INCLUDES="-I$BUILD -I$SRC/src"
STD_FLAG="-std=c++14"
BOOSTDIR="/usr/lib/x86_64-linux-gnu"
SYS_LIBS=(-lrt "$BOOSTDIR/libboost_thread.a" "$BOOSTDIR/libboost_filesystem.a" "$BOOSTDIR/libboost_atomic.a" "$BOOSTDIR/libz.so" "$BOOSTDIR/libssl.so" "$BOOSTDIR/libcrypto.so" "$BOOSTDIR/libboost_program_options.a" -lpthread -ldl)

# Standalone main must be compiled as C (clang++ would mangle the harness's
# extern "C" LLVMFuzzerTestOneInput reference otherwise).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"

for harness in "${HARNESSES[@]}"; do
  harness_src="$HARNESS_DIR/$harness.C"
  extra_defs=""
  [ "$harness" = "fuzz-http" ] && extra_defs="-DHTTP_WITH_SSL -DWTHTTP_WITH_ZLIB"

  echo "── building $harness (libFuzzer) ──"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $STD_FLAG $COMMON_DEFS $extra_defs $INCLUDES \
      "$harness_src" \
      "$WT_LIB" "$WTHTTP_LIB" $LIB_FUZZING_ENGINE "$WT_LIB" \
      "${SYS_LIBS[@]}" \
      -o "/mayhem/$harness"

  echo "── building $harness (standalone) ──"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $STD_FLAG $COMMON_DEFS $extra_defs $INCLUDES \
      "$harness_src" "$BUILD/standalone_main.o" \
      "$WT_LIB" "$WTHTTP_LIB" "$WT_LIB" \
      "${SYS_LIBS[@]}" \
      -o "/mayhem/$harness-standalone"

  echo "✓ built $harness (+ standalone)"
done

echo "build.sh complete:"
ls -lh /mayhem/fuzz-* 2>&1 | grep -v "^d" || echo "NO FUZZ TARGETS FOUND"
