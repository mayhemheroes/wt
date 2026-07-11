#!/usr/bin/env bash
#
# wt/mayhem/test.sh — Wt functional test oracle (KAT — known-answer tests).
#
# Compiles a small standalone program (against the SAME sanitized libwt.a/libwthttp.a
# build.sh already produced under $SRC/mayhem-build) that feeds FIXED inputs to three of
# Wt's real parsers (JSON, URI, XML/rapidxml — the exact parsers fuzz-json/fuzz-uri/
# fuzz-xml exercise) and prints the COMPUTED values it extracts. test.sh then greps the
# captured stdout for the EXACT expected `RESULT k=v` lines.
#
# Anti-reward-hacking (SPEC §6.3): we deliberately do NOT trust the KAT program's own
# process exit code — verify-repo's sabotage check LD_PRELOADs a shim that _exit(0)s any
# non-system binary before main() runs, which would make a naive "rc==0 => pass" oracle
# lie. Instead every pass/fail below is decided by grepping raw captured stdout for the
# literal computed-value markers: under sabotage stdout is EMPTY (the process never gets
# to print), so every marker is "not found" and every check fails.

set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# libwt.a/libwthttp.a were built WITH $SANITIZER_FLAGS (the base image's ENV — persists
# into this RUN/docker-run step). $DEBUG_FLAGS is build.sh-local (not an image ENV), so
# default it the same way here for a consistent recompile.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CXX:=clang++}"

cd "$SRC"
BUILD="${SRC}/mayhem-build"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

WT_LIB="$BUILD/src/libwt.a"
WTHTTP_LIB="$BUILD/src/http/libwthttp.a"
if [ ! -f "$WT_LIB" ] || [ ! -f "$WTHTTP_LIB" ]; then
  echo "libwt.a/libwthttp.a missing — build.sh must run first" >&2
  emit_ctrf "wt-kat" 0 1
  exit 1
fi

mkdir -p "$BUILD"
cat > "$BUILD/wt-kat-test.cpp" << 'EOT'
// KAT test: feeds fixed inputs to Wt's JSON, URI and XML (rapidxml) parsers — the same
// parsers fuzz-json / fuzz-uri / fuzz-xml exercise — and prints the values it computed.
#include <iostream>
#include <string>

#include <Wt/Json/Parser.h>
#include <Wt/Json/Object.h>
#include <Wt/Json/Array.h>
#include <Wt/Http/Client.h>
#include "thirdparty/rapidxml/rapidxml.hpp"

int main() {
  // --- JSON object: known keys/values ---
  try {
    Wt::Json::Object obj;
    Wt::Json::parse(R"({"key": "value", "num": 42})", obj);
    std::cout << "RESULT json_key=" << obj.get("key").toString().orIfNull("<none>") << "\n";
    std::cout << "RESULT json_num=" << obj.get("num").toNumber().orIfNull(-1) << "\n";
  } catch (const std::exception &e) {
    std::cout << "RESULT json_key=<exception>\nRESULT json_num=<exception>\n";
  }

  // --- JSON array: known element count + values ---
  try {
    Wt::Json::Value val;
    Wt::Json::parse("[10, 20, 30]", val);
    const Wt::Json::Array &arr = val;
    std::cout << "RESULT json_arr_size=" << arr.size() << "\n";
    std::cout << "RESULT json_arr_elem1=" << arr[1].toNumber().orIfNull(-1) << "\n";
  } catch (const std::exception &e) {
    std::cout << "RESULT json_arr_size=<exception>\nRESULT json_arr_elem1=<exception>\n";
  }

  // --- URI parsing: known protocol/host/port/path ---
  {
    Wt::Http::Client::URL url;
    bool ok = Wt::Http::Client::parseUrl("http://example.com:8080/some/path", url);
    if (ok) {
      std::cout << "RESULT uri_protocol=" << url.protocol << "\n";
      std::cout << "RESULT uri_host=" << url.host << "\n";
      std::cout << "RESULT uri_port=" << url.port << "\n";
      std::cout << "RESULT uri_path=" << url.path << "\n";
    } else {
      std::cout << "RESULT uri_protocol=<parse-failed>\n";
    }
  }

  // --- XML (rapidxml, what fuzz-xml.C itself parses): known root/child text ---
  try {
    std::string xml = "<root><child>hello</child></root>";
    std::vector<char> text(xml.begin(), xml.end());
    text.push_back('\0');
    Wt::rapidxml::xml_document<> doc;
    doc.parse<0>(&text[0]);
    Wt::rapidxml::xml_node<> *root = doc.first_node();
    if (root) {
      std::cout << "RESULT xml_root=" << std::string(root->name(), root->name_size()) << "\n";
      Wt::rapidxml::xml_node<> *child = root->first_node();
      if (child) {
        std::cout << "RESULT xml_child_text=" << std::string(child->value(), child->value_size()) << "\n";
      }
    }
  } catch (...) {
    std::cout << "RESULT xml_root=<exception>\n";
  }

  return 0;
}
EOT

echo "=== Compiling KAT test ==="
BOOSTDIR="/usr/lib/x86_64-linux-gnu"
# libwt.a/libwthttp.a were built by build.sh WITH $SANITIZER_FLAGS — this KAT binary
# links those archives directly, so it must carry the same sanitizer runtime flags
# (otherwise the link fails with undefined __asan_*/__ubsan_* references).
if ! "${CXX:-clang++}" ${SANITIZER_FLAGS:-} ${DEBUG_FLAGS:-} -std=c++14 -I"$BUILD" -I"$SRC/src" \
     "$BUILD/wt-kat-test.cpp" \
     "$WT_LIB" "$WTHTTP_LIB" "$WT_LIB" \
     -lrt "$BOOSTDIR/libboost_thread.a" "$BOOSTDIR/libboost_filesystem.a" \
     "$BOOSTDIR/libboost_atomic.a" "$BOOSTDIR/libz.so" "$BOOSTDIR/libssl.so" \
     "$BOOSTDIR/libcrypto.so" "$BOOSTDIR/libboost_program_options.a" -lpthread -ldl \
     -o "$BUILD/wt-kat-test" 2> "$BUILD/wt-kat-compile.log"; then
  echo "Failed to compile KAT test:" >&2
  cat "$BUILD/wt-kat-compile.log" >&2
  emit_ctrf "wt-kat" 0 1
  exit 1
fi

echo "=== Running KAT test ==="
OUT="$("$BUILD/wt-kat-test" 2>&1 || true)"
echo "$OUT"

# Independently verify each computed value from raw captured stdout — do NOT trust the
# KAT program's own exit code (see anti-reward-hacking note above).
check() {  # check <label> <expected literal RESULT line>
  if grep -qxF "$2" <<<"$OUT"; then
    echo "✓ $1"
    return 0
  else
    echo "✗ $1 (expected: $2)"
    return 1
  fi
}

passed=0; failed=0
for pair in \
  "JSON object key|RESULT json_key=value" \
  "JSON object num|RESULT json_num=42" \
  "JSON array size|RESULT json_arr_size=3" \
  "JSON array elem[1]|RESULT json_arr_elem1=20" \
  "URI protocol|RESULT uri_protocol=http" \
  "URI host|RESULT uri_host=example.com" \
  "URI port|RESULT uri_port=8080" \
  "URI path|RESULT uri_path=/some/path" \
  "XML root name|RESULT xml_root=root" \
  "XML child text|RESULT xml_child_text=hello" \
; do
  label="${pair%%|*}"; expected="${pair#*|}"
  if check "$label" "$expected"; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
  fi
done

echo "Tests: $((passed + failed)) | Passed: $passed | Failed: $failed"
emit_ctrf "wt-kat" "$passed" "$failed"
