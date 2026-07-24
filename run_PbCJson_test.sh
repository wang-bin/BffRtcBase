#!/usr/bin/env bash
# Host build & run for PbCJson_test (macOS / Linux).
set -euo pipefail
cd "$(dirname "$0")"
OUT="${TMPDIR:-/tmp}/PbCJson_test_build"
mkdir -p "$OUT"

cc -c protobuf-c/protobuf-c.c -I. -o "$OUT/protobuf-c.o"
cc -c rtc.pb-c.c -I. -o "$OUT/rtc.pb-c.o"
c++ -std=c++20 -DJSON_NOEXCEPTION -c PbCJson.cpp -I. -o "$OUT/PbCJson.o"
c++ -std=c++20 -DJSON_NOEXCEPTION -c PbCJson_test.cpp -I. -o "$OUT/PbCJson_test.o"
c++ "$OUT/PbCJson_test.o" "$OUT/PbCJson.o" "$OUT/rtc.pb-c.o" "$OUT/protobuf-c.o" -o "$OUT/PbCJson_test"
"$OUT/PbCJson_test"
