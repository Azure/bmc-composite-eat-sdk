#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

if [[ "$#" -ne 5 && "$#" -ne 6 ]]; then
    echo "usage: $0 <input> <dice-coev-root> <cddlc> <cddl> <python> [mode]" >&2
    exit 2
fi

input=$1
dice_root=$2
cddlc=$3
cddl=$4
python=$5
mode=${6:-evidence}
expected_commit=3e1b724f1154add5d5289df90ad8b2e0e9d5532a
expected_cddlc_version=0.4.5
expected_cddl_version=0.12.14
expected_cddlc_hash=e42735597f2a73582706e42c53e484884176b90152d54f0e95d230c9008667c8
expected_cddl_hash=1f377b0fd8b8b161a28b6a9683e854875c9de76f7673699be19c2aa868d094e4
expected_export_hash=9306b3dc490687e87f41c2f3b942f940ca24577e233ad6b4e3ec53120446ae6f
expected_corim_hash=2fe3bd19eaf0faf09b2217865eb01994b30794688dccb1230e70d78e23f7a6ce
# Generated 2026-09-08 with cddlc 0.4.5 and --start=concise-evidence.
expected_schema_hash=5b3f619be21a200953fadddfbd3bd91f5fb04bbba85ea54d20184e6e7a47b16e

[[ "$(git -C "$dice_root" rev-parse HEAD)" == "$expected_commit" ]]
export_hash=$(sha256sum "$dice_root/exports/coev.cddl" | cut -d' ' -f1)
corim_hash=$(sha256sum "$dice_root/imports/corim-autogen.cddl.bak" | cut -d' ' -f1)
[[ "$export_hash" == "$expected_export_hash" ]]
[[ "$corim_hash" == "$expected_corim_hash" ]]

verify_gem_tool() {
    ruby - "$@" <<'RUBY'
require "digest"
require "rubygems"

path, name, version, expected_hash = ARGV
abort "#{path} is not a RubyGems #{name} launcher" unless File.read(path).include?("activate_bin_path('#{name}'")
spec = Gem::Specification.find_by_name(name, "= #{version}")
tool = File.join(spec.full_gem_path, "bin", name)
actual_hash = Digest::SHA256.file(tool).hexdigest
abort "unexpected #{name} #{version} payload hash: #{actual_hash}" unless actual_hash == expected_hash
RUBY
}

verify_gem_tool "$cddlc" cddlc "$expected_cddlc_version" "$expected_cddlc_hash"
verify_gem_tool "$cddl" cddl "$expected_cddl_version" "$expected_cddl_hash"

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

if [[ "$mode" == "reference-token" ]]; then
    "$input" "$work_dir/token.cbor" "$work_dir/anchor.der"
    "$python" "$(dirname "$0")/extract_reference_evidence.py" \
        "$work_dir/token.cbor" "$work_dir/evidence.cbor"
elif [[ "$mode" == "evidence" ]]; then
    "$input" "$work_dir/evidence.cbor"
elif [[ "$mode" == "reference-token-file" ]]; then
    "$python" "$(dirname "$0")/extract_reference_evidence.py" \
        "$input" "$work_dir/evidence.cbor"
else
    echo "unsupported generator mode: $mode" >&2
    exit 2
fi
"$cddlc" "_${expected_cddlc_version}_" -2tcddl \
    "$dice_root/spdm-toc.cddl" \
    "$dice_root/concise-evidence.cddl" \
    "$dice_root/comid-extensions.cddl" \
    "$dice_root/imports/corim-autogen.cddl.bak" \
    --start=concise-evidence >"$work_dir/coev-map.cddl" 2>"$work_dir/cddlc.log"

schema_hash=$(sha256sum "$work_dir/coev-map.cddl" | cut -d' ' -f1)
[[ "$schema_hash" == "$expected_schema_hash" ]]
"$cddl" "_${expected_cddl_version}_" "$work_dir/coev-map.cddl" validate \
    "$work_dir/evidence.cbor" \
    >"$work_dir/cddl.out" 2>"$work_dir/cddl.err"