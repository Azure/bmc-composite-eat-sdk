# Lightweight Composite EAT SDK for BMC integration

This private snapshot starts internal stakeholder business review of the
reference implementation. It is not a public release or an approved production
product. Business, security, and public-release decisions remain open.

A transport-independent C reference SDK for integrating a BMC attestation
collector with a platform Root of Trust that generates signed Composite EAT
main tokens.

## Scope

The SDK provides:

- strict encoding and decoding of the private Composite EAT generation
  request;
- a typed, split-phase Composite EAT token builder with caller-owned fixed
  workspace and no heap allocation;
- a bounded TCG DICE Concise Evidence helper with separate structural and
  caller-supplied policy validation;
- a fail-closed reference deployment policy for the published IETF `-00`
  profile URI and TCG DICE Concise Evidence under Content-Format 10571;
- streamed local evidence, signing input, and final token output;
- CWT and COSE_Sign1 construction;
- protected `x5t` and unprotected leaf-first `x5chain` encoding;
- RoT evidence, identity, hashing, and opaque-signing provider examples;
- a BMC-side `PlatformAttester` adapter and platform transport boundary;
- tests, synthetic vectors, and integration guidance.

The project version is **0.8** (`0.8.0` in CMake package metadata), as defined
in `composite_eat/version.h`. `BMC_COMPOSITE_EAT_API_DRAFT` marks the public
API as draft-aligned, not stable.
See the [0.8 release notes](docs/release-notes-0.8.md) for standards status,
compatibility expectations, and implementation changes.

The SDK does not provide production key management, cryptography, measurement
storage, command authorization, transport framing, or Detached EAT Bundle
assembly. The platform supplies trusted local evidence and invokes SHA-384 and
ES384 with its non-exportable RoT attestation key. The BMC collector builds the
complete detached bundle.

## Build

The baseline test build requires CMake 3.20 or later, Ninja, C99 and C++20
compilers, OpenSSL 3 development files, Python 3.9.2 or later, and the packages
listed in `requirements-test.txt`.

```bash
python3 -m pip install -r requirements-test.txt
cmake -S . -B build -GNinja \
  -DBMC_COMPOSITE_EAT_BUILD_TESTS=ON \
  -DBMC_COMPOSITE_EAT_BUILD_EXAMPLES=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

This configuration builds the C core, RoT examples, and twelve self-contained
tests. To also compile and test the reference spdmd adapter, point CMake at an
spdmd source directory containing `platform_attester.hpp`:

```bash
cmake -S . -B build -GNinja \
  -DBMC_COMPOSITE_EAT_BUILD_TESTS=ON \
  -DBMC_COMPOSITE_EAT_BUILD_EXAMPLES=ON \
  -DBMC_COMPOSITE_EAT_SPDMD_SOURCE_DIR=/path/to/spdm/spdmd
cmake --build build
ctest --test-dir build --output-on-failure
```

The reference adapter is pinned to the unmerged
[NVIDIA/spdm PR #2](https://github.com/NVIDIA/spdm/pull/2) at commit
`5627b8844ab298477ee4d0ab744d24266e7c6b28`, not a released upstream contract.
With that source path configured, the suite contains thirteen tests. Enabling the
optional TCG CDDL validation adds three more tests.

Runtime test checks remain active with `NDEBUG`, including token generation and
file-output checks. The suite tests check evaluation and intentional failure in
an assertion-disabled build. CI covers Debug, Release, and RelWithDebInfo with
both GCC and Clang; production library assertion settings are not overridden.

The pinned QCBOR subset is vendored under `third_party/qcbor`, so C and C++
builds do not require network access after tool and Python test dependencies
are installed.

Reference integration examples are separated by execution environment:

- `examples/rot/` contains C code for RoT firmware providers and the
  split-phase token-generation lifecycle;
- `examples/spdmd/` contains C++ code for the BMC-side generic
  `PlatformAttester` adapter and platform transport boundary.

RoT examples compile when `BMC_COMPOSITE_EAT_BUILD_EXAMPLES=ON`. The spdmd
adapter is built only when `BMC_COMPOSITE_EAT_SPDMD_SOURCE_DIR` is set. This
keeps the C SDK independent of spdmd while allowing the proposed follow-up
adapter to compile against its real upstream contract. The examples are
integration starting points, not production providers or transports.

Firmware projects can consume the SDK from source:

```cmake
add_subdirectory(path/to/bmc-composite-eat-sdk)
target_link_libraries(firmware PRIVATE bmc::composite_eat)
```

Exported targets are:

| Target | Purpose |
|---|---|
| `bmc::composite_eat` | Typed validation and split-phase signed main-token construction |
| `bmc::generation_request` | Private BMC-to-RoT CBOR generation-request codec; links the core transitively |
| `bmc::tcg_concise_evidence` | Bounded TCG DICE Concise Evidence serialization plus generic and reference-deployment policy validation |

Tests and examples are disabled by default, so the default build requires only
a C compiler.

An installed package can be consumed with
`find_package(bmcCompositeEat CONFIG REQUIRED)` and the same target names.

The installed-package smoke test reuses the public C++ API test and requires
a C++20 compiler. The default SDK build itself remains C-only:

```bash
cmake -S . -B build-default -GNinja \
  -DCMAKE_INSTALL_PREFIX="$PWD/build-default/install"
cmake --build build-default
cmake --install build-default
cmake -S tests/install -B build-consumer -GNinja \
  -DCMAKE_PREFIX_PATH="$PWD/build-default/install"
cmake --build build-consumer
ctest --test-dir build-consumer --output-on-failure
```

### CI Checks

The workflows configure GCC/Clang tests with the pinned spdmd and TCG inputs,
fail-fast ASan/UBSan checks, the default library/install test, and actionlint,
ShellCheck, and offline pedantic zizmor audits. A separate Clang job runs seeded
libFuzzer smoke tests. GitHub Actions are pinned to
full commits; checkout credentials are not persisted. Dependabot checks Actions
and Python dependencies weekly with a seven-day version-update cooldown.

The security workflow configures CodeQL C/C++ analysis and pull-request
dependency review. Tokens default to `contents: read`; only the CodeQL job adds
workflow-metadata read access and `security-events: write` to upload analysis.
Code scanning and dependency review must be enabled and available for the
repository, including the applicable GitHub security entitlement while private.
Local workflow linting does not establish that these hosted services have run.

### Fuzzing

Fuzz targets are opt-in and require Clang with libFuzzer, ASan, and UBSan on a
POSIX host. The default library build does not enable instrumentation or require
these tools. Use a separate build directory; do not ship its instrumented SDK
libraries. Fuzz builds do not require OpenSSL, Python, or the optional adapters.

```bash
cmake -S . -B build-fuzz -GNinja \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBMC_COMPOSITE_EAT_BUILD_FUZZERS=ON
cmake --build build-fuzz
ctest --test-dir build-fuzz --output-on-failure --no-tests=error
```

CTest generates synthetic seed corpora through `fuzz_seed_corpus`, using the SDK
request encoder, and runs 1,000 inputs per target. Properties remain active with
`NDEBUG`. The SDK and vendored QCBOR are instrumented, not just the harnesses.

| Target | Properties |
|---|---|
| `generation_request_fuzz` | Arbitrary CBOR, cleared failure output, deterministic round trips, truncated/trailing rejection |
| `evidence_fuzz` | Bounded typed evidence and policy fields, size/encoding consistency, buffered/streamed identity, capacity/callback failures |
| `token_builder_fuzz` | Up to 32 prepare/sign/finish/clear operations, invalid ordering, repeatable output, invalid reprepare, streamed-evidence and callback failures |

For a bounded local campaign, choose a corpus/artifact directory outside the
source tree and run each target with an approved budget. For example:

```bash
build-fuzz/tests/fuzz/fuzz_seed_corpus /path/to/private/corpus
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  build-fuzz/tests/fuzz/generation_request_fuzz /path/to/private/corpus/generation_request \
    -max_total_time=60 -max_len=8193 -rss_limit_mb=512 -timeout=2 \
    -seed=20260929 -print_final_stats=1 -create_missing_dirs=1 \
    -artifact_prefix=/path/to/private/artifacts/generation_request/
```

Use the corresponding corpus for each target; the initial evidence and builder
campaigns used `-max_len=512` and `-max_len=1024`, respectively. The runtime may
finish just after the requested time limit. Keep logs, corpora, and crash inputs
for reproduction; replay a failure with `TARGET /path/to/artifact`. Corpora and
artifacts are generated locally and are not published test vectors. The builder
harness uses synthetic structural inputs, not a real signing identity, and does
not validate cryptographic signatures. A clean bounded run is not a security
proof or a complete release gate.

## Integration Paths

Start with [the integration guide](docs/bmc-composite-eat-integration-guide.md).
For the BMC collector boundary, see
[the spdmd integration guide](docs/spdmd-composite-eat-integration.md).
For typed local-evidence serialization, see the
[TCG DICE Concise Evidence helper](docs/tcg-concise-evidence-helper.md).
The reference integration emits the exact published `draft-00` identifier
`https://datatracker.ietf.org/doc/draft-sun-rats-composite-eat/` and requires
`application/ce+cbor` (CoAP Content-Format 10571) for every Lead measurement.
This additional deployment constraint does not claim conformance to the
separate OCP Composite EAT profile.
The private, non-IETF BMC-to-RoT interface is defined in the
[Composite EAT generation contract](docs/bmc-to-rot-composite-eat-generation-contract.md).
The published
[Composite EAT Internet-Draft -00](https://datatracker.ietf.org/doc/html/draft-sun-rats-composite-eat-00)
defines the token and Detached EAT Bundle profile; the private Composite EAT
generation request is the input defined by that private contract. The draft is
work in progress, not an RFC or IETF endorsement. See the
[Datatracker document page](https://datatracker.ietf.org/doc/draft-sun-rats-composite-eat/)
for current status. The SDK does not redistribute a draft snapshot.

## Other Languages

C++ callers can link the C targets directly. Firmware written in another
language may implement the same typed request and split-phase builder state
machine natively, or use a carefully reviewed foreign-function wrapper. The
generation-request tests and included fixed token vector are the
interoperability reference.

The Python verifier is intended for interoperability testing. It is not a
production certificate-path validator or attestation appraisal engine.

## Status

This is a non-production reference implementation aligned with the active IETF
Composite EAT Internet-Draft and ongoing OCP Composite EAT Profile draft work.
The IETF document is an individual Internet-Draft, not an RFC or IETF-endorsed
standard. The OCP contribution remains under project review; the SDK does not
claim complete OCP Composite EAT profile conformance.

Public APIs and the private BMC-to-RoT wire contract may evolve with the draft
work before the first stable release. Changes require release notes and version
updates. Version 0.8 is source-only; it does not establish a production support
commitment or a stable API.

## Licensing

Microsoft-owned first-party material is licensed under the MIT License.
Vendored QCBOR remains BSD-3-Clause under its upstream terms. See
[license scope](LICENSING.md) and [third-party notices](THIRD_PARTY_NOTICES.md).

## Review and Support

Local GCC/Clang Debug, Release, and RelWithDebInfo runs passed all sixteen
tests with the pinned spdmd contract and all three CDDL gates enabled. Runtime
test checks remain active under `NDEBUG`. Bounded fuzzing and prior sanitizer
checks are documented in the release notes; hosted security workflows have not
yet been verified in this repository.

Open review items include license metadata completeness, reviewer disposition
of static-analysis diagnostics and lower-severity validation-host advisories,
business assessment, and public-release governance. These are not represented
as closed by this private snapshot. See [support guidance](SUPPORT.md) for
questions and [security reporting](SECURITY.md) for vulnerabilities.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the Microsoft CLA, fork-and-pull
workflow, and Code of Conduct guidance.

## Trademarks

This project may contain trademarks or logos for projects, products, or services.
Authorized use of Microsoft trademarks or logos is subject to
[Microsoft's Trademark and Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks/usage/general).
Use in modified versions must not cause confusion or imply Microsoft sponsorship.
Use of third-party trademarks or logos is subject to those third parties' policies.
