# Lightweight Composite EAT SDK for BMC integration

A transport-independent C SDK for integrating a BMC attestation collector with
a platform Root of Trust (RoT) that generates signed Composite EAT main tokens.

## Features

- Portable C99 implementation with caller-owned memory and no heap allocation.
- Typed BMC-to-RoT requests and bounded TCG DICE Concise Evidence handling.
- Split-phase CWT and COSE_Sign1 construction with streaming input and output.
- Platform boundaries for evidence, identity, hashing, signing, and transport.
- RoT and BMC integration examples, synthetic vectors, tests, and guidance.

Integrators supply trusted evidence, authorization, transport, platform-backed
hashing and signing operations, and the associated certificate chain. Private
keys and opaque key handles remain outside the SDK.

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

This configuration builds the C core, RoT examples, and self-contained tests.
To also compile and test the optional spdmd adapter, point CMake at an spdmd
source directory containing `platform_attester.hpp`:

```bash
cmake -S . -B build -GNinja \
  -DBMC_COMPOSITE_EAT_BUILD_TESTS=ON \
  -DBMC_COMPOSITE_EAT_BUILD_EXAMPLES=ON \
  -DBMC_COMPOSITE_EAT_SPDMD_SOURCE_DIR=/path/to/spdm/spdmd
cmake --build build
ctest --test-dir build --output-on-failure
```

The pinned QCBOR subset is vendored under `third_party/qcbor`, so C and C++
builds do not require network access after tool and Python test dependencies
are installed.

Reference integration examples are separated by execution environment:

- `examples/rot/` contains C code for RoT firmware providers and the
  split-phase token-generation lifecycle;
- `examples/spdmd/` contains C++ code for the BMC-side generic
  `PlatformAttester` adapter and platform transport boundary.

RoT examples compile when `BMC_COMPOSITE_EAT_BUILD_EXAMPLES=ON`. The spdmd
adapter is built only when `BMC_COMPOSITE_EAT_SPDMD_SOURCE_DIR` is set. The SDK
is designed to integrate with the Composite EAT flow and `PlatformAttester`
interface described in [NVIDIA/spdm PR #2](https://github.com/NVIDIA/spdm/pull/2).
The C core can be built without spdmd sources, while the optional reference
adapter requires a compatible spdmd implementation.

Firmware projects can consume the SDK from source:

```cmake
add_subdirectory(path/to/bmc-composite-eat-sdk)
target_link_libraries(firmware PRIVATE bmc::composite_eat)
```

Exported targets are:

| Target | Purpose |
|---|---|
| `bmc::composite_eat` | Typed validation and split-phase signed main-token construction |
| `bmc::generation_request` | SDK-defined BMC-to-RoT CBOR generation-request codec; links the core transitively |
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

## Fuzzing

Fuzz targets are opt-in and require Clang with libFuzzer, ASan, and UBSan on a
POSIX host. They cover generation-request decoding, evidence validation, and
token-builder state transitions.

```bash
cmake -S . -B build-fuzz -GNinja \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBMC_COMPOSITE_EAT_BUILD_FUZZERS=ON
cmake --build build-fuzz
ctest --test-dir build-fuzz --output-on-failure --no-tests=error
```

## Integration

Start with [the integration guide](docs/bmc-composite-eat-integration-guide.md).
For the BMC collector boundary, see
[the spdmd integration guide](docs/spdmd-composite-eat-integration.md).
For typed local-evidence serialization, see the
[TCG DICE Concise Evidence helper](docs/tcg-concise-evidence-helper.md).
The SDK-defined BMC-to-RoT interface is documented in the
[Composite EAT generation contract](docs/bmc-to-rot-composite-eat-generation-contract.md).

The SDK follows the ongoing
[Composite EAT Internet-Draft](https://datatracker.ietf.org/doc/draft-sun-rats-composite-eat/)
and OCP Composite EAT Profile work, which is currently under review. The SDK
will evolve alongside this standardization work.

C++ callers can link the C targets directly. Firmware written in another
language may implement the same typed request and split-phase builder state
machine natively or use a reviewed foreign-function wrapper. The included
Python verifier supports interoperability testing.

## Project Status

The project version is **0.8** (`0.8.0` in CMake package metadata).
`BMC_COMPOSITE_EAT_API_DRAFT` identifies APIs that may evolve with ongoing
standardization and integration experience. Version 0.8 is currently provided
as a non-production reference implementation.

## Support and Security

See [support guidance](SUPPORT.md) for questions and
[security reporting](SECURITY.md) for vulnerabilities.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the Microsoft CLA, fork-and-pull
workflow, and Code of Conduct guidance.

## License

Microsoft-owned material is licensed under the [MIT License](LICENSE).
Third-party components retain their upstream licenses; see
[Third-Party Notices](THIRD_PARTY_NOTICES.md).

## Trademarks

This project may contain trademarks or logos for projects, products, or services.
Authorized use of Microsoft trademarks or logos is subject to
[Microsoft's Trademark and Brand Guidelines](https://www.microsoft.com/legal/intellectualproperty/trademarks/usage/general).
Use in modified versions must not cause confusion or imply Microsoft sponsorship.
Use of third-party trademarks or logos is subject to those third parties' policies.
