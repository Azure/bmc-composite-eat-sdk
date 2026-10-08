# spdmd Composite EAT Integration

## Upstream Starting Point

[NVIDIA/spdm PR #2](https://github.com/NVIDIA/spdm/pull/2) at commit `5627b88`
provides the composite collection, detached Claims-Set, digest, bundle
assembly, D-Bus, and `PlatformAttester` foundations. It is still open as of
2026-08-27. Its only concrete Lead Attester is the software mock used for
development and tests.

The SDK example targets that PR's `PlatformAttester` contract. It supplies the
generic Composite EAT generation-request adapter that the PR deliberately
leaves to a platform backend.

## Ownership Boundary

Keep composite evidence collection and Detached EAT Bundle assembly in spdmd.
Use the SDK adapter only to encode the private Composite EAT generation request
and convey the signed main token returned by the Root of Trust.

```text
spdmd CompositeEatRequest
  -> RotPlatformAttester             SDK example, spdmd side
      -> validate and map fields
      -> composite_eat_generation_request
      -> composite_eat_generation_request_encode
      -> CompositeEatTransport       platform implementation, BMC side
  -> CWT-tagged COSE_Sign1 main token
  -> spdmd Detached EAT Bundle assembly
```

The RoT-side command handler, generation-request decoder, evidence and identity
snapshots, hashing, signing, and token builder are separate C integration work.
See `examples/rot/` and the main integration guide.

## Generic Adapter

`examples/spdmd/rot_platform_attester.*` implements `PlatformAttester`. It:

1. checks backend readiness;
2. rejects the unsupported Platform CoRIM locator;
3. maps the spdmd nonce and detached submodule records into the SDK generation
  request type;
4. obtains the required encoded length and encodes schema version 1;
5. invokes `CompositeEatTransport` with the SDK response limit;
6. rejects empty or oversized successful responses; and
7. returns the exact RoT token bytes without parsing or rewriting them.

## Request Mapping

The adapter sets generation-request schema version `1`, copies the 32-byte
Verifier nonce, and maps every detached submodule record to:

- an `env.*` identifier of at most 64 bytes;
- COSE SHA-384 algorithm `-43`;
- exactly 48 digest bytes.

Reject more than 64 records, duplicate or invalid environment identifiers, and
any unsupported optional metadata. Schema version 1 does not carry a platform
endorsement locator; an adapter must reject it rather than silently omit it.

See the
[BMC-to-RoT Composite EAT generation contract](bmc-to-rot-composite-eat-generation-contract.md)
for the complete request, response, transport-status boundary, and strict
decoding rules.

Use `composite_eat_generation_request_encode` first with zero output capacity
to obtain the required length, allocate or select a bounded transport buffer,
then encode again. The result must not exceed
`COMPOSITE_EAT_MAX_GENERATION_REQUEST_LENGTH`.

## Platform Transport

A platform implementation supplies only this BMC-side byte-transfer boundary:

```cpp
struct TransportResult
{
    std::vector<std::uint8_t> response;
    bool success;
    std::string errorMessage;
};

class CompositeEatTransport
{
  public:
    virtual ~CompositeEatTransport() = default;
    virtual TransportResult submit(std::span<const std::uint8_t> request,
                                   std::size_t responseCapacity) = 0;
    virtual bool isReady() const = 0;
};
```

The transport owns command framing, fragmentation, request identifiers,
timeouts, retries, and reset recovery. It returns the exact main-token bytes and
must reject responses larger than `COMPOSITE_EAT_MAX_RESPONSE_LENGTH`.

Start from `examples/spdmd/platform_transport_skeleton.cpp`. Wire the resulting
transport into `RotPlatformAttester`, then select that backend in the platform's
spdmd factory and build configuration.

## Compile The Reference Adapter

The RoT C examples compile with `BMC_COMPOSITE_EAT_BUILD_EXAMPLES=ON`. To also
compile the spdmd C++ adapter, identify an spdmd source directory containing
`platform_attester.hpp`:

```bash
cmake -S . -B build -GNinja \
  -DBMC_COMPOSITE_EAT_BUILD_TESTS=ON \
  -DBMC_COMPOSITE_EAT_BUILD_EXAMPLES=ON \
  -DBMC_COMPOSITE_EAT_SPDMD_SOURCE_DIR=/path/to/spdm/spdmd
cmake --build build
ctest --test-dir build -R spdmd_adapter_test --output-on-failure
```

## Response Handling

The generic platform attester returns the Root of Trust response unchanged as
the Composite EAT main token. It does not parse or rewrite claims. spdmd then
places the token into slot 1 of the Detached EAT Bundle and places its previously
constructed detached Claims-Sets into slot 2.

Before producing the bundle, spdmd must ensure:

- every nonce-capable native evidence item uses the same Verifier nonce;
- every claim `266` environment/digest entry has exactly one detached
  Claims-Set with the same key;
- each digest covers deterministic encoded Claims-Set bytes directly;
- environment labels are bound to expected device identities by platform
  composition policy.

The focused `spdmd_adapter_test` decodes the bytes captured by a mock transport,
checks field mapping and response capacity, verifies exact token pass-through,
and confirms unsupported metadata is rejected before transport submission.
