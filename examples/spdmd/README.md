# spdmd Examples

These C++ examples run inside the BMC SPDM daemon boundary and target the
`PlatformAttester` contract in
[NVIDIA/spdm PR #2](https://github.com/NVIDIA/spdm/pull/2) at commit `5627b88`.

- `rot_platform_attester.*` maps `CompositeEatRequest` to the SDK Composite EAT
  generation request, invokes the transport, and returns the signed main token
  unchanged.
- `composite_eat_transport.hpp` is the byte-transfer boundary implemented by a
  platform integration.
- `platform_transport_skeleton.cpp` marks the platform-owned command, framing,
  timeout, retry, fragmentation, and reset implementation point.

To compile these examples against an spdmd checkout:

```bash
cmake -S . -B build -GNinja \
  -DBMC_COMPOSITE_EAT_BUILD_EXAMPLES=ON \
  -DBMC_COMPOSITE_EAT_SPDMD_SOURCE_DIR=/path/to/spdm/spdmd
cmake --build build
```

The adapter is reference code for a proposed upstream follow-up. It is not part
of [NVIDIA/spdm PR #2](https://github.com/NVIDIA/spdm/pull/2) at commit
`5627b88`. Keep platform transport details out of the generic adapter.
