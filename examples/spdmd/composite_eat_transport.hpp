// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace bmc::composite {

/*
 * A successful result contains only the exact signed Composite EAT main-token
 * bytes. A failed result contains no usable response and a diagnostic message.
 * Platform-specific status and required-length values are interpreted inside
 * the transport implementation, not by the generic spdmd adapter.
 */
struct TransportResult {
    std::vector<std::uint8_t> response;
    bool success = false;
    std::string errorMessage;
};

/* BMC-side transfer boundary; this interface never runs in RoT firmware. */
class CompositeEatTransport {
  public:
    virtual ~CompositeEatTransport() = default;

    /*
     * Submit one complete encoded generation request. The request view is valid
     * only for this call. On success, response must be nonempty and no larger
     * than responseCapacity. Implementations own framing, retries, timeout,
     * platform-status mapping, required-length handling, and reset recovery.
     */
    virtual TransportResult submit(std::span<const std::uint8_t> request,
                                   std::size_t responseCapacity) = 0;

    /* Advisory availability only; submit must still handle readiness races. */
    virtual bool isReady() const = 0;
};

} // namespace bmc::composite
