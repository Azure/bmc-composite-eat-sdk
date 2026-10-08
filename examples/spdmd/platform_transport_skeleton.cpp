// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "composite_eat_transport.hpp"

namespace bmc::composite {

class PlatformTransport final : public CompositeEatTransport {
  public:
    TransportResult submit(std::span<const std::uint8_t> request,
                           std::size_t responseCapacity) override {
        (void)request;
        (void)responseCapacity;
        TransportResult result;
        result.errorMessage = "replace with the platform command and transfer mechanism";
        return result;
    }

    bool isReady() const override { return false; }
};

} // namespace bmc::composite
