// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "composite_eat_transport.hpp"
#include "platform_attester.hpp"

#include <memory>

namespace spdmd {

/*
 * Reference adapter for the PlatformAttester contract in NVIDIA/spdm PR #2 at
 * commit 5627b88. It maps CompositeEatRequest to the SDK generation-request
 * schema and delegates only byte transfer to CompositeEatTransport. Returned
 * token bytes are bounded but deliberately not parsed or rewritten.
 */
class RotPlatformAttester final : public PlatformAttester {
  public:
    /* A NULL transport is permitted and reports Unavailable. */
    explicit RotPlatformAttester(std::unique_ptr<bmc::composite::CompositeEatTransport> transport);

    composite::CompositeEatResponse
    generateCompositeEat(const composite::CompositeEatRequest &request) override;
    PlatformAttesterStatus getStatus() const override;

  private:
    std::unique_ptr<bmc::composite::CompositeEatTransport> transport;
};

} // namespace spdmd
