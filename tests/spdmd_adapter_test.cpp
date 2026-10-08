// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "composite_eat/generation_request.h"
#include "rot_platform_attester.hpp"

#include <algorithm>
#include <array>
#include "test_check.h"
#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace {

class CapturingTransport final : public bmc::composite::CompositeEatTransport {
  public:
    bmc::composite::TransportResult submit(std::span<const std::uint8_t> request,
                                           std::size_t responseCapacity) override {
        ++submitCount;
        capturedRequest.assign(request.begin(), request.end());
        capturedResponseCapacity = responseCapacity;

        bmc::composite::TransportResult result;
        if (mode == Mode::failure) {
            result.errorMessage = "synthetic transport failure";
            return result;
        }
        if (mode == Mode::oversizedSuccess) {
            result.response.resize(COMPOSITE_EAT_MAX_RESPONSE_LENGTH + 1u);
        } else if (mode == Mode::success) {
            result.response = expectedResponse;
        }
        result.success = true;
        return result;
    }

    bool isReady() const override { return ready; }

    enum class Mode { success, failure, emptySuccess, oversizedSuccess };

    bool ready = true;
    Mode mode = Mode::success;
    std::size_t submitCount = 0;
    std::size_t capturedResponseCapacity = 0;
    std::vector<std::uint8_t> capturedRequest;
    std::vector<std::uint8_t> expectedResponse{0xd8, 0x3d, 0x80};
};

spdmd::composite::CompositeEatRequest makeRequest() {
    spdmd::composite::CompositeEatRequest request;
    for (std::size_t index = 0; index < request.nonce.size(); ++index) {
        request.nonce[index] = static_cast<std::uint8_t>(index);
    }

    spdmd::composite::SubmoduleRecord record;
    record.environmentId = "env.device.0";
    std::fill(record.digest.begin(), record.digest.end(), 0xa5);
    request.deviceRecords.push_back(std::move(record));
    return request;
}

} // namespace

int main() {
    auto transport = std::make_unique<CapturingTransport>();
    CapturingTransport *captured = transport.get();
    spdmd::RotPlatformAttester attester(std::move(transport));

    spdmd::composite::CompositeEatRequest request = makeRequest();
    spdmd::composite::CompositeEatResponse response = attester.generateCompositeEat(request);
    TEST_CHECK(response.success);
    TEST_CHECK(response.compositeEat == captured->expectedResponse);
    TEST_CHECK(captured->submitCount == 1);
    TEST_CHECK(captured->capturedResponseCapacity == COMPOSITE_EAT_MAX_RESPONSE_LENGTH);

    struct composite_eat_generation_request decoded = {};
    TEST_CHECK(composite_eat_generation_request_decode(captured->capturedRequest.data(),
                                                       captured->capturedRequest.size(),
                                                       &decoded) == COMPOSITE_EAT_OK);
    TEST_CHECK(decoded.version == COMPOSITE_EAT_GENERATION_REQUEST_VERSION);
    TEST_CHECK(decoded.nonce_length == request.nonce.size());
    TEST_CHECK(decoded.record_count == 1);
    TEST_CHECK(decoded.records[0].environment_length ==
               request.deviceRecords[0].environmentId.size());
    TEST_CHECK(std::equal(decoded.records[0].digest,
                          decoded.records[0].digest + COMPOSITE_EAT_SHA384_LENGTH,
                          request.deviceRecords[0].digest.begin()));

    request.deviceRecords.clear();
    response = attester.generateCompositeEat(request);
    TEST_CHECK(!response.success);
    TEST_CHECK(!response.errorMsg.empty());
    TEST_CHECK(captured->submitCount == 1);
    request = makeRequest();

    request.platformCorimLocator = "https://example.invalid/platform-corim";
    response = attester.generateCompositeEat(request);
    TEST_CHECK(!response.success);
    TEST_CHECK(!response.errorMsg.empty());
    TEST_CHECK(captured->submitCount == 1);

    request.platformCorimLocator.reset();
    request.deviceRecords[0].hashAlgId = 1;
    response = attester.generateCompositeEat(request);
    TEST_CHECK(!response.success);
    TEST_CHECK(!response.errorMsg.empty());
    TEST_CHECK(captured->submitCount == 1);

    request.deviceRecords[0].hashAlgId = COMPOSITE_EAT_COSE_ALGORITHM_SHA384;
    captured->mode = CapturingTransport::Mode::failure;
    response = attester.generateCompositeEat(request);
    TEST_CHECK(!response.success);
    TEST_CHECK(response.errorMsg == "synthetic transport failure");
    TEST_CHECK(captured->submitCount == 2);

    captured->mode = CapturingTransport::Mode::emptySuccess;
    response = attester.generateCompositeEat(request);
    TEST_CHECK(!response.success);
    TEST_CHECK(!response.errorMsg.empty());
    TEST_CHECK(captured->submitCount == 3);

    captured->mode = CapturingTransport::Mode::oversizedSuccess;
    response = attester.generateCompositeEat(request);
    TEST_CHECK(!response.success);
    TEST_CHECK(!response.errorMsg.empty());
    TEST_CHECK(captured->submitCount == 4);

    captured->ready = false;
    TEST_CHECK(attester.getStatus() == spdmd::PlatformAttesterStatus::Unavailable);
    return 0;
}
