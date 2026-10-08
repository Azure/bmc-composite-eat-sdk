// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "rot_platform_attester.hpp"

#include "composite_eat/generation_request.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace spdmd {
namespace {

bool mapRequest(const composite::CompositeEatRequest &source,
                struct composite_eat_generation_request &destination, std::string &errorMessage) {
    if (source.platformCorimLocator) {
        errorMessage =
            "Composite EAT generation request version 1 does not support a Platform CoRIM locator";
        return false;
    }
    if (source.deviceRecords.size() > COMPOSITE_EAT_MAX_DEVICE_RECORDS) {
        errorMessage = "Composite EAT generation request exceeds the device record limit";
        return false;
    }

    destination = {};
    destination.version = COMPOSITE_EAT_GENERATION_REQUEST_VERSION;
    destination.nonce_length = source.nonce.size();
    std::copy(source.nonce.begin(), source.nonce.end(), destination.nonce);
    destination.record_count = source.deviceRecords.size();

    for (std::size_t index = 0; index < source.deviceRecords.size(); ++index) {
        const auto &sourceRecord = source.deviceRecords[index];
        auto &destinationRecord = destination.records[index];

        if (sourceRecord.hashAlgId != COMPOSITE_EAT_COSE_ALGORITHM_SHA384) {
            errorMessage =
                "Composite EAT generation request version 1 requires COSE SHA-384 digests";
            return false;
        }
        if (sourceRecord.environmentId.size() > sizeof(destinationRecord.environment)) {
            errorMessage = "Composite EAT generation request environment identifier is too long";
            return false;
        }

        destinationRecord.environment_length = sourceRecord.environmentId.size();
        std::memcpy(destinationRecord.environment, sourceRecord.environmentId.data(),
                    destinationRecord.environment_length);
        std::copy(sourceRecord.digest.begin(), sourceRecord.digest.end(), destinationRecord.digest);
    }

    if (composite_eat_validate_generation_request(&destination) != COMPOSITE_EAT_OK) {
        errorMessage = "Composite EAT generation request contains invalid or duplicate fields";
        return false;
    }
    return true;
}

bool encodeRequest(const composite::CompositeEatRequest &source, std::vector<std::uint8_t> &encoded,
                   std::string &errorMessage) {
    struct composite_eat_generation_request request = {};
    std::size_t requiredLength = 0;

    if (!mapRequest(source, request, errorMessage)) {
        return false;
    }

    enum composite_eat_status status =
        composite_eat_generation_request_encode(&request, nullptr, 0, &requiredLength);
    if (status != COMPOSITE_EAT_BUFFER_TOO_SMALL) {
        errorMessage = "Failed to calculate encoded Composite EAT generation request length";
        return false;
    }

    encoded.resize(requiredLength);
    status = composite_eat_generation_request_encode(&request, encoded.data(), encoded.size(),
                                                     &requiredLength);
    if (status != COMPOSITE_EAT_OK) {
        encoded.clear();
        errorMessage = "Failed to encode Composite EAT generation request";
        return false;
    }
    return true;
}

} // namespace

RotPlatformAttester::RotPlatformAttester(
    std::unique_ptr<bmc::composite::CompositeEatTransport> transport)
    : transport(std::move(transport)) {}

composite::CompositeEatResponse
RotPlatformAttester::generateCompositeEat(const composite::CompositeEatRequest &request) {
    composite::CompositeEatResponse response;
    if (getStatus() != PlatformAttesterStatus::Ready) {
        response.errorMsg = "RoT transport is unavailable";
        return response;
    }

    std::vector<std::uint8_t> encoded;
    if (!encodeRequest(request, encoded, response.errorMsg)) {
        return response;
    }

    bmc::composite::TransportResult transportResult =
        transport->submit(encoded, COMPOSITE_EAT_MAX_RESPONSE_LENGTH);
    if (!transportResult.success) {
        response.errorMsg = transportResult.errorMessage.empty()
                                ? "RoT transport failed"
                                : std::move(transportResult.errorMessage);
        return response;
    }
    if (transportResult.response.empty() ||
        transportResult.response.size() > COMPOSITE_EAT_MAX_RESPONSE_LENGTH) {
        response.errorMsg = "RoT returned an invalid response length";
        return response;
    }

    response.compositeEat = std::move(transportResult.response);
    response.success = true;
    return response;
}

PlatformAttesterStatus RotPlatformAttester::getStatus() const {
    return transport && transport->isReady() ? PlatformAttesterStatus::Ready
                                             : PlatformAttesterStatus::Unavailable;
}

} // namespace spdmd
