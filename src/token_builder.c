// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdbool.h>
#include <limits.h>
#include <string.h>

#include "composite_eat/token_builder.h"

#define COMPOSITE_EAT_CLAIM_NONCE 10
#define COMPOSITE_EAT_CLAIM_UEID 256
#define COMPOSITE_EAT_CLAIM_PROFILE 265
#define COMPOSITE_EAT_CLAIM_SUBMODULES 266
#define COMPOSITE_EAT_CLAIM_MEASUREMENTS 273

#define COMPOSITE_EAT_COSE_HEADER_ALGORITHM 1
#define COMPOSITE_EAT_COSE_HEADER_CONTENT_TYPE 3
#define COMPOSITE_EAT_COSE_HEADER_X5CHAIN 33
#define COMPOSITE_EAT_COSE_HEADER_X5T 34

#define COMPOSITE_EAT_CONTENT_TYPE "application/eat+cwt"

#define COMPOSITE_EAT_CBOR_MAJOR_UNSIGNED 0u
#define COMPOSITE_EAT_CBOR_MAJOR_NEGATIVE 1u
#define COMPOSITE_EAT_CBOR_MAJOR_BYTES 2u
#define COMPOSITE_EAT_CBOR_MAJOR_TEXT 3u
#define COMPOSITE_EAT_CBOR_MAJOR_ARRAY 4u
#define COMPOSITE_EAT_CBOR_MAJOR_MAP 5u
#define COMPOSITE_EAT_CBOR_MAJOR_TAG 6u

#define COMPOSITE_EAT_CBOR_TAG_COSE_SIGN1 18u
#define COMPOSITE_EAT_CBOR_TAG_CWT 61u

#if COMPOSITE_EAT_MAX_DEVICE_RECORDS > (UINT8_MAX + 1u)
#error "Device record ordering index does not fit in uint8_t"
#endif

struct composite_eat_writer {
    composite_eat_write write;
    void *context;
    size_t capacity;
    size_t length;
    bool failed;
};

struct composite_eat_buffer_writer {
    uint8_t *buffer;
    size_t capacity;
    size_t offset;
};

struct composite_eat_bounded_writer {
    struct composite_eat_writer *writer;
    size_t remaining;
};

static void composite_eat_writer_add(struct composite_eat_writer *writer, const uint8_t *data,
                                     size_t length) {
    if (writer->failed || (writer->length > writer->capacity) ||
        ((writer->capacity - writer->length) < length)) {
        writer->failed = true;
        return;
    }

    if ((writer->write != NULL) && (length != 0) &&
        (writer->write(writer->context, data, length) != 0)) {
        writer->failed = true;
        return;
    }

    writer->length += length;
}

static int composite_eat_buffer_write(void *context, const uint8_t *data, size_t length) {
    struct composite_eat_buffer_writer *writer = context;

    if ((writer == NULL) || (data == NULL) || (writer->offset > writer->capacity) ||
        ((writer->capacity - writer->offset) < length)) {
        return -1;
    }

    memcpy(&writer->buffer[writer->offset], data, length);
    writer->offset += length;
    return 0;
}

static void composite_eat_add_type_value(struct composite_eat_writer *writer, uint8_t major,
                                         uint64_t value) {
    uint8_t encoded[9];
    size_t length;

    if (value < 24) {
        encoded[0] = (uint8_t)((major << 5) | value);
        length = 1;
    } else if (value <= UINT8_MAX) {
        encoded[0] = (uint8_t)((major << 5) | 24);
        encoded[1] = (uint8_t)value;
        length = 2;
    } else if (value <= UINT16_MAX) {
        encoded[0] = (uint8_t)((major << 5) | 25);
        encoded[1] = (uint8_t)(value >> 8);
        encoded[2] = (uint8_t)value;
        length = 3;
    } else if (value <= UINT32_MAX) {
        encoded[0] = (uint8_t)((major << 5) | 26);
        encoded[1] = (uint8_t)(value >> 24);
        encoded[2] = (uint8_t)(value >> 16);
        encoded[3] = (uint8_t)(value >> 8);
        encoded[4] = (uint8_t)value;
        length = 5;
    } else {
        encoded[0] = (uint8_t)((major << 5) | 27);
        encoded[1] = (uint8_t)(value >> 56);
        encoded[2] = (uint8_t)(value >> 48);
        encoded[3] = (uint8_t)(value >> 40);
        encoded[4] = (uint8_t)(value >> 32);
        encoded[5] = (uint8_t)(value >> 24);
        encoded[6] = (uint8_t)(value >> 16);
        encoded[7] = (uint8_t)(value >> 8);
        encoded[8] = (uint8_t)value;
        length = 9;
    }

    composite_eat_writer_add(writer, encoded, length);
}

static void composite_eat_add_int(struct composite_eat_writer *writer, int64_t value) {
    if (value >= 0) {
        composite_eat_add_type_value(writer, COMPOSITE_EAT_CBOR_MAJOR_UNSIGNED, (uint64_t)value);
    } else {
        composite_eat_add_type_value(writer, COMPOSITE_EAT_CBOR_MAJOR_NEGATIVE,
                                     (uint64_t)(-(value + 1)));
    }
}

static void composite_eat_add_bytes_header(struct composite_eat_writer *writer, size_t length) {
    composite_eat_add_type_value(writer, COMPOSITE_EAT_CBOR_MAJOR_BYTES, length);
}

static void composite_eat_add_bytes(struct composite_eat_writer *writer, const uint8_t *data,
                                    size_t length) {
    composite_eat_add_bytes_header(writer, length);
    composite_eat_writer_add(writer, data, length);
}

static void composite_eat_add_text(struct composite_eat_writer *writer, const uint8_t *data,
                                   size_t length) {
    composite_eat_add_type_value(writer, COMPOSITE_EAT_CBOR_MAJOR_TEXT, length);
    composite_eat_writer_add(writer, data, length);
}

static void composite_eat_open_array(struct composite_eat_writer *writer, size_t count) {
    composite_eat_add_type_value(writer, COMPOSITE_EAT_CBOR_MAJOR_ARRAY, count);
}

static void composite_eat_open_map(struct composite_eat_writer *writer, size_t count) {
    composite_eat_add_type_value(writer, COMPOSITE_EAT_CBOR_MAJOR_MAP, count);
}

static void composite_eat_add_tag(struct composite_eat_writer *writer, uint64_t tag) {
    composite_eat_add_type_value(writer, COMPOSITE_EAT_CBOR_MAJOR_TAG, tag);
}

static void composite_eat_clear_bytes(void *data, size_t length) {
    volatile uint8_t *cursor = data;

    while (length-- > 0) {
        *cursor++ = 0;
    }
}

static bool composite_eat_buffer_valid(const struct composite_eat_buffer *buffer) {
    return (buffer != NULL) && (buffer->data != NULL) && (buffer->length != 0);
}

static bool composite_eat_utf8_valid(const uint8_t *text, size_t length) {
    size_t offset = 0;

    while (offset < length) {
        uint8_t first = text[offset++];
        uint32_t codepoint;
        size_t continuation;
        size_t i;

        if (first < 0x80) {
            continue;
        }
        if ((first >= 0xc2) && (first <= 0xdf)) {
            codepoint = first & 0x1f;
            continuation = 1;
        } else if ((first >= 0xe0) && (first <= 0xef)) {
            codepoint = first & 0x0f;
            continuation = 2;
        } else if ((first >= 0xf0) && (first <= 0xf4)) {
            codepoint = first & 0x07;
            continuation = 3;
        } else {
            return false;
        }

        if ((length - offset) < continuation) {
            return false;
        }
        for (i = 0; i < continuation; ++i) {
            uint8_t next = text[offset++];

            if ((next & 0xc0) != 0x80) {
                return false;
            }
            codepoint = (codepoint << 6) | (next & 0x3f);
        }

        if (((continuation == 1) && (codepoint < 0x80)) ||
            ((continuation == 2) && (codepoint < 0x800)) ||
            ((continuation == 3) && (codepoint < 0x10000)) ||
            ((codepoint >= 0xd800) && (codepoint <= 0xdfff)) || (codepoint > 0x10ffff)) {
            return false;
        }
    }

    return true;
}

static bool composite_eat_evidence_valid(const struct composite_eat_evidence_snapshot *evidence) {
    size_t i;

    if ((evidence == NULL) || !composite_eat_buffer_valid(&evidence->ueid) ||
        (evidence->ueid.length < 7) || (evidence->ueid.length > 33) ||
        !composite_eat_buffer_valid(&evidence->profile) ||
        (evidence->profile.length > COMPOSITE_EAT_MAX_PROFILE_LENGTH) ||
        (memchr(evidence->profile.data, '\0', evidence->profile.length) != NULL) ||
        !composite_eat_utf8_valid(evidence->profile.data, evidence->profile.length) ||
        (evidence->local_evidence == NULL) || (evidence->local_evidence_count == 0) ||
        (evidence->local_evidence_count > COMPOSITE_EAT_MAX_LOCAL_EVIDENCE)) {
        return false;
    }

    for (i = 0; i < evidence->local_evidence_count; ++i) {
        const struct composite_eat_local_evidence *local = &evidence->local_evidence[i];
        bool has_buffer_fields = (local->encoded.data != NULL) || (local->encoded.length != 0);
        bool has_stream_fields = (local->write != NULL) || (local->encoded_length != 0);
        bool buffered = composite_eat_buffer_valid(&local->encoded);
        bool streamed = (local->write != NULL) && (local->encoded_length != 0);
        size_t length = buffered ? local->encoded.length : local->encoded_length;

        if ((has_buffer_fields && !buffered) || (has_stream_fields && !streamed) ||
            (buffered == streamed) || (length > COMPOSITE_EAT_MAX_LOCAL_EVIDENCE_LENGTH)) {
            return false;
        }
    }

    return true;
}

static int composite_eat_writer_local_evidence_write(void *context, const uint8_t *data,
                                                     size_t length) {
    struct composite_eat_bounded_writer *bounded = context;

    if ((bounded == NULL) || (bounded->writer == NULL) || ((data == NULL) && (length != 0)) ||
        (length > bounded->remaining)) {
        return -1;
    }
    composite_eat_writer_add(bounded->writer, data, length);
    if (bounded->writer->failed) {
        return -1;
    }
    bounded->remaining -= length;
    return 0;
}

static void composite_eat_add_local_evidence(struct composite_eat_writer *writer,
                                             const struct composite_eat_local_evidence *evidence) {
    size_t length =
        (evidence->encoded.data != NULL) ? evidence->encoded.length : evidence->encoded_length;
    size_t offset;

    composite_eat_add_bytes_header(writer, length);
    if (evidence->encoded.data != NULL) {
        composite_eat_writer_add(writer, evidence->encoded.data, length);
    } else if (writer->write == NULL) {
        composite_eat_writer_add(writer, NULL, length);
    } else {
        struct composite_eat_bounded_writer bounded = {writer, length};

        offset = writer->length;
        if ((evidence->write(evidence->write_context, composite_eat_writer_local_evidence_write,
                             &bounded) != 0) ||
            writer->failed || (bounded.remaining != 0) || ((writer->length - offset) != length)) {
            writer->failed = true;
        }
    }
}

static bool
composite_eat_identity_valid(const struct composite_eat_attestation_identity *identity) {
    size_t i;

    if ((identity == NULL) || (identity->certificates == NULL) ||
        (identity->certificate_count == 0) ||
        (identity->certificate_count > COMPOSITE_EAT_MAX_CERTIFICATES)) {
        return false;
    }

    for (i = 0; i < identity->certificate_count; ++i) {
        if ((identity->certificates[i].data == NULL) || (identity->certificates[i].length == 0) ||
            (identity->certificates[i].length > COMPOSITE_EAT_MAX_CERTIFICATE_LENGTH)) {
            return false;
        }
    }

    return true;
}

enum composite_eat_status
composite_eat_validate_evidence_snapshot(const struct composite_eat_evidence_snapshot *evidence) {
    return composite_eat_evidence_valid(evidence) ? COMPOSITE_EAT_OK : COMPOSITE_EAT_BAD_ARGUMENT;
}

enum composite_eat_status composite_eat_validate_attestation_identity(
    const struct composite_eat_attestation_identity *identity) {
    return composite_eat_identity_valid(identity) ? COMPOSITE_EAT_OK : COMPOSITE_EAT_BAD_ARGUMENT;
}

static int composite_eat_compare_records(const struct composite_eat_device_record *left,
                                         const struct composite_eat_device_record *right) {
    if (left->environment_length != right->environment_length) {
        return (left->environment_length < right->environment_length) ? -1 : 1;
    }

    return memcmp(left->environment, right->environment, left->environment_length);
}

static void composite_eat_add_payload(struct composite_eat_writer *writer,
                                      const struct composite_eat_generation_request *request,
                                      const struct composite_eat_evidence_snapshot *evidence) {
    uint8_t order[COMPOSITE_EAT_MAX_DEVICE_RECORDS];
    size_t i;
    size_t position;

    for (i = 0; i < request->record_count; ++i) {
        order[i] = (uint8_t)i;
        for (position = i; position > 0; --position) {
            const struct composite_eat_device_record *left = &request->records[order[position - 1]];
            const struct composite_eat_device_record *right = &request->records[order[position]];

            if (composite_eat_compare_records(left, right) <= 0) {
                break;
            }
            order[position] = order[position - 1];
            order[position - 1] = (uint8_t)i;
        }
    }

    composite_eat_open_map(writer, 5);
    composite_eat_add_int(writer, COMPOSITE_EAT_CLAIM_NONCE);
    composite_eat_add_bytes(writer, request->nonce, request->nonce_length);
    composite_eat_add_int(writer, COMPOSITE_EAT_CLAIM_UEID);
    composite_eat_add_bytes(writer, evidence->ueid.data, evidence->ueid.length);
    composite_eat_add_int(writer, COMPOSITE_EAT_CLAIM_PROFILE);
    composite_eat_add_text(writer, evidence->profile.data, evidence->profile.length);
    composite_eat_add_int(writer, COMPOSITE_EAT_CLAIM_SUBMODULES);
    composite_eat_open_map(writer, request->record_count);
    for (i = 0; i < request->record_count; ++i) {
        const struct composite_eat_device_record *record = &request->records[order[i]];

        composite_eat_add_text(writer, record->environment, record->environment_length);
        composite_eat_open_array(writer, 2);
        composite_eat_add_int(writer, COMPOSITE_EAT_COSE_ALGORITHM_SHA384);
        composite_eat_add_bytes(writer, record->digest, sizeof(record->digest));
    }
    composite_eat_add_int(writer, COMPOSITE_EAT_CLAIM_MEASUREMENTS);
    composite_eat_open_array(writer, evidence->local_evidence_count);
    for (i = 0; i < evidence->local_evidence_count; ++i) {
        composite_eat_open_array(writer, 2);
        composite_eat_add_int(writer, evidence->local_evidence[i].content_format);
        composite_eat_add_local_evidence(writer, &evidence->local_evidence[i]);
    }
}

static void composite_eat_add_protected_headers(
    struct composite_eat_writer *writer,
    const uint8_t leaf_thumbprint_sha384[COMPOSITE_EAT_SHA384_LENGTH]) {
    composite_eat_open_map(writer, 3);
    composite_eat_add_int(writer, COMPOSITE_EAT_COSE_HEADER_ALGORITHM);
    composite_eat_add_int(writer, COMPOSITE_EAT_COSE_ALGORITHM_ES384);
    composite_eat_add_int(writer, COMPOSITE_EAT_COSE_HEADER_CONTENT_TYPE);
    composite_eat_add_text(writer, (const uint8_t *)COMPOSITE_EAT_CONTENT_TYPE,
                           strlen(COMPOSITE_EAT_CONTENT_TYPE));
    composite_eat_add_int(writer, COMPOSITE_EAT_COSE_HEADER_X5T);
    composite_eat_open_array(writer, 2);
    composite_eat_add_int(writer, COMPOSITE_EAT_COSE_ALGORITHM_SHA384);
    composite_eat_add_bytes(writer, leaf_thumbprint_sha384, COMPOSITE_EAT_SHA384_LENGTH);
}

static void composite_eat_add_token(struct composite_eat_writer *writer,
                                    const struct composite_eat_prepared *prepared,
                                    const uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH]) {
    size_t i;

    composite_eat_add_tag(writer, COMPOSITE_EAT_CBOR_TAG_CWT);
    composite_eat_add_tag(writer, COMPOSITE_EAT_CBOR_TAG_COSE_SIGN1);
    composite_eat_open_array(writer, 4);
    composite_eat_add_bytes(writer, prepared->workspace->protected_headers,
                            prepared->workspace->protected_headers_length);
    composite_eat_open_map(writer, 1);
    composite_eat_add_int(writer, COMPOSITE_EAT_COSE_HEADER_X5CHAIN);
    if (prepared->identity->certificate_count == 1) {
        composite_eat_add_bytes(writer, prepared->identity->certificates[0].data,
                                prepared->identity->certificates[0].length);
    } else {
        composite_eat_open_array(writer, prepared->identity->certificate_count);
        for (i = 0; i < prepared->identity->certificate_count; ++i) {
            composite_eat_add_bytes(writer, prepared->identity->certificates[i].data,
                                    prepared->identity->certificates[i].length);
        }
    }
    composite_eat_add_bytes_header(writer, prepared->payload_length);
    composite_eat_add_payload(writer, prepared->request, prepared->evidence);
    composite_eat_add_bytes(writer, signature, COMPOSITE_EAT_ES384_SIGNATURE_LENGTH);
}

enum composite_eat_status
composite_eat_prepare(const struct composite_eat_generation_request *request,
                      const struct composite_eat_evidence_snapshot *evidence,
                      const struct composite_eat_attestation_identity *identity,
                      const uint8_t leaf_thumbprint_sha384[COMPOSITE_EAT_SHA384_LENGTH],
                      struct composite_eat_workspace *workspace,
                      struct composite_eat_prepared *prepared) {
    struct composite_eat_buffer_writer protected_output;
    struct composite_eat_writer writer;
    static const uint8_t empty_signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH];

    if ((workspace == NULL) || (prepared == NULL)) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }

    composite_eat_clear(workspace, prepared);
    if ((composite_eat_validate_generation_request(request) != COMPOSITE_EAT_OK) ||
        !composite_eat_evidence_valid(evidence) || !composite_eat_identity_valid(identity) ||
        (leaf_thumbprint_sha384 == NULL)) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }

    protected_output.buffer = workspace->protected_headers;
    protected_output.capacity = sizeof(workspace->protected_headers);
    protected_output.offset = 0;
    writer = (struct composite_eat_writer){
        .write = composite_eat_buffer_write,
        .context = &protected_output,
        .capacity = sizeof(workspace->protected_headers),
    };
    composite_eat_add_protected_headers(&writer, leaf_thumbprint_sha384);
    if (writer.failed) {
        composite_eat_clear(workspace, prepared);
        return COMPOSITE_EAT_ENCODING_ERROR;
    }
    workspace->protected_headers_length = writer.length;

    memset(&writer, 0, sizeof(writer));
    writer.capacity = COMPOSITE_EAT_PAYLOAD_MAX;
    composite_eat_add_payload(&writer, request, evidence);
    if (writer.failed || (writer.length > COMPOSITE_EAT_PAYLOAD_MAX)) {
        composite_eat_clear(workspace, prepared);
        return COMPOSITE_EAT_ENCODING_ERROR;
    }

    prepared->workspace = workspace;
    prepared->request = request;
    prepared->evidence = evidence;
    prepared->identity = identity;
    prepared->payload_length = writer.length;
    prepared->ready = true;

    memset(&writer, 0, sizeof(writer));
    writer.capacity = COMPOSITE_EAT_MAX_RESPONSE_LENGTH;
    composite_eat_add_token(&writer, prepared, empty_signature);
    if (writer.failed || (writer.length > COMPOSITE_EAT_MAX_RESPONSE_LENGTH)) {
        composite_eat_clear(workspace, prepared);
        return COMPOSITE_EAT_ENCODING_ERROR;
    }
    prepared->response_length = writer.length;
    return COMPOSITE_EAT_OK;
}

enum composite_eat_status composite_eat_write_signing_input(struct composite_eat_prepared *prepared,
                                                            composite_eat_write write,
                                                            void *context) {
    struct composite_eat_writer writer = {
        .write = write,
        .context = context,
        .capacity = SIZE_MAX,
    };
    static const uint8_t signature_context[] = "Signature1";

    if ((prepared == NULL) || (write == NULL)) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }
    prepared->signing_complete = false;
    if (!prepared->ready || (prepared->workspace == NULL) || (prepared->request == NULL) ||
        (prepared->evidence == NULL)) {
        return COMPOSITE_EAT_STATE_ERROR;
    }

    composite_eat_open_array(&writer, 4);
    composite_eat_add_text(&writer, signature_context, sizeof(signature_context) - 1);
    composite_eat_add_bytes(&writer, prepared->workspace->protected_headers,
                            prepared->workspace->protected_headers_length);
    composite_eat_add_bytes(&writer, NULL, 0);
    composite_eat_add_bytes_header(&writer, prepared->payload_length);
    composite_eat_add_payload(&writer, prepared->request, prepared->evidence);
    if (writer.failed) {
        return COMPOSITE_EAT_WRITE_ERROR;
    }

    prepared->signing_complete = true;
    return COMPOSITE_EAT_OK;
}

enum composite_eat_status
composite_eat_finish_write(const struct composite_eat_prepared *prepared,
                           const uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH],
                           composite_eat_write write, void *context, size_t response_capacity,
                           size_t *response_length) {
    struct composite_eat_writer writer = {
        .write = write,
        .context = context,
        .capacity = response_capacity,
    };

    if (response_length == NULL) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }
    *response_length = 0;
    if ((prepared == NULL) || !prepared->ready || (prepared->workspace == NULL) ||
        !composite_eat_identity_valid(prepared->identity) || (signature == NULL) ||
        (write == NULL)) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }
    if (!prepared->signing_complete) {
        return COMPOSITE_EAT_STATE_ERROR;
    }

    *response_length = prepared->response_length;
    if (response_capacity < *response_length) {
        return COMPOSITE_EAT_BUFFER_TOO_SMALL;
    }

    composite_eat_add_token(&writer, prepared, signature);
    if (writer.failed || (writer.length != *response_length)) {
        *response_length = 0;
        return COMPOSITE_EAT_WRITE_ERROR;
    }

    return COMPOSITE_EAT_OK;
}

enum composite_eat_status
composite_eat_finish(const struct composite_eat_prepared *prepared,
                     const uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH],
                     uint8_t *response, size_t response_capacity, size_t *response_length) {
    struct composite_eat_buffer_writer output = {
        .buffer = response,
        .capacity = response_capacity,
    };
    enum composite_eat_status status;

    if ((response == NULL) && (response_capacity != 0)) {
        if (response_length != NULL) {
            *response_length = 0;
        }
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }

    status = composite_eat_finish_write(prepared, signature, composite_eat_buffer_write, &output,
                                        response_capacity, response_length);
    if ((status == COMPOSITE_EAT_WRITE_ERROR) && (response != NULL)) {
        memset(response, 0, response_capacity);
    }
    return status;
}

void composite_eat_clear(struct composite_eat_workspace *workspace,
                         struct composite_eat_prepared *prepared) {
    if (workspace != NULL) {
        composite_eat_clear_bytes(workspace, sizeof(*workspace));
    }
    if (prepared != NULL) {
        composite_eat_clear_bytes(prepared, sizeof(*prepared));
    }
}
