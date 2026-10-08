// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <limits.h>
#include <string.h>

#include "composite_eat/tcg_concise_evidence.h"

#define TCG_CE_EV_TRIPLES 0
#define TCG_CE_EVIDENCE_TRIPLES 0
#define TCG_CE_ENVIRONMENT_CLASS 0
#define TCG_CE_ENVIRONMENT_INSTANCE 1
#define TCG_CE_ENVIRONMENT_GROUP 2
#define TCG_CE_CLASS_ID 0
#define TCG_CE_VENDOR 1
#define TCG_CE_MODEL 2
#define TCG_CE_LAYER 3
#define TCG_CE_INDEX 4
#define TCG_CE_MEASUREMENT_KEY 0
#define TCG_CE_MEASUREMENT_VALUE 1
#define TCG_CE_DIGESTS 2
#define TCG_CE_FLAGS 3
#define TCG_CE_NAME 11
#define TCG_CE_FLAG_INTEGRITY_PROTECTED 5
#define TCG_CE_FLAG_RUNTIME_MEASUREMENT 6
#define TCG_CE_FLAG_IMMUTABLE 7
#define TCG_CE_FLAG_TCB 8

#define TCG_CE_CBOR_MAJOR_UNSIGNED 0u
#define TCG_CE_CBOR_MAJOR_NEGATIVE 1u
#define TCG_CE_CBOR_MAJOR_BYTES 2u
#define TCG_CE_CBOR_MAJOR_TEXT 3u
#define TCG_CE_CBOR_MAJOR_ARRAY 4u
#define TCG_CE_CBOR_MAJOR_MAP 5u
#define TCG_CE_CBOR_MAJOR_TAG 6u
#define TCG_CE_CBOR_SIMPLE_FALSE 0xf4u
#define TCG_CE_CBOR_SIMPLE_TRUE 0xf5u

struct tcg_ce_writer {
    tcg_concise_evidence_write write;
    void *context;
    size_t length;
    bool failed;
    bool write_failed;
};

struct tcg_ce_buffer_writer {
    uint8_t *buffer;
    size_t capacity;
    size_t offset;
};

static bool tcg_ce_bytes_valid(const struct tcg_concise_evidence_bytes *bytes) {
    return (bytes != NULL) && (bytes->data != NULL) && (bytes->length != 0);
}

static bool tcg_ce_text_valid(const struct tcg_concise_evidence_text *text) {
    size_t offset = 0;

    if ((text == NULL) || (text->data == NULL) || (text->length == 0) ||
        (memchr(text->data, '\0', text->length) != NULL)) {
        return false;
    }

    while (offset < text->length) {
        uint8_t first = text->data[offset++];
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

        if ((text->length - offset) < continuation) {
            return false;
        }
        for (i = 0; i < continuation; ++i) {
            uint8_t next = text->data[offset++];

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

static bool tcg_ce_tagged_id_valid(const struct tcg_concise_evidence_tagged_id *id) {
    if ((id == NULL) || !tcg_ce_bytes_valid(&id->value)) {
        return false;
    }

    switch (id->type) {
    case TCG_CONCISE_EVIDENCE_TAGGED_BYTES:
    case TCG_CONCISE_EVIDENCE_TAGGED_OID:
        return true;

    case TCG_CONCISE_EVIDENCE_TAGGED_UUID:
        return id->value.length == 16;

    case TCG_CONCISE_EVIDENCE_TAGGED_UEID:
        return (id->value.length >= 7) && (id->value.length <= 33);

    default:
        return false;
    }
}

static bool
tcg_ce_measured_element_valid(const struct tcg_concise_evidence_measured_element *element) {
    if (element == NULL) {
        return false;
    }

    switch (element->type) {
    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UINT:
        return true;

    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_TEXT:
        return tcg_ce_text_valid(&element->value.text);

    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UUID:
        return tcg_ce_bytes_valid(&element->value.bytes) && (element->value.bytes.length == 16);

    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_OID:
        return tcg_ce_bytes_valid(&element->value.bytes);

    default:
        return false;
    }
}

static bool tcg_ce_class_valid(const struct tcg_concise_evidence_class *class_info) {
    return (class_info != NULL) &&
           (class_info->has_class_id || class_info->has_vendor || class_info->has_model ||
            class_info->has_layer || class_info->has_index) &&
           (!class_info->has_class_id ||
            ((class_info->class_id.type != TCG_CONCISE_EVIDENCE_TAGGED_UEID) &&
             tcg_ce_tagged_id_valid(&class_info->class_id))) &&
           (!class_info->has_vendor || tcg_ce_text_valid(&class_info->vendor)) &&
           (!class_info->has_model || tcg_ce_text_valid(&class_info->model));
}

static bool tcg_ce_environment_valid(const struct tcg_concise_evidence_environment *environment) {
    if ((environment == NULL) ||
        (!environment->has_class && !environment->has_instance && !environment->has_group)) {
        return false;
    }
    if (environment->has_class && !tcg_ce_class_valid(&environment->class_info)) {
        return false;
    }
    if (environment->has_instance &&
        ((environment->instance.type != TCG_CONCISE_EVIDENCE_TAGGED_BYTES) &&
         (environment->instance.type != TCG_CONCISE_EVIDENCE_TAGGED_UUID) &&
         (environment->instance.type != TCG_CONCISE_EVIDENCE_TAGGED_UEID))) {
        return false;
    }
    if (environment->has_instance && !tcg_ce_tagged_id_valid(&environment->instance)) {
        return false;
    }
    if (environment->has_group && ((environment->group.type != TCG_CONCISE_EVIDENCE_TAGGED_BYTES) &&
                                   (environment->group.type != TCG_CONCISE_EVIDENCE_TAGGED_UUID))) {
        return false;
    }

    return !environment->has_group || tcg_ce_tagged_id_valid(&environment->group);
}

enum tcg_concise_evidence_status tcg_concise_evidence_validate_environment(
    const struct tcg_concise_evidence_environment *environment) {
    return tcg_ce_environment_valid(environment) ? TCG_CONCISE_EVIDENCE_OK
                                                 : TCG_CONCISE_EVIDENCE_BAD_ARGUMENT;
}

static bool tcg_ce_algorithm_valid(const struct tcg_concise_evidence_algorithm *algorithm,
                                   size_t digest_length) {
    if (algorithm == NULL) {
        return false;
    }

    switch (algorithm->type) {
    case TCG_CONCISE_EVIDENCE_ALGORITHM_SHA256:
        return digest_length == TCG_CONCISE_EVIDENCE_SHA256_LENGTH;

    case TCG_CONCISE_EVIDENCE_ALGORITHM_SHA384:
        return digest_length == TCG_CONCISE_EVIDENCE_SHA384_LENGTH;

    case TCG_CONCISE_EVIDENCE_ALGORITHM_SHA512:
        return digest_length == TCG_CONCISE_EVIDENCE_SHA512_LENGTH;

    case TCG_CONCISE_EVIDENCE_ALGORITHM_INTEGER:
        return digest_length != 0;

    case TCG_CONCISE_EVIDENCE_ALGORITHM_TEXT:
        return (digest_length != 0) && tcg_ce_text_valid(&algorithm->value.text);

    default:
        return false;
    }
}

static bool tcg_ce_flags_valid(const struct tcg_concise_evidence_flags *flags) {
    return (flags != NULL) &&
           (flags->has_is_integrity_protected || flags->has_is_runtime_measurement ||
            flags->has_is_immutable || flags->has_is_tcb);
}

static bool
tcg_ce_measurement_values_valid(const struct tcg_concise_evidence_measurement_values *values) {
    size_t i;

    if ((values == NULL) ||
        ((values->digest_count == 0) && !values->has_flags && !values->has_name) ||
        ((values->digest_count != 0) && (values->digests == NULL)) ||
        (values->has_flags && !tcg_ce_flags_valid(&values->flags)) ||
        (values->has_name && !tcg_ce_text_valid(&values->name))) {
        return false;
    }

    for (i = 0; i < values->digest_count; ++i) {
        if (!tcg_ce_bytes_valid(&values->digests[i].value) ||
            !tcg_ce_algorithm_valid(&values->digests[i].algorithm,
                                    values->digests[i].value.length)) {
            return false;
        }
    }

    return true;
}

enum tcg_concise_evidence_status
tcg_concise_evidence_validate(const struct tcg_concise_evidence_document *document) {
    size_t triple;
    size_t measurement;

    if ((document == NULL) || (document->evidence_triples == NULL) ||
        (document->evidence_triple_count == 0)) {
        return TCG_CONCISE_EVIDENCE_BAD_ARGUMENT;
    }

    for (triple = 0; triple < document->evidence_triple_count; ++triple) {
        const struct tcg_concise_evidence_triple *current = &document->evidence_triples[triple];

        if (!tcg_ce_environment_valid(&current->environment) || (current->measurements == NULL) ||
            (current->measurement_count == 0)) {
            return TCG_CONCISE_EVIDENCE_BAD_ARGUMENT;
        }

        for (measurement = 0; measurement < current->measurement_count; ++measurement) {
            const struct tcg_concise_evidence_measurement *item =
                &current->measurements[measurement];

            if ((item->has_key && !tcg_ce_measured_element_valid(&item->key)) ||
                !tcg_ce_measurement_values_valid(&item->values)) {
                return TCG_CONCISE_EVIDENCE_BAD_ARGUMENT;
            }
        }
    }

    return TCG_CONCISE_EVIDENCE_OK;
}

static void tcg_ce_writer_add(struct tcg_ce_writer *writer, const uint8_t *data, size_t length) {
    if (writer->failed || ((SIZE_MAX - writer->length) < length)) {
        writer->failed = true;
        return;
    }
    if ((writer->write != NULL) && (length != 0) &&
        (writer->write(writer->context, data, length) != 0)) {
        writer->failed = true;
        writer->write_failed = true;
        return;
    }
    writer->length += length;
}

static int tcg_ce_buffer_write(void *context, const uint8_t *data, size_t length) {
    struct tcg_ce_buffer_writer *writer = context;

    if ((writer == NULL) || (data == NULL) || (writer->offset > writer->capacity) ||
        ((writer->capacity - writer->offset) < length)) {
        return -1;
    }
    memcpy(&writer->buffer[writer->offset], data, length);
    writer->offset += length;
    return 0;
}

static void tcg_ce_add_type_value(struct tcg_ce_writer *writer, uint8_t major, uint64_t value) {
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

    tcg_ce_writer_add(writer, encoded, length);
}

static void tcg_ce_add_int(struct tcg_ce_writer *writer, int64_t value) {
    if (value >= 0) {
        tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_UNSIGNED, (uint64_t)value);
    } else {
        tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_NEGATIVE, (uint64_t)(-(value + 1)));
    }
}

static void tcg_ce_add_uint(struct tcg_ce_writer *writer, uint64_t value) {
    tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_UNSIGNED, value);
}

static void tcg_ce_add_bytes(struct tcg_ce_writer *writer,
                             const struct tcg_concise_evidence_bytes *bytes) {
    tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_BYTES, bytes->length);
    tcg_ce_writer_add(writer, bytes->data, bytes->length);
}

static void tcg_ce_add_text(struct tcg_ce_writer *writer,
                            const struct tcg_concise_evidence_text *text) {
    tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_TEXT, text->length);
    tcg_ce_writer_add(writer, text->data, text->length);
}

static void tcg_ce_add_bool(struct tcg_ce_writer *writer, bool value) {
    const uint8_t encoded = value ? TCG_CE_CBOR_SIMPLE_TRUE : TCG_CE_CBOR_SIMPLE_FALSE;

    tcg_ce_writer_add(writer, &encoded, sizeof(encoded));
}

static uint64_t tcg_ce_tagged_id_tag(enum tcg_concise_evidence_tagged_id_type type) {
    switch (type) {
    case TCG_CONCISE_EVIDENCE_TAGGED_UUID:
        return TCG_CONCISE_EVIDENCE_TAG_UUID;

    case TCG_CONCISE_EVIDENCE_TAGGED_OID:
        return TCG_CONCISE_EVIDENCE_TAG_OID;

    case TCG_CONCISE_EVIDENCE_TAGGED_UEID:
        return TCG_CONCISE_EVIDENCE_TAG_UEID;

    case TCG_CONCISE_EVIDENCE_TAGGED_BYTES:
    default:
        return TCG_CONCISE_EVIDENCE_TAG_BYTES;
    }
}

static void tcg_ce_add_tagged_id(struct tcg_ce_writer *writer,
                                 const struct tcg_concise_evidence_tagged_id *id) {
    tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_TAG, tcg_ce_tagged_id_tag(id->type));
    tcg_ce_add_bytes(writer, &id->value);
}

static void
tcg_ce_add_measured_element(struct tcg_ce_writer *writer,
                            const struct tcg_concise_evidence_measured_element *element) {
    switch (element->type) {
    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UINT:
        tcg_ce_add_uint(writer, element->value.uint_value);
        break;

    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_TEXT:
        tcg_ce_add_text(writer, &element->value.text);
        break;

    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UUID:
        tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_TAG, TCG_CONCISE_EVIDENCE_TAG_UUID);
        tcg_ce_add_bytes(writer, &element->value.bytes);
        break;

    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_OID:
        tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_TAG, TCG_CONCISE_EVIDENCE_TAG_OID);
        tcg_ce_add_bytes(writer, &element->value.bytes);
        break;
    }
}

static size_t tcg_ce_class_field_count(const struct tcg_concise_evidence_class *class_info) {
    return (size_t)class_info->has_class_id + (size_t)class_info->has_vendor +
           (size_t)class_info->has_model + (size_t)class_info->has_layer +
           (size_t)class_info->has_index;
}

static void tcg_ce_add_class(struct tcg_ce_writer *writer,
                             const struct tcg_concise_evidence_class *class_info) {
    tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_MAP, tcg_ce_class_field_count(class_info));
    if (class_info->has_class_id) {
        tcg_ce_add_uint(writer, TCG_CE_CLASS_ID);
        tcg_ce_add_tagged_id(writer, &class_info->class_id);
    }
    if (class_info->has_vendor) {
        tcg_ce_add_uint(writer, TCG_CE_VENDOR);
        tcg_ce_add_text(writer, &class_info->vendor);
    }
    if (class_info->has_model) {
        tcg_ce_add_uint(writer, TCG_CE_MODEL);
        tcg_ce_add_text(writer, &class_info->model);
    }
    if (class_info->has_layer) {
        tcg_ce_add_uint(writer, TCG_CE_LAYER);
        tcg_ce_add_uint(writer, class_info->layer);
    }
    if (class_info->has_index) {
        tcg_ce_add_uint(writer, TCG_CE_INDEX);
        tcg_ce_add_uint(writer, class_info->index);
    }
}

static void tcg_ce_add_environment(struct tcg_ce_writer *writer,
                                   const struct tcg_concise_evidence_environment *environment) {
    size_t count = (size_t)environment->has_class + (size_t)environment->has_instance +
                   (size_t)environment->has_group;

    tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_MAP, count);
    if (environment->has_class) {
        tcg_ce_add_uint(writer, TCG_CE_ENVIRONMENT_CLASS);
        tcg_ce_add_class(writer, &environment->class_info);
    }
    if (environment->has_instance) {
        tcg_ce_add_uint(writer, TCG_CE_ENVIRONMENT_INSTANCE);
        tcg_ce_add_tagged_id(writer, &environment->instance);
    }
    if (environment->has_group) {
        tcg_ce_add_uint(writer, TCG_CE_ENVIRONMENT_GROUP);
        tcg_ce_add_tagged_id(writer, &environment->group);
    }
}

static void tcg_ce_add_algorithm(struct tcg_ce_writer *writer,
                                 const struct tcg_concise_evidence_algorithm *algorithm) {
    static const struct tcg_concise_evidence_text sha256 = {(const uint8_t *)"sha-256",
                                                            sizeof("sha-256") - 1};
    static const struct tcg_concise_evidence_text sha384 = {(const uint8_t *)"sha-384",
                                                            sizeof("sha-384") - 1};
    static const struct tcg_concise_evidence_text sha512 = {(const uint8_t *)"sha-512",
                                                            sizeof("sha-512") - 1};

    switch (algorithm->type) {
    case TCG_CONCISE_EVIDENCE_ALGORITHM_SHA256:
        tcg_ce_add_text(writer, &sha256);
        break;

    case TCG_CONCISE_EVIDENCE_ALGORITHM_SHA384:
        tcg_ce_add_text(writer, &sha384);
        break;

    case TCG_CONCISE_EVIDENCE_ALGORITHM_SHA512:
        tcg_ce_add_text(writer, &sha512);
        break;

    case TCG_CONCISE_EVIDENCE_ALGORITHM_INTEGER:
        tcg_ce_add_int(writer, algorithm->value.integer);
        break;

    case TCG_CONCISE_EVIDENCE_ALGORITHM_TEXT:
        tcg_ce_add_text(writer, &algorithm->value.text);
        break;
    }
}

static size_t tcg_ce_flags_field_count(const struct tcg_concise_evidence_flags *flags) {
    return (size_t)flags->has_is_integrity_protected + (size_t)flags->has_is_runtime_measurement +
           (size_t)flags->has_is_immutable + (size_t)flags->has_is_tcb;
}

static void tcg_ce_add_flags(struct tcg_ce_writer *writer,
                             const struct tcg_concise_evidence_flags *flags) {
    tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_MAP, tcg_ce_flags_field_count(flags));
    if (flags->has_is_integrity_protected) {
        tcg_ce_add_uint(writer, TCG_CE_FLAG_INTEGRITY_PROTECTED);
        tcg_ce_add_bool(writer, flags->is_integrity_protected);
    }
    if (flags->has_is_runtime_measurement) {
        tcg_ce_add_uint(writer, TCG_CE_FLAG_RUNTIME_MEASUREMENT);
        tcg_ce_add_bool(writer, flags->is_runtime_measurement);
    }
    if (flags->has_is_immutable) {
        tcg_ce_add_uint(writer, TCG_CE_FLAG_IMMUTABLE);
        tcg_ce_add_bool(writer, flags->is_immutable);
    }
    if (flags->has_is_tcb) {
        tcg_ce_add_uint(writer, TCG_CE_FLAG_TCB);
        tcg_ce_add_bool(writer, flags->is_tcb);
    }
}

static size_t
tcg_ce_measurement_value_field_count(const struct tcg_concise_evidence_measurement_values *values) {
    return (size_t)(values->digest_count != 0) + (size_t)values->has_flags +
           (size_t)values->has_name;
}

static void
tcg_ce_add_measurement_values(struct tcg_ce_writer *writer,
                              const struct tcg_concise_evidence_measurement_values *values) {
    size_t i;

    tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_MAP,
                          tcg_ce_measurement_value_field_count(values));
    if (values->digest_count != 0) {
        tcg_ce_add_uint(writer, TCG_CE_DIGESTS);
        tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_ARRAY, values->digest_count);
        for (i = 0; i < values->digest_count; ++i) {
            tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_ARRAY, 2);
            tcg_ce_add_algorithm(writer, &values->digests[i].algorithm);
            tcg_ce_add_bytes(writer, &values->digests[i].value);
        }
    }
    if (values->has_flags) {
        tcg_ce_add_uint(writer, TCG_CE_FLAGS);
        tcg_ce_add_flags(writer, &values->flags);
    }
    if (values->has_name) {
        tcg_ce_add_uint(writer, TCG_CE_NAME);
        tcg_ce_add_text(writer, &values->name);
    }
}

static void tcg_ce_add_document(struct tcg_ce_writer *writer,
                                const struct tcg_concise_evidence_document *document) {
    size_t triple;
    size_t measurement;

    tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_MAP, 1);
    tcg_ce_add_uint(writer, TCG_CE_EV_TRIPLES);
    tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_MAP, 1);
    tcg_ce_add_uint(writer, TCG_CE_EVIDENCE_TRIPLES);
    tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_ARRAY, document->evidence_triple_count);
    for (triple = 0; triple < document->evidence_triple_count; ++triple) {
        const struct tcg_concise_evidence_triple *current = &document->evidence_triples[triple];

        tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_ARRAY, 2);
        tcg_ce_add_environment(writer, &current->environment);
        tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_ARRAY, current->measurement_count);
        for (measurement = 0; measurement < current->measurement_count; ++measurement) {
            const struct tcg_concise_evidence_measurement *item =
                &current->measurements[measurement];

            tcg_ce_add_type_value(writer, TCG_CE_CBOR_MAJOR_MAP, item->has_key ? 2 : 1);
            if (item->has_key) {
                tcg_ce_add_uint(writer, TCG_CE_MEASUREMENT_KEY);
                tcg_ce_add_measured_element(writer, &item->key);
            }
            tcg_ce_add_uint(writer, TCG_CE_MEASUREMENT_VALUE);
            tcg_ce_add_measurement_values(writer, &item->values);
        }
    }
}

enum tcg_concise_evidence_status
tcg_concise_evidence_get_size(const struct tcg_concise_evidence_document *document,
                              size_t *encoded_length) {
    struct tcg_ce_writer writer = {0};

    if (encoded_length == NULL) {
        return TCG_CONCISE_EVIDENCE_BAD_ARGUMENT;
    }
    *encoded_length = 0;
    if (tcg_concise_evidence_validate(document) != TCG_CONCISE_EVIDENCE_OK) {
        return TCG_CONCISE_EVIDENCE_BAD_ARGUMENT;
    }

    tcg_ce_add_document(&writer, document);
    if (writer.failed) {
        return TCG_CONCISE_EVIDENCE_ENCODING_ERROR;
    }
    *encoded_length = writer.length;
    return TCG_CONCISE_EVIDENCE_OK;
}

enum tcg_concise_evidence_status
tcg_concise_evidence_encode_write(const struct tcg_concise_evidence_document *document,
                                  tcg_concise_evidence_write write, void *context,
                                  size_t output_capacity, size_t *encoded_length) {
    struct tcg_ce_writer writer = {
        .write = write,
        .context = context,
    };
    enum tcg_concise_evidence_status status;

    if ((write == NULL) || (encoded_length == NULL)) {
        return TCG_CONCISE_EVIDENCE_BAD_ARGUMENT;
    }
    status = tcg_concise_evidence_get_size(document, encoded_length);
    if (status != TCG_CONCISE_EVIDENCE_OK) {
        return status;
    }
    if (output_capacity < *encoded_length) {
        return TCG_CONCISE_EVIDENCE_BUFFER_TOO_SMALL;
    }

    tcg_ce_add_document(&writer, document);
    if (writer.failed || (writer.length != *encoded_length)) {
        return writer.write_failed ? TCG_CONCISE_EVIDENCE_WRITE_ERROR
                                   : TCG_CONCISE_EVIDENCE_ENCODING_ERROR;
    }
    return TCG_CONCISE_EVIDENCE_OK;
}

enum tcg_concise_evidence_status
tcg_concise_evidence_encode(const struct tcg_concise_evidence_document *document, uint8_t *encoded,
                            size_t encoded_capacity, size_t *encoded_length) {
    struct tcg_ce_buffer_writer writer = {
        .buffer = encoded,
        .capacity = encoded_capacity,
    };
    enum tcg_concise_evidence_status status;

    if ((encoded == NULL) && (encoded_capacity != 0)) {
        if (encoded_length != NULL) {
            *encoded_length = 0;
        }
        return TCG_CONCISE_EVIDENCE_BAD_ARGUMENT;
    }
    if (encoded == NULL) {
        return tcg_concise_evidence_get_size(document, encoded_length) == TCG_CONCISE_EVIDENCE_OK
                   ? TCG_CONCISE_EVIDENCE_BUFFER_TOO_SMALL
                   : TCG_CONCISE_EVIDENCE_BAD_ARGUMENT;
    }

    status = tcg_concise_evidence_encode_write(document, tcg_ce_buffer_write, &writer,
                                               encoded_capacity, encoded_length);
    if ((status == TCG_CONCISE_EVIDENCE_ENCODING_ERROR) ||
        (status == TCG_CONCISE_EVIDENCE_WRITE_ERROR)) {
        memset(encoded, 0, encoded_capacity);
        if (encoded_length != NULL) {
            *encoded_length = 0;
        }
    }
    return status;
}
