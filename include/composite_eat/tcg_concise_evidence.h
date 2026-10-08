// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef TCG_CONCISE_EVIDENCE_H_
#define TCG_CONCISE_EVIDENCE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TCG_CONCISE_EVIDENCE_TAG_UUID 37u
#define TCG_CONCISE_EVIDENCE_TAG_UEID 550u
#define TCG_CONCISE_EVIDENCE_TAG_BYTES 560u
#define TCG_CONCISE_EVIDENCE_TAG_OID 111u

#define TCG_CONCISE_EVIDENCE_SHA256_LENGTH 32u
#define TCG_CONCISE_EVIDENCE_SHA384_LENGTH 48u
#define TCG_CONCISE_EVIDENCE_SHA512_LENGTH 64u

/* IANA CoAP Content-Format for application/ce+cbor. */
#define COMPOSITE_EAT_TCG_CONCISE_EVIDENCE_CONTENT_FORMAT 10571u

enum tcg_concise_evidence_status {
    TCG_CONCISE_EVIDENCE_OK = 0,
    TCG_CONCISE_EVIDENCE_BAD_ARGUMENT,
    TCG_CONCISE_EVIDENCE_UNSUPPORTED,
    TCG_CONCISE_EVIDENCE_BUFFER_TOO_SMALL,
    TCG_CONCISE_EVIDENCE_ENCODING_ERROR,
    TCG_CONCISE_EVIDENCE_WRITE_ERROR,
};

struct tcg_concise_evidence_bytes {
    const uint8_t *data;
    size_t length;
};

struct tcg_concise_evidence_text {
    const uint8_t *data;
    size_t length;
};

enum tcg_concise_evidence_tagged_id_type {
    TCG_CONCISE_EVIDENCE_TAGGED_BYTES,
    TCG_CONCISE_EVIDENCE_TAGGED_UUID,
    TCG_CONCISE_EVIDENCE_TAGGED_OID,
    TCG_CONCISE_EVIDENCE_TAGGED_UEID,
};

struct tcg_concise_evidence_tagged_id {
    enum tcg_concise_evidence_tagged_id_type type;
    struct tcg_concise_evidence_bytes value;
};

enum tcg_concise_evidence_measured_element_type {
    TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UINT,
    TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_TEXT,
    TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UUID,
    TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_OID,
};

struct tcg_concise_evidence_measured_element {
    enum tcg_concise_evidence_measured_element_type type;
    union {
        uint64_t uint_value;
        struct tcg_concise_evidence_text text;
        struct tcg_concise_evidence_bytes bytes;
    } value;
};

struct tcg_concise_evidence_class {
    bool has_class_id;
    struct tcg_concise_evidence_tagged_id class_id;
    bool has_vendor;
    struct tcg_concise_evidence_text vendor;
    bool has_model;
    struct tcg_concise_evidence_text model;
    bool has_layer;
    uint64_t layer;
    bool has_index;
    uint64_t index;
};

struct tcg_concise_evidence_environment {
    bool has_class;
    struct tcg_concise_evidence_class class_info;
    bool has_instance;
    struct tcg_concise_evidence_tagged_id instance;
    bool has_group;
    struct tcg_concise_evidence_tagged_id group;
};

enum tcg_concise_evidence_algorithm_type {
    TCG_CONCISE_EVIDENCE_ALGORITHM_SHA256,
    TCG_CONCISE_EVIDENCE_ALGORITHM_SHA384,
    TCG_CONCISE_EVIDENCE_ALGORITHM_SHA512,
    TCG_CONCISE_EVIDENCE_ALGORITHM_INTEGER,
    TCG_CONCISE_EVIDENCE_ALGORITHM_TEXT,
};

struct tcg_concise_evidence_algorithm {
    enum tcg_concise_evidence_algorithm_type type;
    union {
        int64_t integer;
        struct tcg_concise_evidence_text text;
    } value;
};

struct tcg_concise_evidence_digest {
    struct tcg_concise_evidence_algorithm algorithm;
    struct tcg_concise_evidence_bytes value;
};

struct tcg_concise_evidence_flags {
    bool has_is_integrity_protected;
    bool is_integrity_protected;
    bool has_is_runtime_measurement;
    bool is_runtime_measurement;
    bool has_is_immutable;
    bool is_immutable;
    bool has_is_tcb;
    bool is_tcb;
};

struct tcg_concise_evidence_measurement_values {
    const struct tcg_concise_evidence_digest *digests;
    size_t digest_count;
    bool has_flags;
    struct tcg_concise_evidence_flags flags;
    bool has_name;
    struct tcg_concise_evidence_text name;
};

struct tcg_concise_evidence_measurement {
    bool has_key;
    struct tcg_concise_evidence_measured_element key;
    struct tcg_concise_evidence_measurement_values values;
};

struct tcg_concise_evidence_triple {
    struct tcg_concise_evidence_environment environment;
    /* Caller-owned order is preserved and must be deterministic for signed evidence. */
    const struct tcg_concise_evidence_measurement *measurements;
    size_t measurement_count;
};

struct tcg_concise_evidence_document {
    /* Caller-owned order is preserved and must be deterministic for signed evidence. */
    const struct tcg_concise_evidence_triple *evidence_triples;
    size_t evidence_triple_count;
};

/* All document pointers are borrowed and must remain immutable for each complete encode call. */

typedef int (*tcg_concise_evidence_write)(void *context, const uint8_t *data, size_t length);

enum tcg_concise_evidence_status tcg_concise_evidence_validate_environment(
    const struct tcg_concise_evidence_environment *environment);

enum tcg_concise_evidence_status
tcg_concise_evidence_validate(const struct tcg_concise_evidence_document *document);

enum tcg_concise_evidence_status
tcg_concise_evidence_get_size(const struct tcg_concise_evidence_document *document,
                              size_t *encoded_length);

enum tcg_concise_evidence_status
tcg_concise_evidence_encode_write(const struct tcg_concise_evidence_document *document,
                                  tcg_concise_evidence_write write, void *context,
                                  size_t output_capacity, size_t *encoded_length);

/* A NULL encoded buffer performs a size query and returns BUFFER_TOO_SMALL with the required size.
 */
enum tcg_concise_evidence_status
tcg_concise_evidence_encode(const struct tcg_concise_evidence_document *document, uint8_t *encoded,
                            size_t encoded_capacity, size_t *encoded_length);

#endif /* TCG_CONCISE_EVIDENCE_H_ */
