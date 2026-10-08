// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <string.h>

#include "composite_eat/profile_evidence.h"

static uint32_t
composite_eat_profile_mkey_mask(enum tcg_concise_evidence_measured_element_type type) {
    switch (type) {
    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UINT:
        return COMPOSITE_EAT_PROFILE_MKEY_UINT;

    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_TEXT:
        return COMPOSITE_EAT_PROFILE_MKEY_TEXT;

    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UUID:
        return COMPOSITE_EAT_PROFILE_MKEY_UUID;

    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_OID:
        return COMPOSITE_EAT_PROFILE_MKEY_OID;

    default:
        return 0;
    }
}

static uint32_t
composite_eat_profile_algorithm_mask(enum tcg_concise_evidence_algorithm_type type) {
    switch (type) {
    case TCG_CONCISE_EVIDENCE_ALGORITHM_SHA256:
        return COMPOSITE_EAT_PROFILE_ALGORITHM_SHA256;

    case TCG_CONCISE_EVIDENCE_ALGORITHM_SHA384:
        return COMPOSITE_EAT_PROFILE_ALGORITHM_SHA384;

    case TCG_CONCISE_EVIDENCE_ALGORITHM_SHA512:
        return COMPOSITE_EAT_PROFILE_ALGORITHM_SHA512;

    case TCG_CONCISE_EVIDENCE_ALGORITHM_INTEGER:
        return COMPOSITE_EAT_PROFILE_ALGORITHM_INTEGER;

    case TCG_CONCISE_EVIDENCE_ALGORITHM_TEXT:
        return COMPOSITE_EAT_PROFILE_ALGORITHM_TEXT;

    default:
        return 0;
    }
}

static size_t
composite_eat_profile_mkey_length(const struct tcg_concise_evidence_measured_element *key) {
    switch (key->type) {
    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_TEXT:
        return key->value.text.length;

    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UUID:
    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_OID:
        return key->value.bytes.length;

    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UINT:
    default:
        return 0;
    }
}

static bool
composite_eat_profile_mkeys_equal(const struct tcg_concise_evidence_measured_element *left,
                                  const struct tcg_concise_evidence_measured_element *right) {
    if (left->type != right->type) {
        return false;
    }

    switch (left->type) {
    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UINT:
        return left->value.uint_value == right->value.uint_value;

    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_TEXT:
        return (left->value.text.length == right->value.text.length) &&
               (memcmp(left->value.text.data, right->value.text.data, left->value.text.length) ==
                0);

    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UUID:
    case TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_OID:
        return (left->value.bytes.length == right->value.bytes.length) &&
               (memcmp(left->value.bytes.data, right->value.bytes.data, left->value.bytes.length) ==
                0);

    default:
        return false;
    }
}

static bool composite_eat_profile_environment_allowed(
    const struct tcg_concise_evidence_environment *environment,
    const struct composite_eat_profile_evidence_policy *policy) {
    const struct tcg_concise_evidence_class *class_info = &environment->class_info;

    if ((policy->require_class && !environment->has_class) ||
        (policy->require_class_id && (!environment->has_class || !class_info->has_class_id)) ||
        (policy->require_vendor && (!environment->has_class || !class_info->has_vendor)) ||
        (policy->require_model && (!environment->has_class || !class_info->has_model))) {
        return false;
    }
    if (environment->has_class &&
        ((class_info->has_class_id &&
          (class_info->class_id.value.length > policy->max_identifier_length)) ||
         (class_info->has_vendor && (class_info->vendor.length > policy->max_text_length)) ||
         (class_info->has_model && (class_info->model.length > policy->max_text_length)))) {
        return false;
    }
    if ((environment->has_instance &&
         (environment->instance.value.length > policy->max_identifier_length)) ||
        (environment->has_group &&
         (environment->group.value.length > policy->max_identifier_length))) {
        return false;
    }

    return true;
}

enum composite_eat_profile_evidence_status composite_eat_profile_validate_environment(
    const struct tcg_concise_evidence_environment *environment,
    const struct composite_eat_profile_evidence_policy *policy) {
    if ((policy == NULL) || (policy->max_identifier_length == 0) ||
        (policy->max_text_length == 0)) {
        return COMPOSITE_EAT_PROFILE_EVIDENCE_BAD_ARGUMENT;
    }
    if (tcg_concise_evidence_validate_environment(environment) != TCG_CONCISE_EVIDENCE_OK) {
        return COMPOSITE_EAT_PROFILE_EVIDENCE_SCHEMA_ERROR;
    }
    return composite_eat_profile_environment_allowed(environment, policy)
               ? COMPOSITE_EAT_PROFILE_EVIDENCE_OK
               : COMPOSITE_EAT_PROFILE_EVIDENCE_POLICY_ERROR;
}

static bool composite_eat_profile_measurement_allowed(
    const struct tcg_concise_evidence_measurement *measurement,
    const struct composite_eat_profile_evidence_policy *policy) {
    size_t digest;

    if ((policy->require_measurement_key && !measurement->has_key) ||
        (measurement->has_key && ((composite_eat_profile_mkey_mask(measurement->key.type) &
                                   policy->allowed_mkey_types) == 0)) ||
        (measurement->has_key &&
         (composite_eat_profile_mkey_length(&measurement->key) > policy->max_identifier_length)) ||
        (measurement->values.has_flags && !policy->allow_flags) ||
        (measurement->values.has_name && !policy->allow_name) ||
        (measurement->values.has_name &&
         (measurement->values.name.length > policy->max_text_length))) {
        return false;
    }

    for (digest = 0; digest < measurement->values.digest_count; ++digest) {
        const struct tcg_concise_evidence_algorithm *algorithm =
            &measurement->values.digests[digest].algorithm;

        if (((composite_eat_profile_algorithm_mask(algorithm->type) & policy->allowed_algorithms) ==
             0) ||
            ((algorithm->type == TCG_CONCISE_EVIDENCE_ALGORITHM_TEXT) &&
             (algorithm->value.text.length > policy->max_text_length))) {
            return false;
        }
    }

    return true;
}

enum composite_eat_profile_evidence_status composite_eat_profile_validate_local_evidence(
    const struct tcg_concise_evidence_document *document,
    const struct composite_eat_profile_evidence_policy *policy, size_t *encoded_length) {
    size_t triple;
    size_t measurement;
    size_t other;
    enum tcg_concise_evidence_status size_status;

    if ((policy == NULL) || (encoded_length == NULL) || (policy->max_triples == 0) ||
        (policy->max_measurements_per_triple == 0) || (policy->max_digests_per_measurement == 0) ||
        (policy->max_identifier_length == 0) || (policy->max_text_length == 0) ||
        (policy->max_encoded_length == 0) || (policy->allowed_mkey_types == 0) ||
        (policy->allowed_algorithms == 0)) {
        return COMPOSITE_EAT_PROFILE_EVIDENCE_BAD_ARGUMENT;
    }
    *encoded_length = 0;
    if ((document == NULL) || (document->evidence_triples == NULL) ||
        (document->evidence_triple_count == 0)) {
        return COMPOSITE_EAT_PROFILE_EVIDENCE_SCHEMA_ERROR;
    }
    if (document->evidence_triple_count > policy->max_triples) {
        return COMPOSITE_EAT_PROFILE_EVIDENCE_LIMIT_EXCEEDED;
    }
    for (triple = 0; triple < document->evidence_triple_count; ++triple) {
        const struct tcg_concise_evidence_triple *current = &document->evidence_triples[triple];

        if (current->measurement_count > policy->max_measurements_per_triple) {
            return COMPOSITE_EAT_PROFILE_EVIDENCE_LIMIT_EXCEEDED;
        }
        if ((current->measurements == NULL) || (current->measurement_count == 0)) {
            return COMPOSITE_EAT_PROFILE_EVIDENCE_SCHEMA_ERROR;
        }
        for (measurement = 0; measurement < current->measurement_count; ++measurement) {
            if (current->measurements[measurement].values.digest_count >
                policy->max_digests_per_measurement) {
                return COMPOSITE_EAT_PROFILE_EVIDENCE_LIMIT_EXCEEDED;
            }
        }
    }
    if (tcg_concise_evidence_validate(document) != TCG_CONCISE_EVIDENCE_OK) {
        return COMPOSITE_EAT_PROFILE_EVIDENCE_SCHEMA_ERROR;
    }

    for (triple = 0; triple < document->evidence_triple_count; ++triple) {
        const struct tcg_concise_evidence_triple *current = &document->evidence_triples[triple];

        if (!composite_eat_profile_environment_allowed(&current->environment, policy)) {
            return COMPOSITE_EAT_PROFILE_EVIDENCE_POLICY_ERROR;
        }

        for (measurement = 0; measurement < current->measurement_count; ++measurement) {
            if (!composite_eat_profile_measurement_allowed(&current->measurements[measurement],
                                                           policy)) {
                return COMPOSITE_EAT_PROFILE_EVIDENCE_POLICY_ERROR;
            }
            if (!current->measurements[measurement].has_key) {
                continue;
            }
            for (other = measurement + 1; other < current->measurement_count; ++other) {
                if (current->measurements[other].has_key &&
                    composite_eat_profile_mkeys_equal(&current->measurements[measurement].key,
                                                      &current->measurements[other].key)) {
                    return COMPOSITE_EAT_PROFILE_EVIDENCE_POLICY_ERROR;
                }
            }
        }
    }

    size_status = tcg_concise_evidence_get_size(document, encoded_length);
    if (size_status != TCG_CONCISE_EVIDENCE_OK) {
        *encoded_length = 0;
        return COMPOSITE_EAT_PROFILE_EVIDENCE_SCHEMA_ERROR;
    }
    if (*encoded_length > policy->max_encoded_length) {
        return COMPOSITE_EAT_PROFILE_EVIDENCE_LIMIT_EXCEEDED;
    }

    return COMPOSITE_EAT_PROFILE_EVIDENCE_OK;
}
