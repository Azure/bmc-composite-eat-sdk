// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "test_check.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "composite_eat/reference_policy.h"
#include "composite_eat/token_builder.h"

static EVP_PKEY *generate_key(void) {
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY *key = NULL;

    TEST_CHECK(context != NULL);
    TEST_CHECK(EVP_PKEY_keygen_init(context) == 1);
    TEST_CHECK(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_secp384r1) == 1);
    TEST_CHECK(EVP_PKEY_keygen(context, &key) == 1);
    EVP_PKEY_CTX_free(context);
    return key;
}

static void add_extension(X509 *certificate, X509 *issuer, int nid, const char *value) {
    X509V3_CTX context;
    X509_EXTENSION *extension;

    X509V3_set_ctx(&context, issuer, certificate, NULL, NULL, 0);
    extension = X509V3_EXT_conf_nid(NULL, &context, nid, value);
    TEST_CHECK(extension != NULL);
    TEST_CHECK(X509_add_ext(certificate, extension, -1) == 1);
    X509_EXTENSION_free(extension);
}

static X509 *generate_certificate(EVP_PKEY *subject_key, const char *common_name, long serial,
                                  X509 *issuer, EVP_PKEY *issuer_key, bool is_ca) {
    X509 *certificate = X509_new();
    X509_NAME *name;

    TEST_CHECK(certificate != NULL);
    TEST_CHECK(X509_set_version(certificate, 2) == 1);
    TEST_CHECK(ASN1_INTEGER_set(X509_get_serialNumber(certificate), serial) == 1);
    TEST_CHECK(X509_gmtime_adj(X509_getm_notBefore(certificate), -300) != NULL);
    TEST_CHECK(X509_gmtime_adj(X509_getm_notAfter(certificate), 315360000L) != NULL);
    TEST_CHECK(X509_set_pubkey(certificate, subject_key) == 1);
    name = X509_get_subject_name(certificate);
    TEST_CHECK(name != NULL);
    TEST_CHECK(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                          (const unsigned char *)common_name, -1, -1, 0) == 1);
    TEST_CHECK(X509_set_issuer_name(certificate,
                                    (issuer == NULL) ? name : X509_get_subject_name(issuer)) == 1);
    add_extension(certificate, (issuer == NULL) ? certificate : issuer, NID_basic_constraints,
                  is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    add_extension(certificate, (issuer == NULL) ? certificate : issuer, NID_key_usage,
                  is_ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature");
    TEST_CHECK(
        X509_sign(certificate, (issuer_key == NULL) ? subject_key : issuer_key, EVP_sha384()) > 0);
    return certificate;
}

static uint8_t *certificate_der(X509 *certificate, size_t *length) {
    int encoded_length = i2d_X509(certificate, NULL);
    uint8_t *encoded;
    unsigned char *cursor;

    TEST_CHECK(encoded_length > 0);
    encoded = malloc((size_t)encoded_length);
    TEST_CHECK(encoded != NULL);
    cursor = encoded;
    TEST_CHECK(i2d_X509(certificate, &cursor) == encoded_length);
    *length = (size_t)encoded_length;
    return encoded;
}

static void sign_digest(EVP_PKEY *key, const uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH],
                        uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH]) {
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new(key, NULL);
    uint8_t der[128];
    size_t der_length = sizeof(der);
    const unsigned char *cursor;
    ECDSA_SIG *decoded;
    const BIGNUM *r;
    const BIGNUM *s;

    TEST_CHECK(context != NULL);
    TEST_CHECK(EVP_PKEY_sign_init(context) == 1);
    TEST_CHECK(EVP_PKEY_CTX_set_signature_md(context, EVP_sha384()) == 1);
    TEST_CHECK(EVP_PKEY_sign(context, der, &der_length, digest, COMPOSITE_EAT_SHA384_LENGTH) == 1);
    cursor = der;
    decoded = d2i_ECDSA_SIG(NULL, &cursor, (long)der_length);
    TEST_CHECK(decoded != NULL);
    ECDSA_SIG_get0(decoded, &r, &s);
    TEST_CHECK(BN_bn2binpad(r, signature, COMPOSITE_EAT_SHA384_LENGTH) ==
               COMPOSITE_EAT_SHA384_LENGTH);
    TEST_CHECK(BN_bn2binpad(s, &signature[COMPOSITE_EAT_SHA384_LENGTH],
                            COMPOSITE_EAT_SHA384_LENGTH) == COMPOSITE_EAT_SHA384_LENGTH);
    ECDSA_SIG_free(decoded);
    EVP_PKEY_CTX_free(context);
}

static void write_file(const char *path, const uint8_t *data, size_t length) {
    FILE *output = fopen(path, "wb");
    size_t written;
    int close_status;

    TEST_CHECK(output != NULL);
    written = fwrite(data, 1u, length, output);
    close_status = fclose(output);
    TEST_CHECK(written == length);
    TEST_CHECK(close_status == 0);
}

static int write_hash(void *context, const uint8_t *data, size_t length) {
    return (EVP_DigestUpdate(context, data, length) == 1) ? 0 : -1;
}

static int approve_synthetic_evidence(void *context,
                                      const struct tcg_concise_evidence_document *document) {
    return (context == document) ? 0 : -1;
}

int main(int argc, char **argv) {
    static const uint8_t profile[] = COMPOSITE_EAT_IETF_DRAFT_00_PROFILE_URI;
    static const uint8_t ueid[] = {0x01, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                                   0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
    static const uint8_t class_id[] = "reference-rot";
    static const uint8_t vendor[] = "Example Vendor";
    static const uint8_t model[] = "Reference RoT";
    uint8_t measurement_digest[TCG_CONCISE_EVIDENCE_SHA384_LENGTH];
    uint8_t local_bytes[256];
    size_t local_bytes_length = 0u;
    struct tcg_concise_evidence_digest ce_digest = {
        {TCG_CONCISE_EVIDENCE_ALGORITHM_SHA384, {0}},
        {measurement_digest, sizeof(measurement_digest)}};
    struct tcg_concise_evidence_measurement measurement = {
        .has_key = true,
        .key = {TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UINT, {.uint_value = 0u}},
        .values = {&ce_digest, 1u, false, {0}, true, {model, sizeof(model) - 1u}},
    };
    struct tcg_concise_evidence_triple triple = {
        .environment =
            {
                .has_class = true,
                .class_info =
                    {
                        .has_class_id = true,
                        .class_id = {TCG_CONCISE_EVIDENCE_TAGGED_BYTES,
                                     {class_id, sizeof(class_id) - 1u}},
                        .has_vendor = true,
                        .vendor = {vendor, sizeof(vendor) - 1u},
                        .has_model = true,
                        .model = {model, sizeof(model) - 1u},
                    },
            },
        .measurements = &measurement,
        .measurement_count = 1u,
    };
    struct tcg_concise_evidence_document document = {&triple, 1u};
    const struct composite_eat_profile_evidence_policy policy = {
        .max_triples = 1u,
        .max_measurements_per_triple = 1u,
        .max_digests_per_measurement = 1u,
        .max_identifier_length = 64u,
        .max_text_length = 64u,
        .max_encoded_length = sizeof(local_bytes),
        .allowed_mkey_types = COMPOSITE_EAT_PROFILE_MKEY_UINT,
        .allowed_algorithms = COMPOSITE_EAT_PROFILE_ALGORITHM_SHA384,
        .require_measurement_key = true,
        .require_class = true,
        .require_class_id = true,
        .require_vendor = true,
        .require_model = true,
        .allow_name = true,
    };
    const struct composite_eat_reference_evidence reference_evidence = {
        &document, &policy, &document, approve_synthetic_evidence};
    struct composite_eat_generation_request request = {0};
    struct composite_eat_local_evidence local_evidence = {0};
    struct composite_eat_evidence_snapshot evidence;
    struct composite_eat_der_certificate der_certificates[2];
    struct composite_eat_attestation_identity identity;
    struct composite_eat_workspace workspace;
    struct composite_eat_prepared prepared;
    EVP_PKEY *root_key;
    EVP_PKEY *leaf_key;
    X509 *root_certificate;
    X509 *leaf_certificate;
    EVP_MD_CTX *hash_context;
    uint8_t *root_der;
    uint8_t *leaf_der;
    size_t root_der_length;
    size_t leaf_der_length;
    uint8_t leaf_thumbprint[COMPOSITE_EAT_SHA384_LENGTH];
    unsigned int leaf_thumbprint_length = 0u;
    uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH];
    unsigned int digest_length = 0u;
    uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH];
    uint8_t response[COMPOSITE_EAT_PAYLOAD_MAX + 2048u];
    size_t response_length;

    TEST_CHECK(argc == 3);
    memset(measurement_digest, 0x38, sizeof(measurement_digest));
    TEST_CHECK(tcg_concise_evidence_encode(&document, local_bytes, sizeof(local_bytes),
                                           &local_bytes_length) == TCG_CONCISE_EVIDENCE_OK);
    root_key = generate_key();
    leaf_key = generate_key();
    root_certificate =
        generate_certificate(root_key, "Synthetic Attestation Root", 1, NULL, NULL, true);
    leaf_certificate = generate_certificate(leaf_key, "Synthetic RoT Attestation", 2,
                                            root_certificate, root_key, false);
    root_der = certificate_der(root_certificate, &root_der_length);
    leaf_der = certificate_der(leaf_certificate, &leaf_der_length);
    TEST_CHECK(EVP_Digest(leaf_der, leaf_der_length, leaf_thumbprint, &leaf_thumbprint_length,
                          EVP_sha384(), NULL) == 1);
    TEST_CHECK(leaf_thumbprint_length == COMPOSITE_EAT_SHA384_LENGTH);

    request.version = COMPOSITE_EAT_GENERATION_REQUEST_VERSION;
    request.nonce_length = COMPOSITE_EAT_NONCE_LENGTH;
    memset(request.nonce, 0x5a, request.nonce_length);
    memcpy(request.records[0].environment, "env.device.0", sizeof("env.device.0") - 1u);
    request.records[0].environment_length = sizeof("env.device.0") - 1u;
    memset(request.records[0].digest, 0xa5, sizeof(request.records[0].digest));
    request.record_count = 1u;
    local_evidence.content_format = COMPOSITE_EAT_TCG_CONCISE_EVIDENCE_CONTENT_FORMAT;
    local_evidence.encoded = (struct composite_eat_buffer){local_bytes, local_bytes_length};
    evidence.ueid = (struct composite_eat_buffer){ueid, sizeof(ueid)};
    evidence.profile = (struct composite_eat_buffer){profile, sizeof(profile) - 1u};
    evidence.local_evidence = &local_evidence;
    evidence.local_evidence_count = 1u;
    der_certificates[0] = (struct composite_eat_der_certificate){leaf_der, leaf_der_length};
    der_certificates[1] = (struct composite_eat_der_certificate){root_der, root_der_length};
    identity.certificates = der_certificates;
    identity.certificate_count = 2u;

    TEST_CHECK(composite_eat_reference_policy_validate_snapshot(
                   &evidence, &reference_evidence, 1u) == COMPOSITE_EAT_REFERENCE_POLICY_OK);

    TEST_CHECK(composite_eat_prepare(&request, &evidence, &identity, leaf_thumbprint, &workspace,
                                     &prepared) == COMPOSITE_EAT_OK);
    hash_context = EVP_MD_CTX_new();
    TEST_CHECK(hash_context != NULL);
    TEST_CHECK(EVP_DigestInit_ex(hash_context, EVP_sha384(), NULL) == 1);
    TEST_CHECK(composite_eat_write_signing_input(&prepared, write_hash, hash_context) ==
               COMPOSITE_EAT_OK);
    TEST_CHECK(EVP_DigestFinal_ex(hash_context, digest, &digest_length) == 1);
    TEST_CHECK(digest_length == COMPOSITE_EAT_SHA384_LENGTH);
    EVP_MD_CTX_free(hash_context);

    sign_digest(leaf_key, digest, signature);
    TEST_CHECK(composite_eat_finish(&prepared, signature, response, sizeof(response),
                                    &response_length) == COMPOSITE_EAT_OK);
    write_file(argv[1], response, response_length);
    write_file(argv[2], root_der, root_der_length);

    free(leaf_der);
    free(root_der);
    X509_free(leaf_certificate);
    X509_free(root_certificate);
    EVP_PKEY_free(leaf_key);
    EVP_PKEY_free(root_key);
    return 0;
}
