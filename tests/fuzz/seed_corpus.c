// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

#include "fuzz_helpers.h"

static void make_directory(const char *path) {
    if (mkdir(path, 0700) != 0) {
        fuzz_check(errno == EEXIST);
    }
}

static void write_seed(const char *root, const char *group, const char *name, const uint8_t *data,
                       size_t length) {
    char path[1024];
    int path_length = snprintf(path, sizeof(path), "%s/%s", root, group);
    fuzz_check(path_length > 0 && (size_t)path_length < sizeof(path));
    make_directory(path);
    path_length = snprintf(path, sizeof(path), "%s/%s/%s", root, group, name);
    fuzz_check(path_length > 0 && (size_t)path_length < sizeof(path));
    FILE *output = fopen(path, "wb");
    fuzz_check(output != NULL);
    size_t written = fwrite(data, 1u, length, output);
    int close_status = fclose(output);
    fuzz_check(written == length && close_status == 0);
}

int main(int argc, char **argv) {
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        puts("Usage: fuzz_seed_corpus DIRECTORY\n"
             "Create/overwrite synthetic fuzz seeds in DIRECTORY; parent must exist.\n"
             "Uses the SDK request encoder. No elevated privileges or device access required.");
        return 0;
    }
    if (argc != 2 || argv[1][0] == '-') {
        fputs("Usage: fuzz_seed_corpus DIRECTORY\n", stderr);
        return 2;
    }
    make_directory(argv[1]);
    struct composite_eat_generation_request request;
    uint8_t encoded[COMPOSITE_EAT_MAX_GENERATION_REQUEST_LENGTH + 1u];
    uint8_t structured[128] = {0};
    size_t encoded_length = 0u;
    fuzz_make_request(&request);
    fuzz_check(composite_eat_generation_request_encode(&request, encoded, sizeof(encoded),
                                                       &encoded_length) == COMPOSITE_EAT_OK);
    write_seed(argv[1], "generation_request", "valid-one", encoded, encoded_length);
    write_seed(argv[1], "generation_request", "truncated", encoded, encoded_length - 1u);
    encoded[encoded_length] = 0u;
    write_seed(argv[1], "generation_request", "trailing", encoded, encoded_length + 1u);
    request.record_count = COMPOSITE_EAT_MAX_DEVICE_RECORDS;
    for (size_t index = 0u; index < request.record_count; ++index) {
        int length = snprintf((char *)request.records[index].environment,
                              sizeof(request.records[index].environment), "env.device.%zu", index);
        fuzz_check(length > 0 && (size_t)length < sizeof(request.records[index].environment));
        request.records[index].environment_length = (size_t)length;
    }
    fuzz_check(composite_eat_generation_request_encode(&request, encoded, sizeof(encoded),
                                                       &encoded_length) == COMPOSITE_EAT_OK);
    write_seed(argv[1], "generation_request", "valid-max", encoded, encoded_length);
    write_seed(argv[1], "evidence", "valid-basic", structured, sizeof(structured));
    memset(structured, 0xff, sizeof(structured));
    write_seed(argv[1], "evidence", "invalid-fields", structured, sizeof(structured));
    for (unsigned mode = 0u; mode < 5u; ++mode) {
        uint8_t sequence[] = {0u, 2u, 0u, 1u, 2u, 3u, 5u, 2u, 4u, 2u, 6u, 2u, 7u, 8u};
        char name[16];
        sequence[0] = mode == 0u ? 0u : (uint8_t)(8u | ((mode - 1u) << 4u));
        fuzz_check(snprintf(name, sizeof(name), "mode-%u", mode) > 0);
        write_seed(argv[1], "token_builder", name, sequence, sizeof(sequence));
    }
    return 0;
}
