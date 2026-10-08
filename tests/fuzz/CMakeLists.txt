# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
foreach(name IN ITEMS generation_request evidence token_builder)
    add_executable(${name}_fuzz ${name}_fuzz.c)
    target_link_libraries(${name}_fuzz PRIVATE
        bmc::generation_request bmc::tcg_concise_evidence)
    target_compile_options(${name}_fuzz PRIVATE
        -Wall -Wextra -Werror -Wpedantic
        -fsanitize=fuzzer,address,undefined
        -fno-sanitize-recover=all -fno-omit-frame-pointer)
    target_link_options(${name}_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
    add_test(NAME ${name}_fuzz_smoke COMMAND ${name}_fuzz
        "${CMAKE_CURRENT_BINARY_DIR}/corpus/${name}"
        -runs=1000 -seed=20260929 -max_len=8193 -timeout=2 -rss_limit_mb=512
        -create_missing_dirs=1
        "-artifact_prefix=${CMAKE_CURRENT_BINARY_DIR}/artifacts/${name}/")
    set_tests_properties(${name}_fuzz_smoke PROPERTIES
        TIMEOUT 30 FIXTURES_REQUIRED fuzz_corpus)
endforeach()

add_executable(fuzz_seed_corpus seed_corpus.c)
target_link_libraries(fuzz_seed_corpus PRIVATE bmc::generation_request)
target_compile_options(fuzz_seed_corpus PRIVATE
    -Wall -Wextra -Werror -Wpedantic
    -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all)
target_link_options(fuzz_seed_corpus PRIVATE -fsanitize=fuzzer-no-link,address,undefined)

add_test(NAME fuzz_seed_corpus_setup
    COMMAND fuzz_seed_corpus "${CMAKE_CURRENT_BINARY_DIR}/corpus")
set_tests_properties(fuzz_seed_corpus_setup PROPERTIES TIMEOUT 30 FIXTURES_SETUP fuzz_corpus)
