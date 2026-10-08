# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.20)
project(bmc_composite_eat_sdk VERSION 0.8.0 LANGUAGES C)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

option(BMC_COMPOSITE_EAT_BUILD_EXAMPLES "Compile RoT and optional spdmd examples" OFF)
option(BMC_COMPOSITE_EAT_BUILD_TESTS "Build SDK tests" OFF)
option(BMC_COMPOSITE_EAT_BUILD_FUZZERS "Build Clang libFuzzer sanitizer targets" OFF)
set(BMC_COMPOSITE_EAT_SPDMD_SOURCE_DIR "" CACHE PATH
    "Path to the spdmd directory containing platform_attester.hpp")
set(BMC_COMPOSITE_EAT_TCG_CDDL_SOURCE_DIR "" CACHE PATH
    "Path to pinned TrustedComputingGroup/dice-coev source")
set(BMC_COMPOSITE_EAT_CDDLC "" CACHE FILEPATH "Path to cddlc 0.4.5")
set(BMC_COMPOSITE_EAT_CDDL "" CACHE FILEPATH "Path to cddl 0.12.14")

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(
    qcbor_vendor
    STATIC
        third_party/qcbor/src/UsefulBuf.c
        third_party/qcbor/src/ieee754.c
        third_party/qcbor/src/qcbor_decode.c
        third_party/qcbor/src/qcbor_encode.c
        third_party/qcbor/src/qcbor_err_to_str.c
)
target_include_directories(
    qcbor_vendor
    PRIVATE
        third_party/qcbor/inc
        third_party/qcbor/inc/qcbor
)
target_compile_definitions(
    qcbor_vendor
    PRIVATE
        QCBOR_DISABLE_FLOAT_HW_USE
        QCBOR_DISABLE_PREFERRED_FLOAT
        USEFULBUF_DISABLE_ALL_FLOAT
        QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
        QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
)

add_library(
    bmc_composite_eat
    src/types.c
    src/token_builder.c
)
add_library(bmc::composite_eat ALIAS bmc_composite_eat)
set_target_properties(bmc_composite_eat PROPERTIES EXPORT_NAME composite_eat)

target_include_directories(
    bmc_composite_eat
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/qcbor/inc
)
target_link_libraries(bmc_composite_eat PRIVATE qcbor_vendor)
target_compile_definitions(
    bmc_composite_eat
    PRIVATE
        QCBOR_DISABLE_FLOAT_HW_USE
        QCBOR_DISABLE_PREFERRED_FLOAT
        USEFULBUF_DISABLE_ALL_FLOAT
        QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
        QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
)
target_compile_options(bmc_composite_eat PRIVATE -Wall -Wextra -Werror -Wpedantic)

add_library(bmc_composite_eat_generation_request src/generation_request.c)
add_library(bmc::generation_request ALIAS bmc_composite_eat_generation_request)
set_target_properties(
    bmc_composite_eat_generation_request
    PROPERTIES EXPORT_NAME generation_request
)
target_include_directories(
    bmc_composite_eat_generation_request
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/qcbor/inc
)
target_link_libraries(
    bmc_composite_eat_generation_request
    PUBLIC bmc_composite_eat
    PRIVATE qcbor_vendor
)
target_compile_definitions(
    bmc_composite_eat_generation_request
    PRIVATE
        QCBOR_DISABLE_FLOAT_HW_USE
        QCBOR_DISABLE_PREFERRED_FLOAT
        USEFULBUF_DISABLE_ALL_FLOAT
        QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
        QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
)
target_compile_options(
    bmc_composite_eat_generation_request
    PRIVATE -Wall -Wextra -Werror -Wpedantic
)

add_library(
    bmc_composite_eat_tcg_concise_evidence
    src/tcg_concise_evidence.c
    src/profile_evidence.c
    src/reference_policy.c
)
add_library(bmc::tcg_concise_evidence ALIAS bmc_composite_eat_tcg_concise_evidence)
set_target_properties(
    bmc_composite_eat_tcg_concise_evidence
    PROPERTIES EXPORT_NAME tcg_concise_evidence
)
target_include_directories(
    bmc_composite_eat_tcg_concise_evidence
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/qcbor/inc
)
target_link_libraries(
    bmc_composite_eat_tcg_concise_evidence
    PUBLIC bmc_composite_eat
    PRIVATE qcbor_vendor
)
target_compile_definitions(
    bmc_composite_eat_tcg_concise_evidence
    PRIVATE
        QCBOR_DISABLE_FLOAT_HW_USE
        QCBOR_DISABLE_PREFERRED_FLOAT
        USEFULBUF_DISABLE_ALL_FLOAT
        QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
        QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
)
target_compile_options(
    bmc_composite_eat_tcg_concise_evidence
    PRIVATE -Wall -Wextra -Werror -Wpedantic
)

if(BMC_COMPOSITE_EAT_BUILD_EXAMPLES)
    add_library(
        bmc_composite_eat_rot_examples
        OBJECT
            examples/rot/evidence_provider_skeleton.c
            examples/rot/attestation_provider_skeleton.c
            examples/rot/software_platform.c
    )
    target_include_directories(
        bmc_composite_eat_rot_examples
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/examples/rot
    )
    target_compile_options(
        bmc_composite_eat_rot_examples
        PRIVATE
            -Wall
            -Wextra
            -Werror
            -Wpedantic
    )
    target_link_libraries(
        bmc_composite_eat_rot_examples
        PRIVATE bmc::composite_eat bmc::tcg_concise_evidence
    )

    if(BMC_COMPOSITE_EAT_SPDMD_SOURCE_DIR)
        if(NOT EXISTS "${BMC_COMPOSITE_EAT_SPDMD_SOURCE_DIR}/platform_attester.hpp")
            message(FATAL_ERROR
                "BMC_COMPOSITE_EAT_SPDMD_SOURCE_DIR must contain platform_attester.hpp")
        endif()

        enable_language(CXX)
        set(CMAKE_CXX_STANDARD 20)
        set(CMAKE_CXX_STANDARD_REQUIRED ON)
        set(CMAKE_CXX_EXTENSIONS OFF)

        add_library(
            bmc_composite_eat_spdmd_adapter_example
            STATIC
                examples/spdmd/rot_platform_attester.cpp
        )
        target_include_directories(
            bmc_composite_eat_spdmd_adapter_example
            PUBLIC
                ${CMAKE_CURRENT_SOURCE_DIR}/examples/spdmd
                ${BMC_COMPOSITE_EAT_SPDMD_SOURCE_DIR}
            PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(
            bmc_composite_eat_spdmd_adapter_example
            PUBLIC bmc::generation_request
        )
        target_compile_options(
            bmc_composite_eat_spdmd_adapter_example
            PRIVATE
                -Wall
                -Wextra
                -Werror
                -Wpedantic
        )

        add_library(
            bmc_composite_eat_spdmd_transport_example
            OBJECT
                examples/spdmd/platform_transport_skeleton.cpp
        )
        target_include_directories(
            bmc_composite_eat_spdmd_transport_example
            PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/examples/spdmd
        )
        target_compile_options(
            bmc_composite_eat_spdmd_transport_example
            PRIVATE
                -Wall
                -Wextra
                -Werror
                -Wpedantic
        )
    endif()
endif()

install(
    TARGETS bmc_composite_eat bmc_composite_eat_generation_request
            bmc_composite_eat_tcg_concise_evidence qcbor_vendor
    EXPORT bmcCompositeEatTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/composite_eat DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(
    EXPORT bmcCompositeEatTargets
    FILE bmcCompositeEatTargets.cmake
    NAMESPACE bmc::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bmcCompositeEat
)
configure_package_config_file(
    cmake/bmcCompositeEatConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/bmcCompositeEatConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bmcCompositeEat
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/bmcCompositeEatConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/bmcCompositeEatConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/bmcCompositeEatConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bmcCompositeEat
)
install(DIRECTORY docs DESTINATION ${CMAKE_INSTALL_DATADIR}/bmc-composite-eat)
install(DIRECTORY LICENSES DESTINATION ${CMAKE_INSTALL_DATADIR}/bmc-composite-eat)
install(
    FILES LICENSE LICENSING.md THIRD_PARTY_NOTICES.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/bmc-composite-eat
)

if(BMC_COMPOSITE_EAT_BUILD_TESTS)
    enable_testing()
    enable_language(CXX)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
    find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)

    add_executable(test_check_test tests/test_check_test.c)
    target_compile_definitions(test_check_test PRIVATE NDEBUG)
    target_compile_options(test_check_test PRIVATE -Wall -Wextra -Werror -Wpedantic)
    add_test(NAME test_check_success COMMAND test_check_test)
    add_test(NAME test_check_failure COMMAND test_check_test --fail)
    set_tests_properties(test_check_failure PROPERTIES WILL_FAIL TRUE)

    add_executable(generation_request_test tests/generation_request_test.c)
    target_link_libraries(generation_request_test PRIVATE bmc::generation_request)
    target_compile_options(generation_request_test PRIVATE -Wall -Wextra -Werror -Wpedantic)
    add_test(NAME generation_request_test COMMAND generation_request_test)

    add_executable(token_builder_test tests/token_builder_test.c)
    target_link_libraries(token_builder_test PRIVATE bmc::composite_eat)
    target_compile_options(token_builder_test PRIVATE -Wall -Wextra -Werror -Wpedantic)
    add_test(NAME token_builder_test COMMAND token_builder_test)

    add_executable(tcg_concise_evidence_test tests/tcg_concise_evidence_test.c)
    target_link_libraries(
        tcg_concise_evidence_test
        PRIVATE bmc::tcg_concise_evidence
    )
    target_compile_options(
        tcg_concise_evidence_test
        PRIVATE -Wall -Wextra -Werror -Wpedantic
    )
    add_test(NAME tcg_concise_evidence_test COMMAND tcg_concise_evidence_test)

    add_executable(reference_policy_test tests/reference_policy_test.c)
    target_link_libraries(
        reference_policy_test
        PRIVATE bmc::tcg_concise_evidence bmc::composite_eat
    )
    target_compile_options(reference_policy_test PRIVATE -Wall -Wextra -Werror -Wpedantic)
    add_test(NAME reference_policy_test COMMAND reference_policy_test)

    if(BMC_COMPOSITE_EAT_TCG_CDDL_SOURCE_DIR)
        if(NOT BMC_COMPOSITE_EAT_CDDLC OR NOT BMC_COMPOSITE_EAT_CDDL)
            message(FATAL_ERROR
                "BMC_COMPOSITE_EAT_CDDLC and BMC_COMPOSITE_EAT_CDDL are required "
                "with BMC_COMPOSITE_EAT_TCG_CDDL_SOURCE_DIR")
        endif()
        add_test(
            NAME validate_tcg_concise_evidence_cddl
            COMMAND
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/validate_tcg_cddl.sh
                $<TARGET_FILE:tcg_concise_evidence_test>
                ${BMC_COMPOSITE_EAT_TCG_CDDL_SOURCE_DIR}
                ${BMC_COMPOSITE_EAT_CDDLC}
                ${BMC_COMPOSITE_EAT_CDDL}
                ${Python3_EXECUTABLE}
        )
        set_tests_properties(
            validate_tcg_concise_evidence_cddl
            PROPERTIES DEPENDS tcg_concise_evidence_test
        )
    endif()

    add_executable(cpp_api_test tests/cpp_api_test.cpp)
    target_link_libraries(cpp_api_test PRIVATE bmc::generation_request)
    target_compile_options(cpp_api_test PRIVATE -Wall -Wextra -Werror -Wpedantic)
    add_test(NAME cpp_api_test COMMAND cpp_api_test)

    if(TARGET bmc_composite_eat_rot_examples)
        add_executable(
            rot_platform_example_test
            tests/rot_platform_example_test.c
            $<TARGET_OBJECTS:bmc_composite_eat_rot_examples>
        )
        target_include_directories(
            rot_platform_example_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/examples/rot
        )
        target_link_libraries(
            rot_platform_example_test
            PRIVATE bmc::composite_eat bmc::tcg_concise_evidence
        )
        target_compile_options(
            rot_platform_example_test
            PRIVATE -Wall -Wextra -Werror -Wpedantic
        )
        add_test(NAME rot_platform_example_test COMMAND rot_platform_example_test)

    endif()

    if(TARGET bmc_composite_eat_spdmd_adapter_example)
        add_executable(spdmd_adapter_test tests/spdmd_adapter_test.cpp)
        target_link_libraries(
            spdmd_adapter_test
            PRIVATE bmc_composite_eat_spdmd_adapter_example
        )
        target_compile_options(
            spdmd_adapter_test
            PRIVATE -Wall -Wextra -Werror -Wpedantic
        )
        add_test(NAME spdmd_adapter_test COMMAND spdmd_adapter_test)
    endif()

    add_executable(generate_test_token tests/generate_test_token.c)
    target_link_libraries(
        generate_test_token
        PRIVATE
            bmc::composite_eat
            bmc::tcg_concise_evidence
            OpenSSL::Crypto
    )
    target_compile_options(generate_test_token PRIVATE -Wall -Wextra -Werror -Wpedantic)
    add_test(
        NAME generate_test_token
        COMMAND generate_test_token
            ${CMAKE_CURRENT_BINARY_DIR}/synthetic-token.cbor
            ${CMAKE_CURRENT_BINARY_DIR}/synthetic-anchor.der
    )
    if(BMC_COMPOSITE_EAT_TCG_CDDL_SOURCE_DIR)
        add_test(
            NAME validate_reference_vector_tcg_cddl
            COMMAND
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/validate_tcg_cddl.sh
                $<TARGET_FILE:generate_test_token>
                ${BMC_COMPOSITE_EAT_TCG_CDDL_SOURCE_DIR}
                ${BMC_COMPOSITE_EAT_CDDLC}
                ${BMC_COMPOSITE_EAT_CDDL}
                ${Python3_EXECUTABLE}
                reference-token
        )
            add_test(
                NAME validate_published_reference_vector_tcg_cddl
                COMMAND
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/validate_tcg_cddl.sh
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/synthetic-token.cbor
                ${BMC_COMPOSITE_EAT_TCG_CDDL_SOURCE_DIR}
                ${BMC_COMPOSITE_EAT_CDDLC}
                ${BMC_COMPOSITE_EAT_CDDL}
                ${Python3_EXECUTABLE}
                reference-token-file
            )
    endif()
    add_test(
        NAME verify_test_token
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/verify.py
            ${CMAKE_CURRENT_BINARY_DIR}/synthetic-token.cbor
            ${CMAKE_CURRENT_BINARY_DIR}/synthetic-anchor.der
    )
    set_tests_properties(verify_test_token PROPERTIES DEPENDS generate_test_token)

    add_test(
        NAME verify_published_vector
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/verify.py
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/synthetic-token.cbor
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/synthetic-anchor.der
    )
    add_test(
        NAME verify_negative_cases
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/verify_negative_test.py
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/synthetic-token.cbor
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/synthetic-anchor.der
    )
endif()

if(BMC_COMPOSITE_EAT_BUILD_FUZZERS)
    enable_testing()
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "BMC_COMPOSITE_EAT_BUILD_FUZZERS requires Clang with libFuzzer")
    endif()
    foreach(library IN ITEMS qcbor_vendor bmc_composite_eat
                             bmc_composite_eat_generation_request
                             bmc_composite_eat_tcg_concise_evidence)
        target_compile_options(${library} PRIVATE
            -fsanitize=fuzzer-no-link,address,undefined
            -fno-sanitize-recover=all -fno-omit-frame-pointer)
        target_link_options(${library} INTERFACE -fsanitize=address,undefined)
    endforeach()
    add_subdirectory(tests/fuzz)
endif()
