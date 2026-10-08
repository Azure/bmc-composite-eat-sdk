# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
cmake_minimum_required(VERSION 3.20)
project(bmc_composite_eat_install_test LANGUAGES CXX)

find_package(bmcCompositeEat CONFIG REQUIRED)
add_executable(installed_consumer ../cpp_api_test.cpp)
target_link_libraries(installed_consumer PRIVATE bmc::generation_request)
target_compile_features(installed_consumer PRIVATE cxx_std_20)
target_compile_options(installed_consumer PRIVATE -Wall -Wextra -Werror -Wpedantic)

enable_testing()
add_test(NAME installed_consumer COMMAND installed_consumer)