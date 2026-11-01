cmake_minimum_required(VERSION 3.16)
project(software_router
    VERSION 1.0.0
    DESCRIPTION "High-Performance Layer 2 / Layer 3 Software Router in C11/C++17 for Linux"
    LANGUAGES C CXX
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(BUILD_TESTS "Build GoogleTest suite" ON)
option(BUILD_BENCHMARKS "Build benchmark targets" ON)

# Strict warning flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wcast-align
        -Wunused
    )
endif()

if(ENABLE_SANITIZERS)
    message(STATUS "Sanitizers ENABLED (-fsanitize=address,undefined)")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Core Router Library
set(ROUTER_SOURCES
    src/core/types.cpp
    src/core/checksum.cpp
    src/parser/ethernet.cpp
    src/parser/ipv4.cpp
    src/routing/lpm_trie.cpp
    src/routing/routing_table.cpp
    src/arp/arp_cache.cpp
    src/forwarding/packet_forwarder.cpp
    src/io/packet_io.cpp
)

add_library(router_core STATIC ${ROUTER_SOURCES})
target_include_directories(router_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Main Executable
add_executable(router_app src/main/main.cpp)
target_link_libraries(router_app PRIVATE router_core pthread)

# Benchmarks
if(BUILD_BENCHMARKS)
    add_executable(router_benchmark benchmarks/routing_benchmarks.cpp)
    target_link_libraries(router_benchmark PRIVATE router_core pthread)
    if(NOT ENABLE_SANITIZERS)
        target_compile_options(router_benchmark PRIVATE -O3 -march=native)
    endif()
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_executable(router_tests
        tests/test_checksum.cpp
        tests/test_ethernet.cpp
        tests/test_ipv4.cpp
        tests/test_lpm_trie.cpp
        tests/test_routing_table.cpp
        tests/test_arp.cpp
        tests/test_packet_forwarder.cpp
        tests/test_malformed.cpp
    )
    target_link_libraries(router_tests PRIVATE router_core gtest_main pthread)
    add_test(NAME AllRouterTests COMMAND router_tests)
endif()
