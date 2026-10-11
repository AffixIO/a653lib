# Optional AffixIO load-time verification for a653lib (A653LIB_AFFIXIO, default OFF).
# Builds standalone too: cmake -S a653_affixio -B build-affixio
cmake_minimum_required(VERSION 3.23)
if(NOT DEFINED PROJECT_NAME)
    project(a653lib_affixio C)
    set(CMAKE_C_STANDARD 99)
    add_compile_options(-Wextra -Wpedantic)
endif()

file(GLOB A653_AFFIXIO_MLDSA_SRC CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/mldsa65/*.c")
add_library(mldsa65_verify STATIC ${A653_AFFIXIO_MLDSA_SRC})
target_include_directories(mldsa65_verify PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/vendor/mldsa65")
target_compile_options(mldsa65_verify PRIVATE -w)
set_target_properties(mldsa65_verify PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(a653lib_affixio STATIC a653_affixio.c)
target_include_directories(a653lib_affixio PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(a653lib_affixio PUBLIC mldsa65_verify)

add_executable(a653_affixio_verify tools/a653_affixio_verify.c)
target_link_libraries(a653_affixio_verify PRIVATE a653lib_affixio)
target_compile_options(a653_affixio_verify PRIVATE -std=gnu99)

add_executable(a653_affixio_test_vectors tests/test_vectors.c)
target_link_libraries(a653_affixio_test_vectors PRIVATE a653lib_affixio)
add_executable(a653_affixio_test_spawn_hook tests/test_spawn_hook.c)
target_link_libraries(a653_affixio_test_spawn_hook PRIVATE a653lib_affixio)

enable_testing()
add_test(NAME affixio_vectors COMMAND a653_affixio_test_vectors)
add_test(NAME affixio_scenarios
         COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_scenarios.sh"
                 "$<TARGET_FILE:a653_affixio_verify>" "$<TARGET_FILE:a653_affixio_test_spawn_hook>"
                 "${CMAKE_CURRENT_SOURCE_DIR}/sidecar")
