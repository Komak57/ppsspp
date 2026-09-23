cmake_minimum_required (VERSION 3.10.0)
project (mbedtls)

# Build mbedtls (2.28.x) directly from source, PPSSPP-style (see zstd-build,
# miniupnp-build). Using upstream's own CMake pulls in its programs/tests by
# default - including a cmake_minimum_required(2.6) subproject that hard-errors
# on CMake >= 4, perl-driven test generation that breaks NMake on Windows, and
# per-compiler warning flags that trip -Werror on clang (Android/libretro).
# Compiling the library sources ourselves sidesteps all of it.

set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../mbedtls)

file(GLOB MBEDTLS_SOURCES ${SRC_DIR}/library/*.c)

add_library(mbedtls STATIC ${MBEDTLS_SOURCES})
target_include_directories(mbedtls PUBLIC ${SRC_DIR}/include)
target_include_directories(mbedtls PRIVATE ${SRC_DIR}/library)

# Third-party code: not our warnings to fix. Keeps -Werror CI jobs quiet
# regardless of compiler (gcc/clang/msvc) and their differing warning sets.
if (MSVC)
	target_compile_options(mbedtls PRIVATE /w)
else()
	target_compile_options(mbedtls PRIVATE -w)
endif()

# Compatibility aliases: existing link lines reference mbedtls, mbedx509 and
# mbedcrypto (upstream splits into three libs; we build one combined static).
add_library(mbedx509 INTERFACE)
target_link_libraries(mbedx509 INTERFACE mbedtls)
add_library(mbedcrypto INTERFACE)
target_link_libraries(mbedcrypto INTERFACE mbedtls)
