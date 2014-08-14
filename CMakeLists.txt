cmake_minimum_required(VERSION 2.8)
project(VigorTLS)

include(CTest)

# Set to FALSE if you don't want
# to use ASM (not recommended).
set(USE_ASM TRUE)

if (CMAKE_COMPILER_IS_GNUCC OR "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -ggdb -std=gnu99")
else()
	message(FATAL_ERROR "Unsupported compiler:" ${CMAKE_C_COMPILER})
endif()

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
	set(ARCH "x86_64")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86")
	set(ARCH "x86")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i686")
	set(ARCH "x86")
else()
	message(FATAL_ERROR "Unsupported processor:" ${CMAKE_SYSTEM_PROCESSOR})
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	add_definitions(-D_GNU_SOURCE)
endif()

if (${USE_ASM})
	set(ASM_C_FLAGS "
#define OPENSSL_BN_ASM_MONT
#define OPENSSL_IA32_SSE2"
)
if (${ARCH} STREQUAL "x86_64")
	set(ASM_C_FLAGS "
#define OPENSSL_BN_ASM_MONT5
#define OPENSSL_BN_ASM_GF2m"
)
endif()
else()
	set(ASM_C_FLAGS "#define OPENSSL_NO_ASM")
endif()

file(READ crypto/openssldefines.h.in CONF)
set(CONF "${CONF} ${ASM_C_FLAGS}")
file(WRITE include/openssl/openssldefines.h "${CONF}")

# read openssldefines.h
file(STRINGS include/openssl/openssldefines.h CONFIGUREARGS)
# replace #define OPENSSL_FOO with -DOPENSSL_FOO
string(REPLACE "#define " " -D" CONFIGUREARGS ${CONFIGUREARGS})
# Replace newlines.
string(REGEX REPLACE "(\r?\n)+$" "" CONFIGUREARGS "${CONFIGUREARGS}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CONFIGUREARGS}")

add_subdirectory(crypto)
add_subdirectory(ssl)
add_subdirectory(apps)
add_subdirectory(tests)
