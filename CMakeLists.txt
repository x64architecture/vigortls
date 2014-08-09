cmake_minimum_required(VERSION 2.8)
project(VigorTLS)

include(CTest)

if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -ggdb -std=gnu99")
else()
	message(FATAL_ERROR "Unsupported compiler:" ${CMAKE_C_COMPILER})
endif()

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
	set(ARCH "x86_64")

	add_definitions(
		-DOPENSSL_IA32_SSE2
		-DOPENSSL_BN_ASM_MONT
		-DOPENSSL_BN_ASM_MONT5
		-DOPENSSL_BN_ASM_GF2m
	)
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86")
	set(ARCH "x86")
else()
	message(FATAL_ERROR "Unsupported processor:" ${CMAKE_SYSTEM_PROCESSOR})
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
	add_definitions(-D_GNU_SOURCE)
endif()

# read openssldefines.h
file(STRINGS include/openssl/openssldefines.h CONFIGUREARGS)
# replace #define OPENSSL_FOO with -DOPENSSL_FOO
string(REPLACE "#define " " -D" CONFIGUREARGS ${CONFIGUREARGS})
# Replace newlines.
# TODO: Why doesn't REPLACE work with anything other than ""?
string(REGEX REPLACE "(\r?\n)+$" "" CONFIGUREARGS "${CONFIGUREARGS}")

set(CONFIGUREARGS ${CONFIGUREARGS})
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CONFIGUREARGS}")

add_subdirectory(crypto)
add_subdirectory(ssl)
add_subdirectory(apps)
add_subdirectory(tests)
