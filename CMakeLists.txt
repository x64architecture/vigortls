cmake_minimum_required(VERSION 2.8.8)
project(VigorTLS C)

find_package(Perl REQUIRED)

include(CTest)
include(CMake/ConfigureChecks.cmake)
include(CMake/GenDeps.cmake)

if (CMAKE_COMPILER_IS_GNUCC OR ${CMAKE_C_COMPILER_ID} STREQUAL "Clang"
    OR ${CMAKE_C_COMPILER_ID} STREQUAL "Intel")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -Wundef -Wsign-compare -g -std=c99")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O3")
elseif(MSVC)
  set(CMAKE_C_FLAGS "/W3 /WX /wd4267 /wd4018 /wd4090 /wd4146 /wd4244")
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} /MT /Ox /O2 /Ob2")
  add_definitions(-DVIGORTLS_MSVC -D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_DEPRECATE -D_WINSOCK_DEPRECATED_NO_WARNINGS -Dinline=__inline)
else()
    message(FATAL_ERROR "Unsupported compiler:" ${CMAKE_C_COMPILER_ID})
endif()

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
	set(ARCH "x86_64")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "amd64")
	set(ARCH "x86_64")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "AMD64")
	# cmake reports AMD64 on Windows, but we might be building for 32-bit.
	if (CMAKE_CL_64)
		set(ARCH "x86_64")
	else()
		set(ARCH "x86")
	endif()
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86")
	set(ARCH "x86")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i386")
	set(ARCH "x86")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "i686")
	set(ARCH "x86")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "arm")
	set(ARCH "arm")
elseif (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "armv7l")
    set(ARCH "arm")
else()
    message(FATAL_ERROR "Unsupported processor:" ${CMAKE_SYSTEM_PROCESSOR})
endif()

add_definitions(-DVIGORTLS_INTERNAL)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    add_definitions(-D_GNU_SOURCE)
endif()

if (BUILD_SHARED_LIBS)
    # Because we use OBJECT we have to globaly set
    # CMAKE_POSITION_INDEPENDENT_CODE to TRUE
    set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
endif()

install(DIRECTORY include/openssl DESTINATION include)

add_subdirectory(crypto)
add_subdirectory(ssl)
add_subdirectory(apps)
add_subdirectory(tests)
