include_directories(../../include ../cpuid)

if (${ARCH} STREQUAL "x86" OR ${ARCH} STREQUAL "x86_64")
    set(
        CHACHA_ARCH_SOURCES

        chacha_vec.c
    )
    if (CMAKE_COMPILER_IS_GNUCC OR ${CMAKE_C_COMPILER_ID} STREQUAL "Clang")
        set_source_files_properties(chacha_vec.c PROPERTIES COMPILE_OPTIONS -mssse3)
    endif()
elseif (${ARCH} STREQUAL "arm")
    set(
        CHACHA_ARCH_SOURCES

        chacha_vec_arm.S
    )
endif()

add_library(
    chacha

    OBJECT

    ${CHACHA_ARCH_SOURCES}

    chacha.c
)
