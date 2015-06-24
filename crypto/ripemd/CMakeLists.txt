include_directories(../../include)

if (${ARCH} STREQUAL "x86")
    set(
        RIPEMD_ARCH_SOURCES

        rmd-586.${ASM_EXT}
    )
endif()

add_library(
    ripemd

    OBJECT

    rmd_dgst.c
    rmd_one.c

    ${RIPEMD_ARCH_SOURCES}
)

perlasm(rmd-586.${ASM_EXT} asm/rmd-586.pl)
