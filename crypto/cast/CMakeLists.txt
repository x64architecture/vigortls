include_directories(../../include)

if (${ARCH} STREQUAL "x86")
    set(
        CAST_ARCH_SOURCES

        cast-586.${ASM_EXT}
    )
else()
    set(
        CAST_ARCH_SOURCES

        c_enc.c
    )
endif()

add_library(
    cast

    OBJECT

    ${CAST_ARCH_SOURCES}

    c_skey.c
    c_ecb.c
    c_cfb64.c
    c_ofb64.c
)
perlasm(cast-586.${ASM_EXT} asm/cast-586.pl)
