include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

if (${ARCH} STREQUAL "x86")
    set(
        BF_ARCH_SOURCES

        bf-586.${ASM_EXT}
    )
else()
    set(
        BF_ARCH_SOURCES

        bf_enc.c
    )
endif()

add_library(
    bf

    OBJECT

    ${BF_ARCH_SOURCES}

    bf_skey.c
    bf_ecb.c
    bf_cfb64.c
    bf_ofb64.c
)

perlasm(bf-586.${ASM_EXT} asm/bf-586.pl)
