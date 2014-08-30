include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

if (${ARCH} STREQUAL "x86")
    set(
        RC5_ARCH_SOURCES

        rc5-586.${ASM_EXT}
    )
else()
    set(
        RC5_ARCH_SOURCES

        rc5_enc.c
    )
endif()

add_library(
    rc5

    OBJECT

    rc5_skey.c
    rc5_ecb.c
    rc5cfb64.c
    rc5ofb64.c 

    ${RC5_ARCH_SOURCES}
)

perlasm(rc5-586.${ASM_EXT} asm/rc5-586.pl)
