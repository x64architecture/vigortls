include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

if (${ARCH} STREQUAL "x86_64")
    set(
        MD5_ARCH_SOURCES

        md5-x86_64.${ASM_EXT}
    )
endif()

if (${ARCH} STREQUAL "x86")
    set(
        MD5_ARCH_SOURCES

        md5-586.${ASM_EXT}
    )
endif()

add_library(
    md5

    OBJECT

    md5_dgst.c
    md5_one.c

    ${MD5_ARCH_SOURCES}
)

perlasm(md5-x86_64.${ASM_EXT} asm/md5-x86_64.pl)
perlasm(md5-586.${ASM_EXT} asm/md5-586.pl)
