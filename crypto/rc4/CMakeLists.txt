include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../evp)

if (${ARCH} STREQUAL "x86_64")
    set(
        RC4_ARCH_SOURCES

        rc4-x86_64.${ASM_EXT}
        rc4-md5-x86_64.${ASM_EXT}
    )
elseif (${ARCH} STREQUAL "x86")
    set(
        RC4_ARCH_SOURCES

        rc4-586.${ASM_EXT}
    )
else()
set(
    RC4_ARCH_SOURCES

    rc4.c
) 
endif()

add_library(
    rc4

    OBJECT

    ${RC4_ARCH_SOURCES}
)

perlasm(rc4-x86_64.${ASM_EXT} asm/rc4-x86_64.pl)
perlasm(rc4-md5-x86_64.${ASM_EXT} asm/rc4-md5-x86_64.pl)
perlasm(rc4-586.${ASM_EXT} asm/rc4-586.pl)
