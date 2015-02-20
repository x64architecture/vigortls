include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

if (${ARCH} STREQUAL "x86_64")
    set(
        EC_ARCH_SOURCES

        ecp_nistz256-x86_64.${ASM_EXT}
        ecp_nistz256-avx2.${ASM_EXT}
    )
elseif(${ARCH} STREQUAL "x86")
    set(
        EC_ARCH_SOURCES

        ecp_nistz256-avx2.${ASM_EXT}
    )
endif()

add_library(
    ec

    OBJECT

    ${EC_ARCH_SOURCES}

    ec2_mult.c
    ec2_oct.c
    ec2_smpl.c
    eck_prn.c
    ecp_mont.c
    ecp_nist.c
    ecp_nistp224.c
    ecp_nistp256.c
    ecp_nistp521.c
    ecp_nistputil.c
    ecp_nistz256.c
    ecp_oct.c
    ecp_smpl.c
    ec_ameth.c
    ec_asn1.c
    ec_check.c
    ec_curve.c
    ec_cvt.c
    ec_err.c
    ec_key.c
    ec_lib.c
    ec_mult.c
    ec_oct.c
    ec_pmeth.c
    ec_print.c
)

perlasm(ecp_nistz256-x86_64.${ASM_EXT} asm/ecp_nistz256-x86_64.pl)
perlasm(ecp_nistz256-avx2.${ASM_EXT} asm/ecp_nistz256-avx2.pl)
