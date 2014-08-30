include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
    ecdh

    OBJECT

    ech_lib.c
    ech_ossl.c
    ech_key.c
    ech_err.c
)
