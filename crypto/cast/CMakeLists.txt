include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
    cast

    OBJECT

    c_skey.c
    c_ecb.c
    c_enc.c
    c_cfb64.c
    c_ofb64.c
)
