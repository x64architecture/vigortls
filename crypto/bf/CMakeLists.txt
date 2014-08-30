include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
    bf

    OBJECT

    bf_skey.c
    bf_ecb.c
    bf_enc.c
    bf_cfb64.c
    bf_ofb64.c
)
