include_directories(../../include)

add_library(
    ecdh

    OBJECT

    ech_lib.c
    ech_ossl.c
    ech_key.c
    ech_err.c
)
