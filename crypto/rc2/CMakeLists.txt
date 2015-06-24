include_directories(../../include)

add_library(
    rc2

    OBJECT

    rc2_ecb.c
    rc2_skey.c
    rc2_cbc.c
    rc2cfb64.c
    rc2ofb64.c
)
