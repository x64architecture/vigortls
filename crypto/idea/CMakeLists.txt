include_directories(../../include)

add_library(
    idea

    OBJECT

    i_cbc.c
    i_cfb64.c
    i_ofb64.c
    i_ecb.c
    i_skey.c
)
