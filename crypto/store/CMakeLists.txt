include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
    store

    OBJECT

    str_err.c
    str_lib.c
    str_mem.c
    str_meth.c
)
