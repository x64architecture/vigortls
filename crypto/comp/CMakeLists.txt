include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
    comp

    OBJECT

    comp_lib.c
    comp_err.c
    c_rle.c
    c_zlib.c
)
