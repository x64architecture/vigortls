include_directories( ${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes )

add_library(
    md5

    OBJECT

    md5_dgst.c
    md5_one.c
)
