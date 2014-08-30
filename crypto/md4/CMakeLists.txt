include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
    md4

    OBJECT

    md4_dgst.c
    md4_one.c
)
