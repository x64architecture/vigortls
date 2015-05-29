include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
    poly1305

    OBJECT

    poly1305.c
    poly1305-donna.c
)
