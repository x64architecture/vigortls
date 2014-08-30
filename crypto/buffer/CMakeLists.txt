include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
    buffer

    OBJECT

    buffer.c
    buf_err.c
    buf_str.c
)
