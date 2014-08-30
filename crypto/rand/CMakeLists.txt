include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
    rand

    OBJECT

    rand.c
    urandom.c
    rand_err.c
)
