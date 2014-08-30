include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
    err

    OBJECT

    err.c
    err_all.c
    err_prn.c
)
