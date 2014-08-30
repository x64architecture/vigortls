include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
    dso

    OBJECT

    dso_dlfcn.c
    dso_err.c
    dso_lib.c
    dso_null.c
    dso_openssl.c
)
