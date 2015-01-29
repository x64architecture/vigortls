include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
    objects

    OBJECT

    o_names.c
    obj_dat.c
    obj_lib.c
    obj_err.c
    obj_xref.c
)
