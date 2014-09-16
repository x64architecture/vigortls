include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_custom_target(
    obj_dat.h 
    ALL 
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMAND perl obj_dat.pl  ${PROJECT_SOURCE_DIR}/include/openssl/obj_mac.h ${CMAKE_CURRENT_BINARY_DIR}/obj_dat.h
)

add_library(
    objects

    OBJECT

    o_names.c
    obj_dat.c
    obj_lib.c
    obj_err.c
    obj_xref.c
)

add_dependencies(objects obj_dat.h)
