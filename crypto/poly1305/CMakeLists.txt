include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
    poly1305

    OBJECT

    poly1305.c
)
set_source_files_properties(poly1305 PROPERTIES COMPILE_FLAGS "-O3 -march=native -save-temps") 
