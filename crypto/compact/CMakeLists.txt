include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include .)

add_library(
    compact

    OBJECT

    reallocarray.c
    strtonum.c
)
