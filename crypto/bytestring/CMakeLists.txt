include_directories( ${CMAKE_CURRENT_BINARY_DIR} .. ../../include . )

add_library(
    bytestring

    OBJECT

    ber.c
    cbb.c
    cbs.c
)
