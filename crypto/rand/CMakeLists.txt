include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

if (WIN32)
    set(
        OS_SOURCES

        windows.c
    )

else() # Posix
    set(
        OS_SOURCES

        urandom.c
    )
endif()

add_library(
    rand

    OBJECT

    ${OS_SOURCES}

    rand.c
    rand_err.c
)
