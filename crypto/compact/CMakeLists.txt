include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include .)

if (NOT HAVE_ASPRINTF)
    set(
        COMPACT_SOURCES 

        asprintf.c
    )
endif()

if (NOT HAVE_REALLOCARRAY)
    set(
        COMPACT_SOURCES 

        ${COMPACT_SOURCES}
        reallocarray.c
    )
endif()

if (NOT HAVE_SNPRINTF)
    set(
        COMPACT_SOURCES 

        ${COMPACT_SOURCES}
        snprintf.c
    )
endif()

if (NOT HAVE_STRNDUP)
    set(
        COMPACT_SOURCES 

        ${COMPACT_SOURCES}
        strndup.c
    )
endif()

if (NOT HAVE_STRLCPY)
    set(
        COMPACT_SOURCES

        ${COMPACT_SOURCES}
        strlcpy.c
    )
endif()
if (NOT HAVE_STRLCAT)
    set(
        COMPACT_SOURCES 

        ${COMPACT_SOURCES}
        strlcat.c
    )
endif()
if (NOT HAVE_STRTONUM)
    set(
        COMPACT_SOURCES 

        ${COMPACT_SOURCES}
        strtonum.c
    )
endif()

add_library(
    compact

    OBJECT

    ${COMPACT_SOURCES}
    gettimeofday_windows.c
    dirent_windows.c
)
