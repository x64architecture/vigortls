include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include .)

if (NOT HAVE_VASPRINTF OR NOT HAVE_ASPRINTF)
    set(
        COMPAT_SOURCES

        vasprintf.c
    )
endif()

if (NOT HAVE_REALLOCARRAY)
    set(
        COMPAT_SOURCES 

        ${COMPAT_SOURCES}
        reallocarray.c
    )
endif()

if (NOT HAVE_SNPRINTF)
    set(
        COMPAT_SOURCES 

        ${COMPAT_SOURCES}
        snprintf.c
    )
endif()

if (NOT HAVE_STRNDUP)
    set(
        COMPAT_SOURCES 

        ${COMPAT_SOURCES}
        strndup.c
    )
endif()

if (NOT HAVE_STRLCPY)
    set(
        COMPAT_SOURCES

        ${COMPAT_SOURCES}
        strlcpy.c
    )
endif()

if (NOT HAVE_STRLCAT)
    set(
        COMPAT_SOURCES 

        ${COMPAT_SOURCES}
        strlcat.c
    )
endif()

if (NOT HAVE_STRTONUM)
    set(
        COMPAT_SOURCES 

        ${COMPAT_SOURCES}
        strtonum.c
    )
endif()

add_library(
    compat

    OBJECT

    ${COMPAT_SOURCES}
    gettimeofday_windows.c
    dirent_windows.c
)
