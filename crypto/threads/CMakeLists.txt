include_directories(../../include)

if(UNIX AND MT_SUPPORT)
    set(
        OS_SOURCES

        pthread.c
    )
elseif(WIN32 AND MT_SUPPORT)
    set(
        OS_SOURCES

        win32.c
    )
elseif(NOT MT_SUPPORT)
    set(
        OS_SOURCES

        none.c
    )
endif()

add_library(
    threads

    OBJECT

    ${OS_SOURCES}
)
