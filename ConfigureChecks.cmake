include (CheckFunctionExists)

CHECK_FUNCTION_EXISTS(strlcpy HAVE_STRLCPY)
CHECK_FUNCTION_EXISTS(strlcat HAVE_STRLCAT)

if (HAVE_STRLCPY)
    add_definitions(-DHAVE_STRLCPY)
elseif (HAVE_STRLCAT)
    add_definitions(-DHAVE_STRLCAT)
endif()
