include_directories( ${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes )

add_library(
	ui

	OBJECT

	ui_err.c
	ui_lib.c
	ui_openssl.c
	ui_util.c
	ui_compat.c
)
