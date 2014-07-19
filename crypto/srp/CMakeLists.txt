include_directories( ${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes )

add_library(
	srp

	OBJECT

	srp_lib.c
	srp_vfy.c
)
