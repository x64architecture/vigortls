include_directories( ${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes )

add_library(
	whrlpool

	OBJECT

	wp_dgst.c
	wp_block.c
)
