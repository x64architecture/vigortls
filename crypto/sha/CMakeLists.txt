include_directories( ${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes )

add_library(
	sha

	OBJECT

	sha_dgst.c
	sha1dgst.c
	sha_one.c
	sha1_one.c
	sha256.c
	sha512.c
)
