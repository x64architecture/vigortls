include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
	rand

	OBJECT

	md_rand.c
	rand_lib.c
	rand_err.c
	rand_egd.c
	rand_unix.c
)
