include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
	rc2

	OBJECT

	rc2_ecb.c
	rc2_skey.c
	rc2_cbc.c
	rc2cfb64.c
	rc2ofb64.c
)
