include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
	idea

	OBJECT

	i_cbc.c
	i_cfb64.c
	i_ofb64.c
	i_ecb.c
	i_skey.c
)
