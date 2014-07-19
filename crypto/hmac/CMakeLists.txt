include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
	hmac

	OBJECT

	hmac.c
	hm_ameth.c
	hm_pmeth.c
)
