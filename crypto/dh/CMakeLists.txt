include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
	dh

	OBJECT

	dh_ameth.c
	dh_asn1.c
	dh_check.c
	dh_depr.c
	dh_err.c
	dh_gen.c
	dh_key.c
	dh_lib.c
	dh_pmeth.c
	dh_prn.c
)
