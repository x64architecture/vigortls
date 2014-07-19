include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
	cmac

	OBJECT

	cm_ameth.c
	cm_pmeth.c
	cmac.c
)
