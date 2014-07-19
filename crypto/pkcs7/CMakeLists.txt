include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
	pkcs7

	OBJECT

	bio_pk7.c
	pk7_asn1.c
	pk7_attr.c
	pk7_doit.c
	pk7_lib.c
	pk7_mime.c
	pk7_smime.c
	pkcs7err.c
)
