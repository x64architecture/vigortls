include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
	pem

	OBJECT

	pem_all.c
	pem_err.c
	pem_info.c
	pem_lib.c
	pem_oth.c
	pem_pk8.c
	pem_pkey.c
	pem_seal.c
	pem_sign.c
	pem_x509.c
	pem_xaux.c
	pvkfmt.c
)
