include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
	des

	OBJECT

	cbc_cksm.c
	cbc_enc.c
	cfb64ede.c
	cfb64enc.c
	cfb_enc.c
	des_enc.c
	ecb3_enc.c
	ecb_enc.c
	ede_cbcm_enc.c
	enc_read.c
	enc_writ.c
	fcrypt.c
	fcrypt_b.c
	ofb64ede.c
	ofb64enc.c
	ofb_enc.c
	pcbc_enc.c
	qud_cksm.c
	rand_key.c
	set_key.c
	str2key.c
	xcbc_enc.c
)
