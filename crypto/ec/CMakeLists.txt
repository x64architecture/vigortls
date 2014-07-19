include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
	ec

	OBJECT

	ec2_mult.c
	ec2_oct.c
	ec2_smpl.c
	eck_prn.c
	ecp_mont.c
	ecp_nist.c
	ecp_oct.c
	ecp_smpl.c
	ec_ameth.c
	ec_asn1.c
	ec_check.c
	ec_curve.c
	ec_cvt.c
	ec_err.c
	ec_key.c
	ec_lib.c
	ec_mult.c
	ec_oct.c
	ec_pmeth.c
	ec_print.c
)
