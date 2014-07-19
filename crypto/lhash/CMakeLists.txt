include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

add_library(
	lhash

	OBJECT

	lhash.c
	lh_stats.c
)
