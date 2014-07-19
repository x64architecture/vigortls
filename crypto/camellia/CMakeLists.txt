include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

if (${ARCH} STREQUAL "x86_64")
	set(
		CMLL_ARCH_SOURCES

		cmll-x86_64.${ASM_EXT}
	)
endif()

if (${ARCH} STREQUAL "x86")
	set(
		CMLL_ARCH_SOURCES

		cmll-x86.${ASM_EXT}
	)
endif()

add_library(
	camellia

	OBJECT

	camellia.c
	cmll_misc.c
	cmll_ecb.c
	cmll_cbc.c
	cmll_ofb.c
	cmll_cfb.c
	cmll_ctr.c
	cmll_utl.c

	${CMLL_ARCH_SOURCES}
)

perlasm(cmll-x86_64.${ASM_EXT} asm/cmll-x86_64.pl)
perlasm(cmll-x86.${ASM_EXT} asm/cmll-x86.pl)
