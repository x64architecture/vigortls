include_directories( ${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes )

if (${ARCH} STREQUAL "x86_64")
	set(
		WHRL_ARCH_SOURCES

		wp-x86_64.${ASM_EXT}
	)
endif()

add_library(
	whrlpool

	OBJECT

	wp_dgst.c
	wp_block.c

    ${WHRL_ARCH_SOURCES}
)

perlasm(wp-x86_64.${ASM_EXT} asm/wp-x86_64.pl)
