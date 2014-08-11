include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../../include . ../asn1 ../evp ../modes)

if (${ARCH} STREQUAL "x86_64")
	set(
		AES_ARCH_SOURCES

		aes-x86_64.${ASM_EXT}
		aesni-x86_64.${ASM_EXT}
		aesni-sha1-x86_64.${ASM_EXT}
		bsaes-x86_64.${ASM_EXT}
		vpaes-x86_64.${ASM_EXT}
	)

elseif (${ARCH} STREQUAL "x86")
	set(
		AES_ARCH_SOURCES

		aes-586.${ASM_EXT}
		vpaes-x86.${ASM_EXT}
		aesni-x86.${ASM_EXT}
	)

else()
	set(
		AES_ARCH_SOURCES

		aes_core.c
		aes_cbc.c
	)
endif()

add_library(
	aes

	OBJECT

	aes_misc.c
	aes_ecb.c
	aes_cfb.c
	aes_ofb.c
	aes_ctr.c
	aes_ige.c
	aes_wrap.c

    ${AES_ARCH_SOURCES}
)

perlasm(aes-x86_64.${ASM_EXT} asm/aes-x86_64.pl)
perlasm(aesni-x86_64.${ASM_EXT} asm/aesni-x86_64.pl)
perlasm(aesni-sha1-x86_64.${ASM_EXT} asm/aesni-sha1-x86_64.pl)
perlasm(bsaes-x86_64.${ASM_EXT} asm/bsaes-x86_64.pl)
perlasm(vpaes-x86_64.${ASM_EXT} asm/vpaes-x86_64.pl)
perlasm(aes-586.${ASM_EXT} asm/aes-586.pl)
perlasm(vpaes-x86.${ASM_EXT} asm/vpaes-x86.pl)
perlasm(aesni-x86.${ASM_EXT} asm/aesni-x86.pl)
