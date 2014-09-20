include_directories(${CMAKE_CURRENT_BINARY_DIR} .. ../include . asn1 evp modes)

if(APPLE)
    set(PERLASM_STYLE macosx)
    set(ASM_EXT S)
    enable_language(ASM)
else(UNIX)
    set(PERLASM_STYLE elf)
    set(ASM_EXT S)
    enable_language(ASM)
else()
    message(FATAL ERROR "Unsupported operating system")
endif()

function(perlasm dest src)
    add_custom_command(
        OUTPUT ${dest}
        COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/${src} ${PERLASM_STYLE} ${ARGN} > ${dest}
        DEPENDS
        ${src}
        ${PROJECT_SOURCE_DIR}/crypto/perlasm/x86_64-xlate.pl
        ${PROJECT_SOURCE_DIR}/crypto/perlasm/x86gas.pl
        ${PROJECT_SOURCE_DIR}/crypto/perlasm/x86asm.pl
        ${PROJECT_SOURCE_DIR}/crypto/perlasm/x86asm.pl
        WORKING_DIRECTORY .
    )
endfunction()

if (${ARCH} STREQUAL "x86_64")
    set(
        CRYPTO_ARCH_SOURCES

        x86_64cpuid.${ASM_EXT}
    )
endif()

if (${ARCH} STREQUAL "x86")
    set(
        CRYPTO_ARCH_SOURCES

        x86cpuid.${ASM_EXT}
    )
endif()

if (${ARCH} STREQUAL "arm")
    set(
        CRYPTO_ARCH_SOURCES

        armcap.c
        armv4cpuid.S
    )
endif()

add_subdirectory(aes)
add_subdirectory(asn1)
add_subdirectory(bf)
add_subdirectory(bio)
add_subdirectory(bn)
add_subdirectory(buffer)
add_subdirectory(camellia)
add_subdirectory(cast)
add_subdirectory(chacha)
add_subdirectory(cmac)
add_subdirectory(cms)
add_subdirectory(conf)
add_subdirectory(compact)
add_subdirectory(des)
add_subdirectory(dh)
add_subdirectory(dsa)
add_subdirectory(dso)
add_subdirectory(ec)
add_subdirectory(ecdh)
add_subdirectory(ecdsa)
add_subdirectory(engine)
add_subdirectory(err)
add_subdirectory(hmac)
add_subdirectory(idea)
add_subdirectory(lhash)
add_subdirectory(md4)
add_subdirectory(md5)
add_subdirectory(mdc2)
add_subdirectory(modes)
add_subdirectory(objects)
add_subdirectory(ocsp)
add_subdirectory(pem)
add_subdirectory(pkcs7)
add_subdirectory(pkcs12)
add_subdirectory(poly1305)
add_subdirectory(pqueue)
add_subdirectory(rand)
add_subdirectory(rc2)
add_subdirectory(rc4)
add_subdirectory(rc5)
add_subdirectory(ripemd)
add_subdirectory(rsa)
add_subdirectory(sha)
add_subdirectory(stack)
add_subdirectory(ts)
add_subdirectory(txt_db)
add_subdirectory(ui)
add_subdirectory(evp)
add_subdirectory(whrlpool)
add_subdirectory(x509)
add_subdirectory(x509v3)

add_library(
    crypto

    STATIC

    cpt_err.c
    cryptlib.c
    ex_data.c
    malloc_wrapper.c
    mem_clr.c
    mem_dbg.c
    time_support.c
    uid.c

    ${CRYPTO_ARCH_SOURCES}

    $<TARGET_OBJECTS:aes>
    $<TARGET_OBJECTS:asn1>
    $<TARGET_OBJECTS:bf>
    $<TARGET_OBJECTS:bio>
    $<TARGET_OBJECTS:bn>
    $<TARGET_OBJECTS:buffer>
    $<TARGET_OBJECTS:camellia>
    $<TARGET_OBJECTS:cast>
    $<TARGET_OBJECTS:chacha>
    $<TARGET_OBJECTS:cmac>
    $<TARGET_OBJECTS:cms>
    $<TARGET_OBJECTS:conf>
    $<TARGET_OBJECTS:compact>
    $<TARGET_OBJECTS:des>
    $<TARGET_OBJECTS:dh>
    $<TARGET_OBJECTS:dsa>
    $<TARGET_OBJECTS:dso>
    $<TARGET_OBJECTS:ec>
    $<TARGET_OBJECTS:ecdh>
    $<TARGET_OBJECTS:ecdsa>
    $<TARGET_OBJECTS:engine>
    $<TARGET_OBJECTS:err>
    $<TARGET_OBJECTS:evp>
    $<TARGET_OBJECTS:hmac>
    $<TARGET_OBJECTS:idea>
    $<TARGET_OBJECTS:lhash>
    $<TARGET_OBJECTS:md4>
    $<TARGET_OBJECTS:md5>
    $<TARGET_OBJECTS:mdc2>
    $<TARGET_OBJECTS:modes>
    $<TARGET_OBJECTS:objects>
    $<TARGET_OBJECTS:ocsp>
    $<TARGET_OBJECTS:pem>
    $<TARGET_OBJECTS:pkcs7>
    $<TARGET_OBJECTS:pkcs12>
    $<TARGET_OBJECTS:poly1305>
    $<TARGET_OBJECTS:pqueue>
    $<TARGET_OBJECTS:rand>
    $<TARGET_OBJECTS:rc2>
    $<TARGET_OBJECTS:rc4>
    $<TARGET_OBJECTS:rc5>
    $<TARGET_OBJECTS:ripemd>
    $<TARGET_OBJECTS:rsa>
    $<TARGET_OBJECTS:sha>
    $<TARGET_OBJECTS:stack>
    $<TARGET_OBJECTS:ts>
    $<TARGET_OBJECTS:txt_db>
    $<TARGET_OBJECTS:ui>
    $<TARGET_OBJECTS:whrlpool>
    $<TARGET_OBJECTS:x509>
    $<TARGET_OBJECTS:x509v3>
)

set_source_files_properties(mem_clr.c PROPERTIES COMPILE_FLAGS -O0)

perlasm(x86_64cpuid.${ASM_EXT} x86_64cpuid.pl)
perlasm(x86cpuid.${ASM_EXT} x86cpuid.pl)
