include_directories (../crypto/bytestring ../crypto .. ../include)

function(
    add_test_suite

    testname

    sources
)

    add_executable(${testname} ${sources})

    add_test(${testname} ./${testname})

    target_link_libraries(${testname} crypto)

endfunction(add_test_suite)

add_executable(ssltest ssltest.c)
add_executable(evptest evptest.c)
add_executable(aeadtest aeadtest.c)
target_link_libraries(aeadtest crypto ssl)
target_link_libraries(evptest crypto)
target_link_libraries(ssltest crypto ssl)

set(AEADTDIR "${PROJECT_SOURCE_DIR}/tests/data/aead")
add_test(aes-128-gcm_aead ./aeadtest aes-128-gcm ${AEADTDIR}/aes_128_gcm_tests.txt)
add_test(aes-256-gcm_aead ./aeadtest aes-256-gcm ${AEADTDIR}/aes_256_gcm_tests.txt)
add_test(chacha20-poly1305_aead ./aeadtest chacha20-poly1305 ${AEADTDIR}/chacha20_poly1305_tests.txt)
add_test_suite(aes_wrap aes_wrap.c)
add_test_suite(bftest bftest.c)
add_test_suite(bntest bntest.c)
add_test_suite(bytestringtest bytestringtest.c)
add_test_suite(casttest casttest.c)
add_test_suite(chachatest chachatest.c)
add_test_suite(consttimetest constant_time_test.c)
add_test_suite(cts128test cts128test.c)
add_test_suite(destest destest.c)
add_test_suite(dhtest dhtest.c)
add_test_suite(dsatest dsatest.c)
add_test_suite(ecdhtest ecdhtest.c)
add_test_suite(ecdsatest ecdsatest.c)
add_test_suite(ectest ectest.c)
add_test_suite(enginetest enginetest.c)
add_test(evptest ./evptest ${PROJECT_SOURCE_DIR}/tests/data/evptests.txt)
add_test_suite(exptest exptest.c)
add_test_suite(gcm128test gcm128test.c)
add_test_suite(gosttest gostr2814789t.c)
add_test_suite(hmactest hmactest.c)
add_test_suite(ideatest ideatest.c)
add_test_suite(igetest igetest.c)
add_test_suite(md5test md5test.c)
add_test_suite(mdc2test mdc2test.c)
add_test_suite(poly1305test poly1305test.c)
add_test_suite(pq_test pq_test.c)
add_test_suite(randtest randtest.c)
add_test_suite(rc2test rc2test.c)
add_test_suite(rc4test rc4test.c)
add_test_suite(rmdtest rmdtest.c)
add_test_suite(rsatest rsatest.c)
add_test_suite(sha1test sha1test.c)
add_test_suite(sha256test sha256test.c)
add_test_suite(sha512test sha512test.c)
if (NOT WIN32)
add_test(ssltest ${CMAKE_CURRENT_SOURCE_DIR}/ssltest.sh ${CMAKE_CURRENT_BINARY_DIR}/../apps ${CMAKE_CURRENT_SOURCE_DIR})
endif()
add_test_suite(wptest wptest.c)
