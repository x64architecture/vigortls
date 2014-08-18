include_directories (../crypto .. ../include)

function(
    add_test_suite

    testname

    sources
)

    add_executable(${testname} ${sources})

    add_test(${testname} ./${testname})

    target_link_libraries(${testname} crypto)

endfunction(add_test_suite)

add_test_suite(aes_wrap aes_wrap.c)
add_test_suite(asn1test asn1test.c)
add_test_suite(bftest bftest.c)
add_test_suite(bntest bntest.c)
add_test_suite(casttest casttest.c)
add_test_suite(chachatest chachatest.c)
add_test_suite(cts128test cts128test.c)
add_test_suite(destest destest.c)
add_test_suite(dhtest dhtest.c)
add_test_suite(dsatest dsatest.c)
add_test_suite(ecdhtest ecdhtest.c)
add_test_suite(ecdsatest ecdsatest.c)
add_test_suite(ectest ectest.c)
add_test_suite(enginetest enginetest.c)
add_test_suite(evptest evptest.c)
add_test_suite(exptest exptest.c)
add_test_suite(hmactest hmactest.c)
add_test_suite(ideatest ideatest.c)
add_test_suite(igetest igetest.c)
add_test_suite(md4test md4test.c)
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
add_test_suite(shatest shatest.c)
add_test_suite(srptest srptest.c)
#add_test_suite(ssltest ssltest.c)
add_test_suite(wptest wptest.c)
