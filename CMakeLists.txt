cmake_minimum_required(VERSION 3.27)
project(libjjwtid)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-fPIC)

find_package(cpprestsdk REQUIRED)

add_library(crypto OBJECT sha2alg.cpp include/sha2alg.h PkceS256.cpp include/PkceS256.h OpensslRsa.cpp include/OpensslRsa.h
        Openssl.cpp include/Openssl.h JwkPemRsaKey.cpp JwkPemRsaKeyJson.cpp include/JwkPemRsaKey.h Base64.cpp include/Base64.h
        Bignum.cpp include/Bignum.h include/SigningKey.h include/VerificationKey.h)

add_library(jjwtid SHARED Jwt.cpp include/Jwt.h JwtPart.cpp include/JwtPart.h Rs256.cpp include/Rs256.h OidcTokenRequest.cpp include/OidcTokenRequest.h)
target_link_libraries(jjwtid PRIVATE crypto)
target_link_libraries(jjwtid PRIVATE -lssl -lcrypto)
target_link_libraries(jjwtid PRIVATE cpprestsdk::cpprest -lcrypto)

install(TARGETS jjwtid
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
)
install(DIRECTORY include/ DESTINATION include/jjwtid)


enable_testing()

add_executable(genrsatest GenRsaTest.cpp)
target_link_libraries(genrsatest PRIVATE crypto)
target_link_libraries(genrsatest PRIVATE -lssl -lcrypto)

add_test(NAME GenRsaTest COMMAND genrsatest)

add_executable(jwktopemtest JwkToPemTest.cpp)
target_link_libraries(jwktopemtest PRIVATE crypto)
target_link_libraries(jwktopemtest PRIVATE -lssl -lcrypto)

add_test(NAME JwkToPemTest COMMAND jwktopemtest)

add_executable(tokenrequesttest OidcTokenRequestTest.cpp OidcTokenRequest.cpp include/OidcTokenRequest.h Jwt.cpp include/Jwt.h JwtPart.cpp include/JwtPart.h Rs256.cpp include/Rs256.h)
target_link_libraries(tokenrequesttest PRIVATE crypto)
target_link_libraries(tokenrequesttest PRIVATE -lssl -lcrypto)
target_link_libraries(tokenrequesttest PRIVATE cpprestsdk::cpprest -lcrypto)

add_test(NAME TokenRequestTest COMMAND tokenrequesttest)
