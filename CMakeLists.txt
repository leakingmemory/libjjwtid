cmake_minimum_required(VERSION 3.26)
project(libjjwtid)

set(CMAKE_CXX_STANDARD 23)
set(CPPLEVEL 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_options(-fPIC)

find_package(cpprestsdk REQUIRED)

if (${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD")
    add_compile_options("-I/usr/local/include")
endif()

try_compile(CONSTEXPRSTRINGTEST "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/configtests/constexprstrtest.cpp")

if (CONSTEXPRSTRINGTEST)
    message("std::string constructors are constexpr")
    set(CONSTEXPRSTRING "true")
else()
    message("std::string constructors are not constexpr")
    set(CONSTEXPRSTRING "false")
endif()

try_compile(OPENSSL3TEST "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/configtests/openssl3test.cpp")

if (OPENSSL3TEST)
    message("system has openssl 3 or later")
    set(OPENSSL3 "true")
else()
    message("system does not have openssl 3 or later")
    set(OPENSSL3 "false")
endif()

add_custom_target("cpplevel.h"
        ALL "cat" "${CMAKE_CURRENT_SOURCE_DIR}/cpplevel.h.in" | sed -e "s/xCPPLEVELx/${CPPLEVEL}/" | sed -e "s/xCONSTEXPRSTRINGx/${CONSTEXPRSTRING}/" | sed -e "s/xOPENSSL3x/${OPENSSL3}/" > "${CMAKE_CURRENT_BINARY_DIR}/cpplevel.h"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/cpplevel.h.in"
)

add_library(crypto OBJECT sha2alg.cpp include/sha2alg.h PkceS256.cpp include/PkceS256.h OpensslRsa.cpp include/OpensslRsa.h
        Openssl.cpp include/Openssl.h JwkPemRsaKey.cpp JwkPemRsaKeyJson.cpp include/JwkPemRsaKey.h Base64.cpp include/Base64.h
        Bignum.cpp include/Bignum.h include/SigningKey.h include/VerificationKey.h)
add_dependencies(crypto "cpplevel.h")
target_include_directories(crypto PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")

add_library(jjwtid SHARED Jwt.cpp include/Jwt.h JwtPart.cpp include/JwtPart.h Rs256.cpp include/Rs256.h OidcTokenRequest.cpp include/OidcTokenRequest.h)
add_dependencies(jjwtid "cpplevel.h")
target_include_directories(jjwtid PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(jjwtid PRIVATE crypto)
target_link_libraries(jjwtid PRIVATE -lssl -lcrypto)
target_link_libraries(jjwtid PRIVATE cpprestsdk::cpprest -lcrypto)

set_target_properties(jjwtid PROPERTIES SOVERSION 2 VERSION 2.0.0)

install(TARGETS jjwtid
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/cpplevel.h"
        DESTINATION include/jjwtid)
install(DIRECTORY include/ DESTINATION include/jjwtid)


enable_testing()

add_executable(genrsatest GenRsaTest.cpp)
add_dependencies(genrsatest "cpplevel.h")
target_include_directories(genrsatest PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(genrsatest PRIVATE crypto)
target_link_libraries(genrsatest PRIVATE -lssl -lcrypto)

add_test(NAME GenRsaTest COMMAND genrsatest)

add_executable(jwktopemtest JwkToPemTest.cpp)
target_link_libraries(jwktopemtest PRIVATE crypto)
target_link_libraries(jwktopemtest PRIVATE -lssl -lcrypto)

add_test(NAME JwkToPemTest COMMAND jwktopemtest)

add_executable(tokenrequesttest OidcTokenRequestTest.cpp OidcTokenRequest.cpp include/OidcTokenRequest.h Jwt.cpp include/Jwt.h JwtPart.cpp include/JwtPart.h Rs256.cpp include/Rs256.h)
add_dependencies(tokenrequesttest "cpplevel.h")
target_include_directories(tokenrequesttest PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(tokenrequesttest PRIVATE crypto)
target_link_libraries(tokenrequesttest PRIVATE -lssl -lcrypto)
target_link_libraries(tokenrequesttest PRIVATE cpprestsdk::cpprest -lcrypto)

add_test(NAME TokenRequestTest COMMAND tokenrequesttest)

add_executable(helseidmultitenanttokenrequesttest HelseidMultiTenantOidcTokenRequestTest.cpp OidcTokenRequest.cpp include/OidcTokenRequest.h Jwt.cpp include/Jwt.h JwtPart.cpp include/JwtPart.h Rs256.cpp include/Rs256.h)
add_dependencies(helseidmultitenanttokenrequesttest "cpplevel.h")
target_include_directories(helseidmultitenanttokenrequesttest PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(helseidmultitenanttokenrequesttest PRIVATE crypto)
target_link_libraries(helseidmultitenanttokenrequesttest PRIVATE -lssl -lcrypto)
target_link_libraries(helseidmultitenanttokenrequesttest PRIVATE cpprestsdk::cpprest -lcrypto)

add_test(NAME HelseIdMultiTenantTokenRequestTest COMMAND helseidmultitenanttokenrequesttest)
