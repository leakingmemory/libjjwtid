//
// Created by sigsegv on 12/25/23.
//

#include "include/OidcTokenRequest.h"
#include "include/JwkPemRsaKey.h"
#include <boost/uuid/uuid_generators.hpp> // for random_generator
#include <boost/uuid/uuid_io.hpp> // for to_string

#include <sstream>
#include <cpprest/uri.h>
#include "include/Jwt.h"
#include "include/Rs256.h"

OidcPostRequest OidcTokenRequest::GetTokenRequest() const {
    std::string tokenEndpoint{};
    {
        std::stringstream sstr{};
        sstr << url;
        if (!url.ends_with("/")) {
            sstr << "/";
        }
        sstr << "connect/token";
        tokenEndpoint = sstr.str();
    }
    std::string scopeStr{};
    {
        std::stringstream scopeStream{};
        auto iterator = scope.begin();
        if (iterator != scope.end()) {
            scopeStream << *iterator;
            ++iterator;
        }
        while (iterator != scope.end()) {
            scopeStream << " " << *iterator;
            ++iterator;
        }
        scopeStr = scopeStream.str();
    }
    std::string jwt{};
    {
        std::shared_ptr<SigningKey> signingKey{};
        {
            JwkPemRsaKey rsa{};
            rsa.FromJwk(jwk);
            signingKey = rsa.ToSigningKey();
        }
        auto iat = std::time(nullptr);
        Jwt token{};
        {
            boost::uuids::random_generator generator;
            boost::uuids::uuid randomUUID = generator();
            std::string uuidStr = boost::uuids::to_string(randomUUID);
            token.Body()->Add("jti", uuidStr);
        }
        token.Body()->Add("iss", clientId);
        token.Body()->Add("iat", iat);
        token.Body()->Add("nbf", iat);
        token.Body()->Add("exp", iat + 120);
        token.Body()->Add("sub", clientId);
        token.Body()->Add("aud", tokenEndpoint);
        Rs256 rs256{signingKey};
        rs256.Sign(token);
        jwt = token.ToString();
    }
    std::map<std::string,std::string> params{};
    params.insert_or_assign("client_id", clientId);
    params.insert_or_assign("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    params.insert_or_assign("client_assertion", jwt);
    if (!code.empty()) {
        params.insert_or_assign("grant_type", "authorization_code");
        params.insert_or_assign("redirect_uri", redirectUri);
        params.insert_or_assign("code", code);
        params.insert_or_assign("code_verifier", codeVerifier);
    } else if (!refreshToken.empty()) {
        params.insert_or_assign("grant_type", "refresh_token");
        params.insert_or_assign("refresh_token", refreshToken);
    }
    params.insert_or_assign("scope", scopeStr);
    return {.url = tokenEndpoint, .params = params};
}
