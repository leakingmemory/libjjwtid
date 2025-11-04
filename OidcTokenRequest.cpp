//
// Created by sigsegv on 12/25/23.
//

#include "include/OidcTokenRequest.h"
#include "include/JwkPemRsaKey.h"
#include <boost/uuid/uuid_generators.hpp> // for random_generator
#include <boost/uuid/uuid_io.hpp> // for to_string

#include <sstream>
#include "include/Jwt.h"
#include "include/Rs256.h"
#include "include/OidcClientAssertion.h"

void OidcTokenRequest::AddHelseIdJournalId(const std::string &jid) {
    helseidMultiTenantInfo.journalId = jid;
}

void OidcTokenRequest::AddHelseIdConsumerOrgNo(const std::string &no) {
    helseidMultiTenantInfo.consumerOrgNo = no;
}

void OidcTokenRequest::AddHelseIdConsumerChildOrgNo(const std::string &no) {
    helseidMultiTenantInfo.consumerChildOrgNo = no;
}

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
        OidcClientAssertion clientAssertion{url, clientId, jwk, helseidMultiTenantInfo};
        jwt = clientAssertion.ToString();
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
