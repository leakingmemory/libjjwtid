//
// Created by sigsegv on 12/25/23.
//

#ifndef DRWHATSNOT_TOKENURL_H
#define DRWHATSNOT_TOKENURL_H

#include <string>
#include <map>
#include <vector>

struct OidcPostRequest {
    std::string url{};
    std::map<std::string,std::string> params{};
};

struct HelseidMultiTenantInfo {
    std::string journalId{};
    std::string consumerOrgNo{};
    std::string consumerChildOrgNo{};

    bool IsSet() const {
        return !journalId.empty() || !consumerOrgNo.empty() || !consumerChildOrgNo.empty();
    }
};

class OidcTokenRequest {
private:
    std::string url;
    std::string clientId;
    std::string jwk;
    std::string redirectUri;
    std::string code;
    std::vector<std::string> scope;
    std::string codeVerifier;
    std::string refreshToken;
    HelseidMultiTenantInfo helseidMultiTenantInfo{};
public:
    OidcTokenRequest(const std::string &url, const std::string &clientId, const std::string &jwk, const std::string &redirectUri, const std::string &code, const std::vector<std::string> &scope, const std::string &codeVerifier) : url(url), clientId(clientId), jwk(jwk), redirectUri(redirectUri), code(code), scope(scope), codeVerifier(codeVerifier), refreshToken() {}
    OidcTokenRequest(const std::string &url, const std::string &clientId, const std::string &jwk, const std::vector<std::string> &scope, const std::string &refreshToken) : url(url), clientId(clientId), jwk(jwk), redirectUri(), code(), scope(scope), codeVerifier(), refreshToken(refreshToken) {}
    void AddHelseIdJournalId(const std::string &);
    void AddHelseIdConsumerOrgNo(const std::string &);
    void AddHelseIdConsumerChildOrgNo(const std::string &);
    OidcPostRequest GetTokenRequest() const;
};


#endif //DRWHATSNOT_TOKENURL_H
