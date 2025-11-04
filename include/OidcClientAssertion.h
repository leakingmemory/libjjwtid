//
// Created by sigsegv on 11/4/25.
//

#ifndef LIBJJWTID_OIDCCLIENTASSERTION_H
#define LIBJJWTID_OIDCCLIENTASSERTION_H

#include "HelseidMultiTenantInfo.h"
#include <string>

class OidcClientAssertion {
private:
    std::string url;
    std::string clientId;
    std::string jwk;
    HelseidMultiTenantInfo helseidMultiTenantInfo{};
public:
    OidcClientAssertion(const std::string &audienceUrl, const std::string &clientId, const std::string &jwk,
                    const HelseidMultiTenantInfo &multiTenantInfo = {});
    std::string ToString() const;
};

#endif //LIBJJWTID_OIDCCLIENTASSERTION_H