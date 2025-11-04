//
// Created by sigsegv on 11/4/25.
//

#ifndef LIBJJWTID_HELSEIDMULTITENANTINFO_H
#define LIBJJWTID_HELSEIDMULTITENANTINFO_H

#include <string>

struct HelseidMultiTenantInfo {
    std::string journalId{};
    std::string consumerOrgNo{};
    std::string consumerChildOrgNo{};

    bool IsSet() const {
        return !journalId.empty() || !consumerOrgNo.empty() || !consumerChildOrgNo.empty();
    }
};

#endif //LIBJJWTID_HELSEIDMULTITENANTINFO_H