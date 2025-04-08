//
// Created by sigsegv on 4/7/25.
//

#ifndef LIBJJWTID_DPOPHOST_H
#define LIBJJWTID_DPOPHOST_H

#include <string>
#include "JwkPemRsaKey.h"
#include "Jwt.h"

class DpopHost {
private:
    JwkPemRsaKey jwk{};
    bool privateKey{false};
    bool publicKey{false};
public:
    constexpr DpopHost() = default;
    DpopHost(Jwt dpop);
    std::string Generate(const std::string &method, const std::string &url, const std::string &accessToken = "", const std::string &nonce = "");
    bool Verify(Jwt &jwt) const;
    bool Verify(Jwt &jwt, const std::string &accessToken, const std::string &nonce) const;
};


#endif //LIBJJWTID_DPOPHOST_H
