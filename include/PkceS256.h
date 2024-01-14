//
// Created by sigsegv on 12/20/23.
//

#ifndef DRWHATSNOT_PKCES256_H
#define DRWHATSNOT_PKCES256_H

#include "sha2alg.h"
#include "Base64.h"

class PkceS256 {
private:
    std::string verifier;
public:
    PkceS256();
    LIBJJWTID_CONSTEXPR_STRING explicit PkceS256(const std::string &verifier) : verifier(verifier) {};
    LIBJJWTID_CONSTEXPR_STRING explicit PkceS256(std::string &&verifier) : verifier(std::move(verifier)) {};
    [[nodiscard]] constexpr bool IsValid() const {
        return Base64UrlEncoding::DecodingOutputSize(verifier.size()) == 32;
    }
    constexpr void CalculateChallenge(std::string &challenge) const {
        Base64UrlEncoding base64{};
        sha256 sha = sha256::Digest(verifier);
        uint8_t hash[32];
        sha.Result(hash);
        base64.Encode(challenge, hash, 32);
    }
    [[nodiscard]] std::string GetChallenge() const;
    [[nodiscard]] LIBJJWTID_CONSTEXPR_STRING std::string GetVerifier() const {
        return verifier;
    }
};


#endif //DRWHATSNOT_PKCES256_H
