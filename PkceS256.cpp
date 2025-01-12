//
// Created by sigsegv on 12/20/23.
//

#include "include/PkceS256.h"
#include <random>

PkceS256::PkceS256() : verifier() {
    verifier.reserve(Base64UrlEncoding::EncodingOutputSize(32));
    uint8_t rand[32];
    {
        std::random_device rd{};
#ifdef WIN32
        std::uniform_int_distribution<int> dist{0, 255};
        for (int i = 0; i < 32; i++) {
            rand[i] = static_cast<uint8_t>(dist(rd));
        }
#else
        std::uniform_int_distribution<uint8_t> dist{std::numeric_limits<uint8_t>::min(),
                                                    std::numeric_limits<uint8_t>::max()};
        for (int i = 0; i < 32; i++) {
            rand[i] = dist(rd);
        }
#endif
    }
    Base64UrlEncoding encoding{};
    encoding.Encode(verifier, rand, 32);
}

std::string PkceS256::GetChallenge() const {
    std::string result{};
    CalculateChallenge(result);
    return result;
}

#if (LIBJJWTID_CPPLEVEL >= 23 && LIBJJWTID_HAS_CONSTEXPRSTRING)

constexpr bool AssertChallenge(const std::string &expected_challenge, const std::string &verifier) {
    std::string challenge{};
    PkceS256 pkce{verifier};
    pkce.CalculateChallenge(challenge);
    return challenge == expected_challenge;
}

static_assert(AssertChallenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));

#endif