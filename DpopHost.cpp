//
// Created by sigsegv on 4/7/25.
//

#include <random>
#include <nlohmann/json.hpp>
#include "include/DpopHost.h"
#include "include/Jwt.h"
#include "include/Base64.h"
#include "include/Rs256.h"
#include "include/sha2alg.h"

class DpopException : public std::exception {
private:
    std::string str{};
public:
    DpopException(const std::string &str) : str(str) {}
    const char * what() const noexcept override;
};

const char *DpopException::what() const noexcept {
    return str.c_str();
}

DpopHost::DpopHost(Jwt dpop) {
    auto header = std::make_shared<JwtPart>(dpop.GetUnverifiedHeader());
    auto jwk = header->GetValue("jwk");
    auto jsonString = jwk ? jwk->ToJsonStr() : "";
    if (!jsonString.empty()) {
        this->jwk.FromJwk(jsonString);
        publicKey = true;
    }
}

std::string DpopHost::Generate(const std::string &method, const std::string &url, const std::string &accessToken, const std::string &nonce) {
    Jwt jwt{JwtType::DPOP};
    auto body = jwt.Body();
    {
        std::string jti{};
        jti.reserve(Base64UrlEncoding::EncodingOutputSize(12));
        uint8_t rand[12];
        {
            std::random_device rd{};
#ifdef WIN32
            std::uniform_int_distribution<int> dist{0, 255};
            for (int i = 0; i < 12; i++) {
                rand[i] = static_cast<uint8_t>(dist(rd));
            }
#else
            std::uniform_int_distribution<uint8_t> dist{std::numeric_limits<uint8_t>::min(),
                                                        std::numeric_limits<uint8_t>::max()};
            for (int i = 0; i < 12; i++) {
                rand[i] = dist(rd);
            }
#endif
        }
        Base64UrlEncoding encoding{};
        encoding.Encode(jti, rand, 32);
        body->Add("jti", jti);
        body->Add("htm", method);
        auto iat = std::time(nullptr);
        body->Add("iat", iat);
        body->Add("htu", url);
        if (!accessToken.empty()) {
            auto sh256 = sha256::Digest(accessToken);
            uint8_t data[32];
            sh256.Result(data);
            Base64UrlEncoding encoding{};
            body->Add("ath", encoding.Encode(data, 32));
        }
        if (!nonce.empty()) {
            body->Add("nonce", nonce);
        }
    }
    if (!privateKey) {
        if (publicKey) {
            throw DpopException("Dpop: Only capable of verifying this host");
        }
        jwk.GenerateRandom();
        privateKey = true;
        publicKey = true;
    }
    auto header = jwt.Header();
    header->Add("alg", "RS256");
    auto jwkPub = jwk.ToPublicJwk();
    header->AddJsonObject("jwk", jwkPub); // str json
    Rs256 rs256{jwk.ToSigningKey()};
    rs256.Sign(jwt);
    return jwt.ToString();
}

bool DpopHost::Verify(Jwt &jwt) const {
    if (!publicKey) {
        throw DpopException("Dpop: No verification key");
    }
    Rs256 rs256{jwk.ToVerificationKey()};
    return rs256.Verify(jwt);
}

bool DpopHost::Verify(Jwt &jwt, const std::string &accessToken, const std::string &nonce) const {
    if (!Verify(jwt)) {
        return false;
    }
    if (!jwt.Body()) {
        return false;
    }
    if (!accessToken.empty()) {
        auto sh256 = sha256::Digest(accessToken);
        uint8_t data[32];
        sh256.Result(data);
        Base64UrlEncoding encoding{};
        if (encoding.Encode(data, 32) != jwt.Body()->GetString("ath")) {
            return false;
        }
    }
    if (!nonce.empty()) {
        if (nonce != jwt.Body()->GetString("nonce")) {
            return false;
        }
    }
    return true;
}
