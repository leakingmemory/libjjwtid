//
// Created by sigsegv on 11/13/26.
//

#include "include/Ps256.h"
#include "include/Jwt.h"
#include "include/SigningKey.h"
#include "include/VerificationKey.h"
#include "include/Base64.h"

void Ps256::Sign(Jwt &jwt) const {
    jwt.Header()->Add("alg", "PS256");
    std::string content = jwt.ToStringWithoutSignature();
    std::string signature = signingKey->SignPss(content);
    Base64UrlEncoding encoding{};
    jwt.SetSignature(encoding.Encode(signature));
}

bool Ps256::Verify(Jwt &jwt) const {
    std::string content = jwt.GetUnverifiedHeader();
    content.append(".");
    content.append(jwt.GetUnverifiedBody());
    Base64UrlEncoding encoding{};
    if (verificationKey->VerifyPss(content, encoding.Decode(jwt.GetSignature()))) {
        auto header = std::make_shared<JwtPart>(jwt.GetUnverifiedHeader());
        auto body = std::make_shared<JwtPart>(jwt.GetUnverifiedBody());
        jwt.SetVerified(header, body);
        return true;
    } else {
        return false;
    }
}
