//
// Created by sigsegv on 11/4/25.
//

#include "include/OidcClientAssertion.h"
#include "include/SigningKey.h"
#include "include/JwkPemRsaKey.h"
#include "include/Jwt.h"
#include <memory>
#include <boost/uuid/uuid_generators.hpp> // for random_generator
#include <boost/uuid/uuid_io.hpp> // for to_string
#include "include/Ps256.h"

OidcClientAssertion::OidcClientAssertion(const std::string &audienceUrl, const std::string &clientId, const std::string &jwk,
                                 const HelseidMultiTenantInfo &multiTenantInfo)
    : url(audienceUrl), clientId(clientId), jwk(jwk), helseidMultiTenantInfo(multiTenantInfo) {}

std::string OidcClientAssertion::ToString() const {
    std::string jwt{};
    {
        std::shared_ptr<SigningKey> signingKey{};
        {
            JwkPemRsaKey rsa{};
            rsa.FromJwk(jwk);
            signingKey = rsa.ToSigningKey();
        }
        auto iat = std::time(nullptr);
        Jwt token{JwtType::CLIENT_AUTHENTICATION};
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
        token.Body()->Add("aud", url);
        if (helseidMultiTenantInfo.IsSet()) {
            JwtPartArray arr{};
            if (!helseidMultiTenantInfo.journalId.empty()) {
                JwtPartObject jid{};
                jid.Add("type", "nhn:sfm:journal-id");
                JwtPartObject val{};
                val.Add("journal_id", helseidMultiTenantInfo.journalId);
                jid.Add("value", val);
                arr.Add(jid);
            }
            if (!helseidMultiTenantInfo.consumerOrgNo.empty() || !helseidMultiTenantInfo.consumerChildOrgNo.empty()) {
                std::string strval{"NO:ORGNR"};
                if (!helseidMultiTenantInfo.consumerOrgNo.empty()) {
                    strval.append(":");
                    strval.append(helseidMultiTenantInfo.consumerOrgNo);
                }
                if (!helseidMultiTenantInfo.consumerChildOrgNo.empty()) {
                    strval.append(":");
                    strval.append(helseidMultiTenantInfo.consumerChildOrgNo);
                }
                JwtPartObject auth{};
                auth.Add("type", "helseid_authorization");
                JwtPartObject pr{};
                JwtPartObject org{};
                JwtPartObject identifier{};
                identifier.Add("system", "urn:oid:1.0.6523");
                identifier.Add("type", "ENH");
                identifier.Add("value", strval);
                org.Add("identifier", identifier);
                pr.Add("organization", org);
                auth.Add("practitioner_role", pr);
                arr.Add(auth);
            }
            token.Body()->Add("authorization_details", arr);
        }
        Ps256 ps256{signingKey};
        ps256.Sign(token);
        jwt = token.ToString();
    }
    return jwt;
}
