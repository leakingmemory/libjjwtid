//
// Created by sigsegv on 12/30/23.
//

#include "include/JwkPemRsaKey.h"
#include <nlohmann/json.hpp>
#include "include/Base64.h"

std::string JwkPemRsaKey::ToJwk() const {
    nlohmann::json jwkJson{};
    Base64UrlEncoding encoding{};
    jwkJson.emplace("kty", "RSA");
    jwkJson.emplace("d", encoding.Encode(d.operator std::string()));
    jwkJson.emplace("dp", encoding.Encode(dp.operator std::string()));
    jwkJson.emplace("dq", encoding.Encode(dq.operator std::string()));
    jwkJson.emplace("e", encoding.Encode(e.operator std::string()));
    jwkJson.emplace("n", encoding.Encode(n.operator std::string()));
    jwkJson.emplace("p", encoding.Encode(p.operator std::string()));
    jwkJson.emplace("q", encoding.Encode(q.operator std::string()));
    jwkJson.emplace("qi", encoding.Encode(qi.operator std::string()));
    return jwkJson.dump();
}

std::string JwkPemRsaKey::ToPublicJwk() const {
    nlohmann::json jwkJson{};
    Base64UrlEncoding encoding{};
    jwkJson.emplace("kty", "RSA");
    jwkJson.emplace("e", encoding.Encode(e));
    jwkJson.emplace("n", encoding.Encode(n));
    return jwkJson.dump();
}

void JwkPemRsaKey::FromJwk(const std::string &json) {
    nlohmann::json jwkJson = nlohmann::json::parse(json);
    if (!jwkJson.contains("kty") || !jwkJson["kty"].is_string()) {
        throw std::exception();
    }
    {
        std::string kty = jwkJson["kty"];
        if (kty != "RSA") {
            throw std::exception();
        }
    }
    bool pubkey{true};
    bool privkey{true};
    if (!jwkJson.contains("d") || !jwkJson["d"].is_string()) {
        privkey = false;
    }
    if (!jwkJson.contains("dp") || !jwkJson["dp"].is_string()) {
        privkey = false;
    }
    if (!jwkJson.contains("dq") || !jwkJson["dq"].is_string()) {
        privkey = false;
    }
    if (!jwkJson.contains("e") || !jwkJson["e"].is_string()) {
        pubkey = false;
        privkey = false;
    }
    if (!jwkJson.contains("n") || !jwkJson["n"].is_string()) {
        pubkey = false;
        privkey = false;
    }
    if (!jwkJson.contains("p") || !jwkJson["p"].is_string()) {
        privkey = false;
    }
    if (!jwkJson.contains("q") || !jwkJson["q"].is_string()) {
        privkey = false;
    }
    if (!pubkey && !privkey) {
        throw std::exception();
    }

    if (!privkey) {
        std::string e = jwkJson["e"];
        std::string n = jwkJson["n"];

        Base64UrlEncoding encoding{};
        this->e = encoding.Decode(e);
        this->n = encoding.Decode(n);
        return;
    }

    std::string d = jwkJson["d"];
    std::string dp = jwkJson["dp"];
    std::string dq = jwkJson["dq"];
    std::string e = jwkJson["e"];
    std::string n = jwkJson["n"];
    std::string p = jwkJson["p"];
    std::string q = jwkJson["q"];
    std::string qi{};
    if (jwkJson.contains("qi") && jwkJson["qi"].is_string()) {
        qi = jwkJson["qi"];
    }

    Base64UrlEncoding encoding{};
    this->d = encoding.Decode(d);
    this->dp = encoding.Decode(dp);
    this->dq = encoding.Decode(dq);
    this->e = encoding.Decode(e);
    this->n = encoding.Decode(n);
    this->p = encoding.Decode(p);
    this->q = encoding.Decode(q);
    this->qi = !qi.empty() ? encoding.Decode(qi) : "";
}
