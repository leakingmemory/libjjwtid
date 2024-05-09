//
// Created by sigsegv on 12/25/23.
//

#include "include/OpensslRsa.h"
#include "include/Openssl.h"
#include <iostream>
#include <memory>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#if (OPENSSL3)
#include <openssl/param_build.h>
#else
#include <bit>
#include "include/sha2alg.h"
#endif

#if (OPENSSL3)
OpensslRsa::OpensslRsa() : rsa(nullptr, [] (EVP_PKEY *) {}) {}

OpensslRsa::OpensslRsa(OpensslRsa &&mv)  noexcept : rsa(nullptr, [] (EVP_PKEY *) {}) {
    rsa = std::move(mv.rsa);
}

static std::unique_ptr<EVP_PKEY,void (*)(EVP_PKEY *)> GeneratePkey(EVP_PKEY_CTX &pctx) {
    EVP_PKEY *pkey{nullptr};
    int res = EVP_PKEY_keygen(&pctx, &pkey);
    if (res <= 0) {
        std::cerr << Openssl::GetError() << "\n";
        throw std::exception();
    }
    std::unique_ptr<EVP_PKEY,void (*)(EVP_PKEY *)> uk{pkey, [] (EVP_PKEY *release) {EVP_PKEY_free(release);}};
    return uk;
}

#else
OpensslRsa::OpensslRsa() : rsa(nullptr, [] (RSA *) {}) {}

OpensslRsa::OpensslRsa(OpensslRsa &&mv)  noexcept : rsa(nullptr, [] (RSA *) {}) {
    rsa = std::move(mv.rsa);
}

static std::unique_ptr<RSA,void (*)(RSA *)> GeneratePkey(BIGNUM *e) {
    std::unique_ptr<RSA,void (*)(RSA *)> rsa{RSA_new(), [] (RSA *release) {RSA_free(release);}};
    auto err = RSA_generate_key_ex(&(*rsa), 2048, e, NULL);
    return rsa;
}

#endif

OpensslRsa::~OpensslRsa() = default;

#if (OPENSSL3)
static std::unique_ptr<EVP_PKEY,void (*)(EVP_PKEY *)> PkeyFromParams(EVP_PKEY_CTX &pctx, OSSL_PARAM *params) {
    EVP_PKEY *pkey{nullptr};
    int res = EVP_PKEY_fromdata(&pctx, &pkey, EVP_PKEY_KEYPAIR, params);
    if (res <= 0) {
        std::cerr << Openssl::GetError() << "\n";
        throw std::exception();
    }
    std::unique_ptr<EVP_PKEY,void (*)(EVP_PKEY *)> uk{pkey, [] (EVP_PKEY *release) {EVP_PKEY_free(release);}};
    return uk;
}

static std::unique_ptr<EVP_PKEY,void (*)(EVP_PKEY *)> PubkeyFromParams(EVP_PKEY_CTX &pctx, OSSL_PARAM *params) {
    EVP_PKEY *pkey{nullptr};
    int res = EVP_PKEY_fromdata(&pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
    if (res <= 0) {
        std::cerr << Openssl::GetError() << "\n";
        throw std::exception();
    }
    std::unique_ptr<EVP_PKEY,void (*)(EVP_PKEY *)> uk{pkey, [] (EVP_PKEY *release) {EVP_PKEY_free(release);}};
    return uk;
}
#endif

bool OpensslRsa::operator==(const OpensslRsa &other) const {
    auto p1 = ExportParams();
    auto p2 = other.ExportParams();
    for (const auto &p : p1) {
        auto f = p2.find(p.first);
        if (f == p2.end()) {
            return false;
        }
        if (p.second.operator std::string() != f->second.operator std::string()) {
            return false;
        }
    }
    for (const auto &p : p2) {
        auto f = p1.find(p.first);
        if (f == p1.end()) {
            return false;
        }
    }
    return true;
}

void OpensslRsa::GenerateRandom(int sizeKey, int exponent) {
#if (OPENSSL3)
    std::unique_ptr<BIGNUM, void (*)(BIGNUM *)> e = {BN_new(), [] (BIGNUM *release) { BN_free(release); }};
    BN_native2bn((unsigned char *) &exponent, sizeof(exponent), &(*e));
    std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX *)> pctx{EVP_PKEY_CTX_new_id( EVP_PKEY_RSA, NULL), [] (EVP_PKEY_CTX *ctx) {EVP_PKEY_CTX_free(ctx);}};
    EVP_PKEY_keygen_init(&(*pctx));
    rsa = std::move(GeneratePkey(*pctx));
#else
    if constexpr (std::endian::native == std::endian::little) {
        exponent = std::byteswap(exponent);
    }
    std::unique_ptr<BIGNUM, void (*)(BIGNUM *)> e = {BN_bin2bn((const unsigned char *) &exponent, sizeof(exponent), NULL), [] (BIGNUM *release) { BN_free(release); }};
    rsa = std::move(GeneratePkey(&(*e)));
#endif
}

std::map<std::string,Bignum> OpensslRsa::ExportParams() const {
    std::map<std::string,Bignum> paramsMap{};
#if (OPENSSL3)
    OSSL_PARAM *params;
    int ret = EVP_PKEY_todata(&(*rsa), EVP_PKEY_KEYPAIR, &params);
    if (ret <= 0) {
        return {};
    }
    for (auto i = 0; params[i].key != NULL; i++) {
        auto *param = &(params[i]);
        std::string key{param->key};
        if (param->data_type != OSSL_PARAM_UNSIGNED_INTEGER) {
            OSSL_PARAM_free(params);
            return {};
        }
        BIGNUM *bignum{NULL};
        if(OSSL_PARAM_get_BN(param, &bignum) == 0) {
            OSSL_PARAM_free(params);
            return {};
        }
        Bignum bn{};
        bn = bignum;
        BN_free(bignum);
        paramsMap.insert_or_assign(key, bn);
    }
    OSSL_PARAM_free(params);
#else
    std::map<std::string,const BIGNUM *> zerorefs{};
    zerorefs.insert_or_assign("n", RSA_get0_n(&(*rsa)));
    zerorefs.insert_or_assign("e", RSA_get0_e(&(*rsa)));
    zerorefs.insert_or_assign("d", RSA_get0_d(&(*rsa)));
    zerorefs.insert_or_assign("rsa-factor1", RSA_get0_p(&(*rsa)));
    zerorefs.insert_or_assign("rsa-factor2", RSA_get0_q(&(*rsa)));
    zerorefs.insert_or_assign("rsa-exponent1", RSA_get0_dmp1(&(*rsa)));
    zerorefs.insert_or_assign("rsa-exponent2", RSA_get0_dmq1(&(*rsa)));
    zerorefs.insert_or_assign("rsa-coefficient1", RSA_get0_iqmp(&(*rsa)));
    for (const auto &zr : zerorefs) {
        Bignum bn{};
        bn = zr.second;
        paramsMap.insert_or_assign(zr.first, bn);
    }
#endif
    return paramsMap;
}

void OpensslRsa::ImportParams(const std::map<std::string, Bignum> &params) {
#if (OPENSSL3)
    std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX *)> pctx{EVP_PKEY_CTX_new_id( EVP_PKEY_RSA, NULL), [] (EVP_PKEY_CTX *ctx) {EVP_PKEY_CTX_free(ctx);}};
    EVP_PKEY_fromdata_init(&(*pctx));
    std::unique_ptr<OSSL_PARAM_BLD,void (*)(OSSL_PARAM_BLD *)> bld{
            OSSL_PARAM_BLD_new(),
            [](OSSL_PARAM_BLD *release) { OSSL_PARAM_BLD_free(release); }
    };
    for (const auto &param : params) {
        if (!OSSL_PARAM_BLD_push_BN(&(*bld), param.first.c_str(), param.second.bn)) {
            throw std::exception();
        }
    }
    std::unique_ptr<OSSL_PARAM,void (*)(OSSL_PARAM *)> opensslParams{nullptr, [] (OSSL_PARAM *) {}};
    {
        OSSL_PARAM *p = OSSL_PARAM_BLD_to_param(&(*bld));
        if (p == NULL) {
            throw std::exception();
        }
        opensslParams = {p, [] (OSSL_PARAM *release) {OSSL_PARAM_free(release);}};
    }
    rsa = std::move(PkeyFromParams(*pctx, &(*opensslParams)));
#else
    {
        std::unique_ptr<RSA, void (*)(RSA *)> pkey{RSA_new(), [](RSA *release) { RSA_free(release); }};
        rsa = std::move(pkey);
    }
    auto findN = params.find("n");
    auto findE = params.find("e");
    auto findD = params.find("d");
    if (findN != params.end() && findE != params.end()) {
        BIGNUM *n = BN_dup(findN->second.bn);
        BIGNUM *e = BN_dup(findE->second.bn);
        BIGNUM *d = findD != params.end() ? BN_dup(findD->second.bn) : nullptr;
        RSA_set0_key(&(*rsa), n, e, d);
    }
    auto findP = params.find("rsa-factor1");
    auto findQ = params.find("rsa-factor2");
    if (findP != params.end() && findQ != params.end()) {
        BIGNUM *p = BN_dup(findP->second.bn);
        BIGNUM *q = BN_dup(findQ->second.bn);
        RSA_set0_factors(&(*rsa), p, q);
    }
    auto findDmp1 = params.find("rsa-exponent1");
    auto findDmq1 = params.find("rsa-exponent2");
    auto findIqmp = params.find("rsa-coefficient1");
    if (findDmp1 != params.end() && findDmq1 != params.end() && findIqmp != params.end()) {
        BIGNUM *dmp1 = BN_dup(findDmp1->second.bn);
        BIGNUM *dmq1 = BN_dup(findDmq1->second.bn);
        BIGNUM *iqmp = BN_dup(findIqmp->second.bn);
        RSA_set0_crt_params(&(*rsa), dmp1, dmq1, iqmp);
    }
#endif
}

void OpensslRsa::ImportPublicParams(const std::map<std::string, Bignum> &params) {
#if (OPENSSL4)
    std::unique_ptr<EVP_PKEY_CTX, void (*)(EVP_PKEY_CTX *)> pctx{EVP_PKEY_CTX_new_id( EVP_PKEY_RSA, NULL), [] (EVP_PKEY_CTX *ctx) {EVP_PKEY_CTX_free(ctx);}};
    EVP_PKEY_fromdata_init(&(*pctx));
    std::unique_ptr<OSSL_PARAM_BLD,void (*)(OSSL_PARAM_BLD *)> bld{
            OSSL_PARAM_BLD_new(),
            [](OSSL_PARAM_BLD *release) { OSSL_PARAM_BLD_free(release); }
    };
    for (const auto &param : params) {
        if (!OSSL_PARAM_BLD_push_BN(&(*bld), param.first.c_str(), param.second.bn)) {
            throw std::exception();
        }
    }
    std::unique_ptr<OSSL_PARAM,void (*)(OSSL_PARAM *)> opensslParams{nullptr, [] (OSSL_PARAM *) {}};
    {
        OSSL_PARAM *p = OSSL_PARAM_BLD_to_param(&(*bld));
        if (p == NULL) {
            throw std::exception();
        }
        opensslParams = {p, [] (OSSL_PARAM *release) {OSSL_PARAM_free(release);}};
    }
    rsa = std::move(PubkeyFromParams(*pctx, &(*opensslParams)));
#else
    {
        std::unique_ptr<RSA, void (*)(RSA *)> pkey{RSA_new(), [](RSA *release) { RSA_free(release); }};
        rsa = std::move(pkey);
    }
    auto findN = params.find("n");
    auto findE = params.find("e");
    if (findN != params.end() && findE != params.end()) {
        BIGNUM *n = BN_dup(findN->second.bn);
        BIGNUM *e = BN_dup(findE->second.bn);
        RSA_set0_key(&(*rsa), n, e, nullptr);
    }
#endif
}

std::string OpensslRsa::ToTraditionalPrivatePem() const {
    std::string pem{};
    std::unique_ptr<BIO,void (*)(BIO*)> bio{BIO_new(BIO_s_mem()), [] (auto *release) {BIO_free(release);}};
#if (OPENSSL3)
    auto ret = PEM_write_bio_PrivateKey_traditional(&(*bio), &(*rsa), NULL, NULL, 0, NULL, NULL);
#else
    auto ret = PEM_write_bio_RSAPrivateKey(&(*bio), &(*rsa), NULL, NULL, 0, NULL, NULL);
#endif
    if (ret <= 0) {
        return "";
    }
    size_t size{0};
    size = BIO_pending(&(*bio));
    pem.resize(size);
    BIO_read(&(*bio), pem.data(), size);
    return pem;
}

std::string OpensslRsa::ToPublicPem() const {
    std::string pem{};
    std::unique_ptr<BIO,void (*)(BIO*)> bio{BIO_new(BIO_s_mem()), [] (auto *release) {BIO_free(release);}};
#if (OPENSSL3)
    auto ret = PEM_write_bio_PUBKEY(&(*bio), &(*rsa));
#else
    auto ret = PEM_write_bio_RSAPublicKey(&(*bio), &(*rsa));
#endif
    if (ret <= 0) {
        return "";
    }
    size_t size{0};
    size = BIO_pending(&(*bio));
    pem.resize(size);
    BIO_read(&(*bio), pem.data(), size);
    return pem;
}

std::string OpensslRsa::Sign(const std::string &content) const {
#if (OPENSSL3)
    std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX *)> ctx{
        EVP_MD_CTX_new(),
        [] (EVP_MD_CTX *release) { EVP_MD_CTX_free(release); }
    };
    if (!ctx) {
        std::cerr << Openssl::GetError() << "\n";
        throw std::exception();
    }
    if (EVP_DigestSignInit(&(*ctx), NULL, EVP_sha256(), NULL, &(*rsa)) <= 0) {
        std::cerr << Openssl::GetError() << "\n";
        throw std::exception();
    }
    size_t siglen{0};
    if (EVP_DigestSignUpdate(&(*ctx), content.data(), content.size()) <= 0) {
        std::cerr << Openssl::GetError() << "\n";
        throw std::exception();
    }
    if (EVP_DigestSignFinal(&(*ctx), NULL, &siglen) <= 0) {
        std::cerr << Openssl::GetError() << "\n";
        throw std::exception();
    }
    std::string signature{};
    signature.resize(siglen);
    if (EVP_DigestSignFinal(&(*ctx), (unsigned char *) signature.data(), &siglen) <= 0) {
        std::cerr << Openssl::GetError() << "\n";
        throw std::exception();
    }
#else
    sha256::result_type digest{};
    {
        sha256 digester{};
        auto remaining = content.size();
        const sha256::chunk_type *c = (const sha256::chunk_type *) content.data();
        while (remaining > sizeof(*c)) {
            digester.Consume(*c);
            c = (const sha256::chunk_type *) (((const char *) c) + sizeof(*c));
            remaining -= sizeof(*c);
        }
        digester.Final((const unsigned char *) c, remaining);
        digester.Result(digest);
    }
    unsigned int siglen = RSA_size(&(*rsa));
    std::string signature{};
    signature.resize(siglen);
    auto res = RSA_sign(NID_sha256, digest, sizeof(digest), (unsigned char *) signature.data(), &siglen, &(*rsa));
    if (res <= 0) {
        std::cerr << Openssl::GetError() << "\n";
        throw std::exception();
    }
#endif
    return signature;
}

bool OpensslRsa::Verify(const std::string &content, const std::string &signature) const {
#if (OPENSSL3)
    std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX *)> ctx{
            EVP_MD_CTX_new(),
            [] (EVP_MD_CTX *release) { EVP_MD_CTX_free(release); }
    };
    if (!ctx) {
        std::cerr << Openssl::GetError() << "\n";
        throw std::exception();
    }
    if (EVP_DigestVerifyInit(&(*ctx), NULL, EVP_sha256(), NULL, &(*rsa)) <= 0) {
        std::cerr << Openssl::GetError() << "\n";
        throw std::exception();
    }
    if (EVP_DigestVerifyUpdate(&(*ctx), content.data(), content.size()) <= 0) {
        std::cerr << Openssl::GetError() << "\n";
        return false;
    }
    if (EVP_DigestVerifyFinal(&(*ctx), (unsigned char *) signature.data(), signature.size()) != 1) {
        std::cerr << Openssl::GetError() << "\n";
        return false;
    }
    return true;
#else
    sha256::result_type digest{};
    {
        sha256 digester{};
        auto remaining = content.size();
        const sha256::chunk_type *c = (const sha256::chunk_type *) content.data();
        while (remaining > sizeof(*c)) {
            digester.Consume(*c);
            c = (const sha256::chunk_type *) (((const char *) c) + sizeof(*c));
            remaining -= sizeof(*c);
        }
        digester.Final((const unsigned char *) c, remaining);
        digester.Result(digest);
    }
    auto res = RSA_verify(NID_sha256, digest, sizeof(digest), (unsigned char *) signature.data(), signature.size(), &(*rsa));
    if (res != 1) {
        std::cerr << Openssl::GetError() << "\n";
        return false;
    }
    return true;
#endif
}
