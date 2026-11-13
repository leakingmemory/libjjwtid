//
// Created by sigsegv on 11/13/26.
//

#ifndef DRWHATSNOT_PS256_H
#define DRWHATSNOT_PS256_H

#include <memory>

class SigningKey;
class VerificationKey;
class Jwt;

class Ps256 {
private:
    std::shared_ptr<SigningKey> signingKey;
    std::shared_ptr<VerificationKey> verificationKey;
public:
    Ps256(std::shared_ptr<SigningKey> signingKey) : signingKey(signingKey), verificationKey() {}
    Ps256(std::shared_ptr<VerificationKey> verificationKey) : signingKey(), verificationKey(verificationKey) {}
    void Sign(Jwt &jwt) const;
    bool Verify(Jwt &jwt) const;
};


#endif //DRWHATSNOT_PS256_H
