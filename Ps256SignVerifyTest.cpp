//
// Created by sigsegv on 11/13/26.
//

#include "include/Ps256.h"
#include "include/Jwt.h"
#include "include/JwkPemRsaKey.h"
#include "include/Openssl.h"
#include <string>
#include <iostream>

int main() {
    Openssl::Seed(256 / 8);
    JwkPemRsaKey key{};
    key.GenerateRandom();
    std::string token{};
    {
        Jwt jwt{};
        jwt.Body()->Add("sub", "test");
        Ps256 ps256{key.ToSigningKey()};
        ps256.Sign(jwt);
        token = jwt.ToString();
    }
    {
        Jwt jwt{token};
        Ps256 ps256{key.ToVerificationKey()};
        if (!ps256.Verify(jwt)) {
            std::cerr << "Verification failed" << std::endl;
            return 1;
        }
    }
    {
        JwkPemRsaKey wrongKey{};
        wrongKey.GenerateRandom();
        Jwt jwt{token};
        Ps256 ps256{wrongKey.ToVerificationKey()};
        if (ps256.Verify(jwt)) {
            std::cerr << "Verification with wrong key succeeded when it should have failed" << std::endl;
            return 1;
        }
    }
    {
        std::string tampered{token};
        tampered[tampered.size() - 2] = tampered[tampered.size() - 2] == 'A' ? 'B' : 'A';
        Jwt jwt{tampered};
        Ps256 ps256{key.ToVerificationKey()};
        if (ps256.Verify(jwt)) {
            std::cerr << "Verification of tampered signature succeeded when it should have failed" << std::endl;
            return 1;
        }
    }
}
