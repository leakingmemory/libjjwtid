//
// Created by sigsegv on 4/7/25.
//

#include "include/DpopHost.h"
#include <string>
#include <iostream>

int main() {
    DpopHost source{};
    DpopHost dest{};
    std::string firstPop = source.Generate("POST", "https://example.com/foo");
    {
        Jwt jwt{firstPop};
        {
            DpopHost verifier{jwt};
            dest = verifier;
        }
        if (!dest.Verify(jwt)) {
            std::cerr << "Verification failed" << std::endl;
            return 1;
        }
    }
    std::string secondPop = source.Generate("POST", "https://example.com/foo", "accesstoken", "nonce");
    {
        Jwt jwt{secondPop};
        if (!dest.Verify(jwt, "accesstoken", "nonce")) {
            std::cerr << "Second verification failed" << std::endl;
            return 1;
        }
    }
    std::string thirdPop = source.Generate("POST", "https://example.com/foo", "accesstoken", "nonce");
    {
        Jwt jwt{thirdPop};
        if (dest.Verify(jwt, "wrongtoken", "nonce")) {
            std::cerr << "Second verification succeeded when it should have failed" << std::endl;
            return 1;
        }
    }
    DpopHost wrongSource{};
    std::string fourthPop = wrongSource.Generate("POST", "https://example.com/foo", "accesstoken", "nonce");
    {
        Jwt jwt{fourthPop};
        if (dest.Verify(jwt, "accesstoken", "nonce")) {
            std::cerr << "Fourth verification succeeded when it should have failed" << std::endl;
            return 1;
        }
    }
}