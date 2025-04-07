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
}