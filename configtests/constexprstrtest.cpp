//
// Created by sigsegv on 1/12/24.
//

#include <string>
#include <iostream>

class Testclass {
public:
    std::string str;
    constexpr Testclass() : str("test\n") {}
};

int main() {
    Testclass t{};
    std::cout << t.str;
}