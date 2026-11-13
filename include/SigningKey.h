//
// Created by sigsegv on 12/31/23.
//

#ifndef DRWHATSNOT_SIGNINGKEY_H
#define DRWHATSNOT_SIGNINGKEY_H

#include <string>

class SigningKey {
public:
    virtual std::string Sign(const std::string &content) const = 0;
    virtual std::string SignPss(const std::string &content) const = 0;
};

#endif //DRWHATSNOT_SIGNINGKEY_H
