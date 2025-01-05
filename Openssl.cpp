//
// Created by sigsegv on 12/26/23.
//

#ifdef WIN32
#define _CRT_RAND_S
#include <stdlib.h>
#endif
#include "include/Openssl.h"
#include <memory>
#include <iostream>
#ifndef WIN32
#include <fcntl.h>
#include <unistd.h>
#endif
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>

template <class T> class scope_exit {
private:
    T destr;
public:
    constexpr scope_exit(T destr) : destr(destr) {}
    ~scope_exit() {
        destr();
    }
};

void Openssl::Seed(int bytes) {
    std::unique_ptr<uint8_t, void (*)(uint8_t *)> buf{(uint8_t *) malloc(bytes), [] (uint8_t *release) {free((void *) release);}};
#ifdef WIN32
    for (int i = 0; i < bytes; i += sizeof(int)) {
        unsigned int randomValue;
        if (rand_s(&randomValue) != 0) {
            std::cerr << "rand_s failed\n";
            throw std::exception();
        }
        auto destIndex = i * sizeof(decltype(randomValue));
        auto destIndexLimit = destIndex + sizeof(decltype(randomValue));
        uint8_t *bufPtr = &(*buf);
        if (destIndexLimit <= bytes) {
            auto *destPtr = reinterpret_cast<decltype(randomValue) *>(&(bufPtr[destIndex]));
            *destPtr = randomValue;
        } else {
            auto *srcPtr = reinterpret_cast<uint8_t *>(&randomValue);
            if (bytes > destIndex) {
                destIndexLimit = bytes;
                for (auto j = destIndex; j < destIndexLimit; j++) {
                    bufPtr[j] = srcPtr[j - destIndex];
                }
            }
        }
    }
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        std::cerr << "Open failed: /dev/urandom\n";
        throw std::exception();
    }
    scope_exit fdguard{[fd] () { close(fd); }};
    int rd = read(fd, (void *) &(*buf), bytes);
    if (rd < bytes) {
        std::cerr << "Unable to get seed bytes from /dev/urandom\n";
        throw std::exception();
    }
#endif
    RAND_seed((const void *) &(*buf), bytes);
}

std::string Openssl::GetError() {
    auto errcode = ERR_get_error();
    std::string errstr{};
    errstr.resize(256, '\0');
    ERR_error_string_n(errcode, errstr.data(), errstr.size());
    {
        auto len = strlen(errstr.data());
        if (len < errstr.size()) {
            errstr.resize(len);
        }
    }
    return errstr;
}