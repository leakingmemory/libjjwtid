//
// Created by sigsegv on 1/13/24.
//

#ifndef LIBJJWTID_CONFIG_H
#define LIBJJWTID_CONFIG_H

#include "cpplevel.h"

#if (LIBJJWTID_CPPLEVEL >= 23 && LIBJJWTID_HAS_CONSTEXPRSTRING)
#define LIBJJWTID_CONSTEXPR_STRING constexpr
#else
#define LIBJJWTID_CONSTEXPR_STRING
#endif


#endif //LIBJJWTID_CONFIG_H
