// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_RSA_H
#define BITCOIN_CRYPTO_RSA_H

class Int4096
{
private:

public:
    static constexpr size_t BYTE_SIZE = 512;

#ifdef __SIZEOF_INT128__
    typedef unsigned __int128 double_limb_t;
    typedef signed __int128 signed_double_limb_t;
    typedef uint64_t limb_t;
    typedef int64_t signed_limb_t;
    static constexpr int LIMBS = 64;
    static constexpr int LIMB_SIZE = 64;
#else
    typedef uint64_t double_limb_t;
    typedef int64_t signed_double_limb_t;
    typedef uint32_t limb_t;
    typedef int32_t signed_limb_t;
    static constexpr int LIMBS = 128;
    static constexpr int LIMB_SIZE = 32;
#endif
    limb_t limbs[LIMBS];
};

#endif // BITCOIN_CRYPTO_RSA_H
