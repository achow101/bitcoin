// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MUSIG_H
#define BITCOIN_MUSIG_H

#include <pubkey.h>

#include <optional>
#include <vector>

struct secp256k1_musig_keyagg_cache;
class MuSig2SecNonceImpl;
struct secp256k1_musig_secnonce;

//! MuSig2 chaincode as defined by BIP 328
using namespace util::hex_literals;
constexpr uint256 MUSIG_CHAINCODE{"868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965"_hex_u8};

//! Create a secp256k1_musig_keyagg_cache from the pubkeys in their current order. This is necessary for most MuSig2 operations
bool GetMuSig2KeyAggCache(const std::vector<CPubKey>& pubkeys, secp256k1_musig_keyagg_cache& keyagg_cache);
//! Retrieve the full aggregate pubkey from the secp256k1_musig_keyagg_cache
std::optional<CPubKey> GetCPubKeyFromMuSig2KeyAggCache(secp256k1_musig_keyagg_cache& cache);
//! Compute the full aggregate pubkey from the given participant pubkeys in their current order
std::optional<CPubKey> MuSig2AggregatePubkeys(const std::vector<CPubKey>& pubkeys);

/**
 * MuSig2SecNonce encapsulates a secret nonce in use in a MuSig2 signing session.
 * Since this nonce persists outside of libsecp256k1 signing code, we must handle
 * its construction and destruction ourselves.
 * The secret nonce must be kept a secret, otherwise the private key may be leaked.
 * As such, it needs to be treated in the same way that CKeys are treated.
 * So this class handles the secure allocation of the secp256k1_musig_secnonce object
 * that libsecp256k1 uses, and only gives out references to this object to avoid
 * any possibility of copies being made. Furthermore, objects of this class are not
 * copyable to avoid nonce reuse.
*/
class MuSig2SecNonce
{
private:
    std::unique_ptr<MuSig2SecNonceImpl> m_impl;

public:
    MuSig2SecNonce();
    MuSig2SecNonce(MuSig2SecNonce&&) noexcept;
    MuSig2SecNonce& operator=(MuSig2SecNonce&&) noexcept;
    ~MuSig2SecNonce();

    // Delete copy constructors
    MuSig2SecNonce(const MuSig2SecNonce&) = delete;
    MuSig2SecNonce& operator=(const MuSig2SecNonce&) = delete;

    secp256k1_musig_secnonce* Get() const;
    void Invalidate();
    bool IsValid();
};

#endif // BITCOIN_MUSIG_H
