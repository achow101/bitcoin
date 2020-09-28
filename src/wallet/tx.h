// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_TX_H
#define BITCOIN_WALLET_TX_H

#include <primitives/transaction.h>
#include <script/script.h>

class COutput
{
public:
    CTxOut txout;
    COutPoint outpoint;
    int nDepth;

    /** Pre-computed estimated size of this output as a fully-signed input in a transaction. Can be -1 if it could not be calculated */
    int nInputBytes;

    /** Whether we have the private keys to spend this output */
    bool fSpendable;

    /** Whether we know how to spend this output, ignoring the lack of keys */
    bool fSolvable;

    /**
     * Whether this output is considered safe to spend. Unconfirmed transactions
     * from outside keys and unconfirmed replacement transactions are considered
     * unsafe and will not be used to fund new spending transactions.
     */
    bool fSafe;

    /** Whether this output is in a transaction we created */
    bool m_from_me;

    /** The transaction time */
    int64_t m_time;

    COutput(const CTxOut& txout, const COutPoint& outpoint, int nDepthIn, bool fSpendableIn, bool fSolvableIn, bool fSafeIn, bool from_me, int input_bytes, int64_t time) :
        txout(txout),
        outpoint(outpoint),
        nDepth(nDepthIn),
        nInputBytes(input_bytes),
        fSpendable(fSpendableIn),
        fSolvable(fSolvableIn),
        fSafe(fSafeIn),
        m_from_me(from_me),
        m_time(time)
    {}

    std::string ToString() const;

    CAmount GetValue() const;
    int64_t GetTxTime() const;
    const CScript& GetScriptPubKey() const;
    const uint256& GetTxHash() const;
    uint32_t GetVoutIndex() const;
    const CTxOut& GetTxOut() const;
};

#endif // BITCOIN_WALLET_TX_H
