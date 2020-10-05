// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_TX_H
#define BITCOIN_WALLET_TX_H

#include <primitives/transaction.h>
#include <script/script.h>

/* Confirmation includes tx status and a triplet of {block height/block hash/tx index in block}
 * at which tx has been confirmed. All three are set to 0 if tx is unconfirmed or abandoned.
 * Meaning of these fields changes with CONFLICTED state where they instead point to block hash
 * and block height of the deepest conflicting tx.
 */
struct Confirmation {
    /* New transactions start as UNCONFIRMED. At BlockConnected,
     * they will transition to CONFIRMED. In case of reorg, at BlockDisconnected,
     * they roll back to UNCONFIRMED. If we detect a conflicting transaction at
     * block connection, we update conflicted tx and its dependencies as CONFLICTED.
     * If tx isn't confirmed and outside of mempool, the user may switch it to ABANDONED
     * by using the abandontransaction call. This last status may be override by a CONFLICTED
     * or CONFIRMED transition.
     */
    enum Status {
        UNCONFIRMED,
        CONFIRMED,
        CONFLICTED,
        ABANDONED
    };

    Status status;
    int block_height;
    uint256 hashBlock;
    int nIndex;
    Confirmation(Status s = UNCONFIRMED, int b = 0, uint256 h = uint256(), int i = 0) : status(s), block_height(b), hashBlock(h), nIndex(i) {}
};

class COutput
{
private:
    /** When the transaction containing this output is unconfirmed, whether it is in the mempool */
    bool m_in_mempool{false};

public:
    CTxOut txout;
    COutPoint outpoint;

    /** Pre-computed estimated size of this output as a fully-signed input in a transaction. Can be -1 if it could not be calculated */
    int nInputBytes{-1};

    /** Whether we have the private keys to spend this output. Only used for output to user */
    bool fSpendable{true};

    /** Whether we know how to spend this output, ignoring the lack of keys. Only used for output to user */
    bool fSolvable{true};

    /** Whether this output is in a transaction we created */
    bool m_from_me;

    /** The transaction time */
    int64_t m_time;

    /** Confirmation status about this output */
    Confirmation m_confirm;

    /** The transaction contianing this output has an unconfirmed conflict */
    bool m_has_unconfirmed_conflict;

    COutput(const CTxOut& txout, const COutPoint& outpoint, bool from_me, int64_t time, Confirmation confirm, bool in_mempool) :
        m_in_mempool(in_mempool),
        txout(txout),
        outpoint(outpoint),
        m_from_me(from_me),
        m_time(time),
        m_confirm(confirm),
    {}

    std::string ToString() const;

    CAmount GetValue() const;
    int64_t GetTxTime() const;
    const CScript& GetScriptPubKey() const;
    const uint256& GetTxHash() const;
    uint32_t GetVoutIndex() const;
    const CTxOut& GetTxOut() const;
    int GetDepth(int tip_height) const;
    bool IsSafe() const;
    bool IsImmatureCoinbase(int tip_height) const;
};

#endif // BITCOIN_WALLET_TX_H
