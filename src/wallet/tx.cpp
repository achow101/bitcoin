// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/consensus.h>
#include <tinyformat.h>
#include <util/moneystr.h>
#include <wallet/tx.h>

std::string COutput::ToString() const
{
    return strprintf("COutput(%s, %d, %d) [%s]", GetTxHash().ToString(), GetVoutIndex(), m_confirm.block_height, FormatMoney(GetValue()));
}

CAmount COutput::GetValue() const
{
    return txout.nValue;
}

int64_t COutput::GetTxTime() const
{
    return m_time;
}

const CScript& COutput::GetScriptPubKey() const
{
    return txout.scriptPubKey;
}

const uint256& COutput::GetTxHash() const
{
    return outpoint.hash;
}

uint32_t COutput::GetVoutIndex() const
{
    return outpoint.n;
}

const CTxOut& COutput::GetTxOut() const
{
    return txout;
}

int COutput::GetDepth(int tip_height) const
{
    if (m_confirm.status == Confirmation::Status::UNCONFIRMED || m_confirm.status == Confirmation::Status::ABANDONED) {
        return 0;
    }
    return (tip_height - m_confirm.block_height + 1) * (m_confirm.status == Confirmation::Status::CONFLICTED ? -1 : 1);
}

bool COutput::IsSafe() const
{
    if (m_confirm.status == Confirmation::Status::CONFIRMED) return true;

    // We should not consider coins which aren't at least in our mempool
    // It's possible for these to be conflicted via ancestors which we may never be able to detect
    if (!m_in_mempool || m_confirm.status == Confirmation::Status::CONFLICTED) return false;
    // We should not consider coins from transactions that are replacing
    // other transactions.
    //
    // Example: There is a transaction A which is replaced by bumpfee
    // transaction B. In this case, we want to prevent creation of
    // a transaction B' which spends an output of B.
    //
    // Reason: If transaction A were initially confirmed, transactions B
    // and B' would no longer be valid, so the user would have to create
    // a new transaction C to replace B'. However, in the case of a
    // one-block reorg, transactions B' and C might BOTH be accepted,
    // when the user only wanted one of them. Specifically, there could
    // be a 1-block reorg away from the chain where transactions A and C
    // were accepted to another chain where B, B', and C were all
    // accepted.
    //
    // Similarly, we should not consider coins from transactions that
    // have been replaced. In the example above, we would want to prevent
    // creation of a transaction A' spending an output of A, because if
    // transaction B were initially confirmed, conflicting with A and
    // A', we wouldn't want to the user to create a transaction D
    // intending to replace A', but potentially resulting in a scenario
    // where A, A', and D could all be accepted (instead of just B and
    // D, or just A and A' like the user would want).
    if (m_has_unconfirmed_conflict) return false;
    return m_from_me;
}

bool COutput::IsImmatureCoinbase(int tip_height) const
{
    if (m_confirm.status != Confirmation::Status::CONFIRMED) return false;
    if (!m_is_coinbase) return false;
    int depth = GetDepth(tip_height);
    return (COINBASE_MATURITY + 1) - depth > 0;
}
