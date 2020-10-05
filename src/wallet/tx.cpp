// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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

    if (!m_in_mempool || m_confirm.status == Confirmation::Status::CONFLICTED) return false;
    // Either UNCONFIRMED or ABANDONED now
    if (m_has_unconfirmed_conflict) return false;
    return m_from_me;
}
