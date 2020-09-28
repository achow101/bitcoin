// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <tinyformat.h>
#include <util/moneystr.h>
#include <wallet/tx.h>

std::string COutput::ToString() const
{
    return strprintf("COutput(%s, %d, %d) [%s]", GetTxHash().ToString(), GetVoutIndex(), nDepth, FormatMoney(GetValue()));
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

