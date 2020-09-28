// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_COINSELECTION_H
#define BITCOIN_WALLET_COINSELECTION_H

#include <amount.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <random.h>

class COutput;

//! target minimum change amount
static constexpr CAmount MIN_CHANGE{COIN / 100};
//! final minimum change amount after paying for fees
static const CAmount MIN_FINAL_CHANGE = MIN_CHANGE/2;

struct CoinEligibilityFilter
{
    const int conf_mine;
    const int conf_theirs;
    const uint64_t max_ancestors;
    const uint64_t max_descendants;

    CoinEligibilityFilter(int conf_mine, int conf_theirs, uint64_t max_ancestors) : conf_mine(conf_mine), conf_theirs(conf_theirs), max_ancestors(max_ancestors), max_descendants(max_ancestors) {}
    CoinEligibilityFilter(int conf_mine, int conf_theirs, uint64_t max_ancestors, uint64_t max_descendants) : conf_mine(conf_mine), conf_theirs(conf_theirs), max_ancestors(max_ancestors), max_descendants(max_descendants) {}
};

struct OutputGroup
{
    std::vector<COutPoint> m_outpoints;
    bool m_from_me{true};
    CAmount m_value{0};
    int m_depth{999};
    size_t m_ancestors{0};
    size_t m_descendants{0};
    CAmount effective_value{0};
    CAmount fee{0};
    CFeeRate m_effective_feerate{0};
    CAmount long_term_fee{0};
    CFeeRate m_long_term_feerate{0};
    int m_tip_height{0};

    OutputGroup() {}
    OutputGroup(const CFeeRate& effective_feerate, const CFeeRate& long_term_feerate, int tip_height) :
        m_effective_feerate(effective_feerate),
        m_long_term_feerate(long_term_feerate),
        m_tip_height(tip_height)
    {}

    void Insert(const COutput& output, size_t ancestors, size_t descendants, bool positive_only);
    // Insert just values, OutputGroups where items were inserted with this function should not be used in actual coin selection
    void Insert(CAmount effective_value, CAmount value, CAmount fee, const COutPoint& outpoint);
    bool EligibleForSpending(const CoinEligibilityFilter& eligibility_filter) const;
    std::set<COutPoint> GetOutpoints() const;

    bool operator==(const OutputGroup& rhs) const {
        return std::equal(m_outpoints.begin(), m_outpoints.end(), rhs.m_outpoints.begin());
    }
};

bool SelectCoinsBnB(std::vector<OutputGroup>& utxo_pool, const CAmount& target_value, const CAmount& cost_of_change, std::vector<OutputGroup>& out_set, CAmount& value_ret, CAmount not_input_fees);

// Original coin selection algorithm as a fallback
bool KnapsackSolver(const CAmount& nTargetValue, std::vector<OutputGroup>& groups, std::vector<OutputGroup>& setCoinsRet, CAmount& nValueRet);

#endif // BITCOIN_WALLET_COINSELECTION_H
