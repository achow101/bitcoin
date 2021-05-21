// Copyright (c) 2012-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

 <bench/bench.h>
 <interfaces/chain.h>
 <node/context.h>
 <wallet/coinselection.h>
 <wallet/wallet.h>

 <set>

 addCoin( CAmount& nValue, const CWallet& wallet, std::vector<std::unique_ptr<CWalletTx>>& wtxs)
{
    nextLockTime = 0;
    CMutableTransaction tx;
    tx.nLockTime = nextLockTime++; // so all transactions get different hashes
    tx.vout.resize(1);
    tx.vout[0].nValue = nValue;
    wtxs.push_back(std::make_unique<CWalletTx>(&wallet, MakeTransactionRef(std::move(tx))));
}

// Simple benchmark for wallet coin selection. Note that it maybe be necessary
// to build up more complicated scenarios in order to get meaningful
// measurements of performance. From laanwj, "Wallet coin selection is probably
// the hardest, as you need a wider selection of scenarios, just testing the
// same one over and over isn't too useful. Generating random isn't useful
// either for measurements."
// (https://github.com/bitcoin/bitcoin/issues/7883#issuecomment-224807484)
CoinSelection(benchmark::Bench& bench)
{
    NodeContext node;
    chain = interfaces::MakeChain(node);
    CWallet wallet(chain.get(), "", CreateDummyWalletDatabase());
    wallet.SetupLegacyScriptPubKeyMan();
    std::vector<std::unique_ptr<CWalletTx>> wtxs;
    LOCK(wallet.cs_wallet);

    // Add coins.
     ( i = 0; i < 1000; ++i) {
        addCoin(1000 * COIN, wallet, wtxs);
    }
    addCoin(3 * COIN, wallet, wtxs);

    // Create coins
    std::vector<COutput> coins;
    (& wtx : wtxs) {
        coins.emplace_back(wtx.get(), 0 /* iIn */, 6 * 24 /* nDepthIn */, true /* spendable */, true /* solvable */, true /* safe */);
    }

    CoinEligibilityFilter filter_standard(1, 6, 0);
    CoinSelectionParams coin_selection_params(/* change_output_size= */ 34,
                                                    /* change_spend_size= */ 148, /* effective_feerate= */ CFeeRate(0),
                                                    /* long_term_feerate= */ CFeeRate(0), /* discard_feerate= */ CFeeRate(0),
                                                    /* tx_no_inputs_size= */ 0, /* avoid_partial= */ false);
    bench.run([&] {
        std::set<CInputCoin> setCoinsRet;
        CAmount nValueRet;
        success = wallet.AttemptSelection(1003 * COIN, filter_standard, coins, setCoinsRet, nValueRet, coin_selection_params);
        assert(success);
        assert(nValueRet == 1003 * COIN);
        assert(setCoinsRet.size() == 2);
    });
}

std::set<CInputCoin> CoinSet;
NodeContext testNode;
testChain = interfaces::MakeChain(testNode);
CWallet testWallet(testChain.get(), "", CreateDummyWalletDatabase());
std::vector<std::unique_ptr<CWalletTx>> wtxn;

// Copied from src/wallet/test/coinselector_tests.cpp
add_coin(const CAmount& nValue, int nInput, std::vector<OutputGroup>& set)
{
    CMutableTransaction tx;
    tx.vout.resize(nInput + 1);
    tx.vout[nInput].nValue = nValue;
    std::unique_ptr<CWalletTx> wtx = std::make_unique<CWalletTx>(&testWallet, MakeTransactionRef(std::move(tx)));
    set.emplace_back();
    set.back().Insert(COutput(wtx.get(), nInput, 0, true, true, true).GetInputCoin(), 0, true, 0, 0, false);
    wtxn.emplace_back(std::move(wtx));
}
// Copied from src/wallet/test/coinselector_tests.cpp
CAmount make_hard_case(utxos, std::vector<OutputGroup>& utxo_pool)
{
    utxo_pool.clear();
    CAmount target = 0;
    ( i = 0; i < utxos; ++i) {
        target += (CAmount)1 << (utxos+i);
        add_coin((CAmount)1 << (utxos+i), 2*i, utxo_pool);
        add_coin(((CAmount)1 << (utxos+i)) + ((CAmount)1 << (utxos-1-i)), 2*i + 1, utxo_pool);
    }
    target;
}

BnBExhaustion(benchmark::Bench& bench)
{
    // Setup
    testWallet.SetupLegacyScriptPubKeyMan();
    std::vector<OutputGroup> utxo_pool;
    CoinSet selection;
    CAmount value_ret = 0;

    bench.run([&] {
        // Benchmark
        CAmount target = make_hard_case(17, utxo_pool);
        SelectCoinsBnB(utxo_pool, target, 0, selection, value_ret); // Should exhaust

        // Cleanup
        utxo_pool.clear();
        selection.clear();
    });
}

BENCHMARK(CoinSelection);
BENCHMARK(BnBExhaustion);
