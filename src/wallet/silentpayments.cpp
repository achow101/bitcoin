#include <wallet/silentpayments.h>
#include <addresstype.h>
#include <arith_uint256.h>
#include <coins.h>
#include <crypto/common.h>
#include <crypto/hmac_sha512.h>
#include <key_io.h>
#include <undo.h>
#include <logging.h>
#include <pubkey.h>
#include <policy/policy.h>
#include <script/solver.h>
#include <util/check.h>
#include <wallet/wallet.h>

namespace wallet {

CPubKey ComputeECDHSharedSecret(const CKey& scan_key, const CPubKey& sender_public_key, const uint256& outpoints_hash)
{
    auto tweaked_scan_seckey{scan_key};
    tweaked_scan_seckey.TweakMultiply(outpoints_hash.begin());
    CPubKey result = tweaked_scan_seckey.UnhashedECDH(sender_public_key);
    assert(result.IsValid());
    return result;
}

uint256 ComputeTweak(const CPubKey& ecdh_pubkey, const uint32_t output_index)
{
    HashWriter h;
    h.write(Span{ecdh_pubkey});
    unsigned char num[4];
    WriteBE32(num, output_index);
    h << num;
    return h.GetSHA256();
}

std::vector<uint256> GetTxOutputTweaks(const CPubKey& spend_pubkey, const CPubKey& ecdh_pubkey, std::vector<XOnlyPubKey> output_pub_keys)
{
    // Because a sender can create multiple outputs for us, we first check the outputs vector for an output with
    // output index 0. If we find it, we remove it from the vector and then iterate over the vector again looking for
    // an output with index 1, and so on until one of the following happens:
    //
    //     1. We have determined all outputs belong to us (the vector is empty)
    //     2. We have passed over the vector and found no outputs belonging to us
    //

    bool removed;
    uint32_t output_index{0};
    std::vector<uint256> tweaks;
    do {
        // We haven't removed anything yet on this pass and if we don't remove anything, we didn't find
        // any silent payment outputs and should stop checking
        removed = false;
        uint256 tweak = ComputeTweak(ecdh_pubkey, output_index);
        CPubKey computed_sp_pubkey = spend_pubkey.TweakAdd(tweak.data());
        const XOnlyPubKey& sp_pubkey = XOnlyPubKey{computed_sp_pubkey};
        //const CKey& silent_payment_priv_key = tweakResult.first;
        output_pub_keys.erase(std::remove_if(output_pub_keys.begin(), output_pub_keys.end(), [&](auto output_pubkey) {
            if (sp_pubkey == output_pubkey) {
                // Since we found an output, we need to increment the output index and check the vector again
                tweaks.emplace_back(tweak);
                removed = true;
                output_index++;
                // Return true so that this output pubkey is removed the from vector and not checked again
                return true;
            }
            return false;
        }), output_pub_keys.end());
    } while (!output_pub_keys.empty() && removed);
    return tweaks;
}

std::optional<std::pair<uint256, CPubKey>> GetSilentPaymentsTweakDataFromTxInputs(const std::vector<CTxIn>& vin, const std::map<COutPoint, Coin>& coins)
{

    // Extract the keys from the inputs
    // or skip if no valid inputs
    std::vector<CPubKey> input_pubkeys;
    std::vector<COutPoint> input_outpoints;
    for (const CTxIn& txin : vin) {
        const Coin& coin = coins.at(txin.prevout);
        Assert(!coin.IsSpent());
        input_outpoints.emplace_back(txin.prevout);

        std::vector<std::vector<unsigned char>> solutions;
        TxoutType type = Solver(coin.out.scriptPubKey, solutions);
        if (type == TxoutType::WITNESS_V1_TAPROOT) {
            // Check for H point in script path spend
            if (txin.scriptWitness.stack.size() > 1) {
                // Check for annex
                bool has_annex = txin.scriptWitness.stack.back()[0] == ANNEX_TAG;
                size_t post_annex_size = txin.scriptWitness.stack.size() - (has_annex ? 1 : 0);
                if (post_annex_size > 1) {
                    // Actually a script path spend
                    const std::vector<unsigned char>& control = txin.scriptWitness.stack.back();
                    Assert(control.size() >= 33);
                    if (std::equal(NUMS_H.begin(), NUMS_H.end(), control.begin() + 1)) {
                        // Skip script path with H internal key
                        continue;
                    }
                }
            }

            std::vector<unsigned char> pubkey;
            pubkey.resize(33);
            pubkey[0] = 0x02;
            std::copy(solutions[0].begin(), solutions[0].end(), pubkey.begin() + 1);
            input_pubkeys.emplace_back(pubkey);
        } else if (type == TxoutType::WITNESS_V0_KEYHASH) {
            input_pubkeys.emplace_back(txin.scriptWitness.stack.back());
        } else if (type == TxoutType::PUBKEYHASH || type == TxoutType::SCRIPTHASH) {
            // Use the script interpreter to get the stack after executing the scriptSig
            std::vector<std::vector<unsigned char>> stack;
            ScriptError serror;
            Assert(EvalScript(stack, txin.scriptSig, MANDATORY_SCRIPT_VERIFY_FLAGS, DUMMY_CHECKER, SigVersion::BASE, &serror));
            if (type == TxoutType::PUBKEYHASH) {
                input_pubkeys.emplace_back(stack.back());
            } else if (type == TxoutType::SCRIPTHASH) {
                // Check if the redeemScript is P2WPKH
                CScript redeem_script{stack.back().begin(), stack.back().end()};
                TxoutType rs_type = Solver(redeem_script, solutions);
                if (rs_type == TxoutType::WITNESS_V0_KEYHASH) {
                    input_pubkeys.emplace_back(txin.scriptWitness.stack.back());
                }
            }
        } else if (type == TxoutType::PUBKEY) {
            input_pubkeys.emplace_back(solutions[0]);
        }
    }
    if (input_pubkeys.size() == 0) return std::nullopt;
    const uint256& outpoints_hash = HashOutpoints(input_outpoints);
    CPubKey input_pubkeys_sum = CPubKey::Combine(input_pubkeys);
    return std::make_pair(outpoints_hash, input_pubkeys_sum);
}

CPubKey CreateOutput(const CKey& ecdh_scalar, const CPubKey& scan_pubkey, const CPubKey& spend_pubkey, const uint32_t output_index)
{
    CPubKey ecdh_pubkey = ecdh_scalar.UnhashedECDH(scan_pubkey);
    HashWriter h;
    h.write(Span{ecdh_pubkey});
    unsigned char num[4];
    WriteBE32(num, output_index);
    h << num;
    uint256 shared_secret = h.GetSHA256();
    return spend_pubkey.TweakAdd(shared_secret.begin());
}

CKey SumInputPrivKeys(const std::vector<std::pair<CKey, bool>>& sender_secret_keys)
{
    // Grab the first key, copy it to the accumulator, and negate if necessary
    const auto& [seckey, is_taproot] = sender_secret_keys.at(0);
    CKey sum_seckey{seckey};
    if (is_taproot && sum_seckey.GetPubKey()[0] == 3) sum_seckey.Negate();
    if (sender_secret_keys.size() == 1) return sum_seckey;

    // If there are more keys, check if the key needs to be negated and add it to the accumulator
    for (size_t i = 1; i < sender_secret_keys.size(); i++) {
        const auto& [sender_seckey, sender_is_taproot] = sender_secret_keys.at(i);
        auto temp_key{sender_seckey};
        if (sender_is_taproot && sender_seckey.GetPubKey()[0] == 3) {
            temp_key.Negate();
        }
        sum_seckey.TweakAdd(temp_key.begin());
    }
    return sum_seckey;
}

CKey PrepareScalarECDHInput(const std::vector<std::pair<CKey, bool>>& sender_secret_keys, const std::vector<COutPoint>& tx_outpoints)
{
    CKey sum_input_secret_keys = SumInputPrivKeys(sender_secret_keys);
    uint256 outpoints_hash = HashOutpoints(tx_outpoints);
    sum_input_secret_keys.TweakMultiply(outpoints_hash.begin());
    return sum_input_secret_keys;
}

std::map<size_t, WitnessV1Taproot> GenerateSilentPaymentTaprootDestinations(const CKey& ecdh_scalar, const std::map<size_t, V0SilentPaymentDestination>& sp_dests)
{
    std::map<CPubKey, std::vector<std::pair<CPubKey, size_t>>> sp_groups;
    std::map<size_t, WitnessV1Taproot> tr_dests;

    for (const auto& [out_idx, sp_dest] : sp_dests) {
        sp_groups[sp_dest.m_scan_pubkey].emplace_back(sp_dest.m_spend_pubkey, out_idx);
    }

    for (const auto& [scan_pubkey, spend_pubkeys] : sp_groups) {
        for (size_t i = 0; i < spend_pubkeys.size(); ++i) {
            const auto& [spend_pubkey, out_idx] = spend_pubkeys.at(i);
            tr_dests.emplace(out_idx, XOnlyPubKey{CreateOutput(ecdh_scalar, scan_pubkey, spend_pubkey, i)});
        }
    }
    return tr_dests;
}

uint256 HashOutpoints(const std::vector<COutPoint>& tx_outpoints)
{

    // Make a local copy of the outpoints so we can sort them before hashing.
    // This is to ensure the sender and receiver deterministically arrive at the same outpoint hash,
    // regardless of how the outpoints are ordered in the transaction.

    std::vector<COutPoint> outpoints{tx_outpoints};
    std::sort(outpoints.begin(), outpoints.end());

    HashWriter h;
    for (const auto& outpoint: outpoints) {
        h << outpoint;
    }
    return h.GetSHA256();
}
}
