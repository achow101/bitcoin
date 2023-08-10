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

SilentPaymentsSPKM::SilentPaymentsSPKM(WalletStorage& storage, const uint256& id, const V0SilentPaymentDestination& address, const CKey& scan_key, const CKey& spend_key, const std::vector<unsigned char>& spend_ckey, const std::vector<uint256>& tweaks, int64_t labels_size, int64_t creation_time, int64_t labels_used)
    : ScriptPubKeyMan(storage),
    m_address(address),
    m_scan_key(scan_key),
    m_spend_key(spend_key),
    m_spend_crypted_key(spend_ckey),
    m_creation_time(creation_time),
    m_labels_used(labels_used),
    m_id(id)
{
    // Create the scriptPubKeys given the tweaks and store them in memory
    for (const uint256& tweak : tweaks) {
        XOnlyPubKey output_key{m_address.m_spend_pubkey.TweakAdd(tweak.data())};
        m_spk_tweaks.emplace(GetScriptForDestination(WitnessV1Taproot(output_key)), tweak);
    }

    // Setup labels and change
    SetupLabels(labels_size);
}

SilentPaymentsSPKM::SilentPaymentsSPKM(WalletStorage& storage, int64_t labels_size, const CExtKey& master_key)
    : ScriptPubKeyMan(storage),
    m_creation_time(GetTime()),
    m_labels_used(0)
{
    LOCK(cs_sp_man);
    if (m_storage.HasEncryptionKeys() && m_storage.IsLocked()) {
        throw std::runtime_error("Wallet locked; Unable to write spend key");
    }

    // Derive the spend key at m/352h/0h/0h/0h/0
    CExtKey derived = master_key;
    for (uint32_t i : std::vector<uint32_t>{352 | 0x80000000, (Params().IsTestChain() ? 1 : 0) | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0}) {
        if (!derived.Derive(derived, i)) {
            throw std::runtime_error("Unable to derive silent payments spend key");
        }
    }
    m_address.m_spend_pubkey = derived.key.GetPubKey();
    if (m_storage.HasEncryptionKeys()) {
        CKeyingMaterial secret(derived.key.begin(), derived.key.end());
        if (!EncryptSecret(m_storage.GetEncryptionKey(), secret, derived.key.GetPubKey().GetHash(), m_spend_crypted_key)) {
            throw std::runtime_error("Unable to encrypt silent payments spend key");
        }
    } else {
        m_spend_key = derived.key;
    }

    // Derive the scan key
    derived = master_key;
    for (uint32_t i : std::vector<uint32_t>{352 | 0x80000000, (Params().IsTestChain() ? 1 : 0) | 0x80000000, 0 | 0x80000000, 1 | 0x80000000, 0}) {
        if (!derived.Derive(derived, i)) {
            throw std::runtime_error("Unable to derive silent payments scan key");
        }
    }
    m_address.m_scan_pubkey = derived.key.GetPubKey();
    m_scan_key = derived.key;

    // Calculate the spkm id by hashing the pubkeys together
    // The method for calculating the id just needs to be mostly random, we do not rely on being able to calculate it again in the future
    // and instead just use the stored value
    HashWriter hasher;
    hasher.write(m_address.m_scan_pubkey);
    hasher.write(m_address.m_spend_pubkey);
    m_id = hasher.GetSHA256();

    // Store the spend key
    WalletBatch batch(m_storage.GetDatabase());
    if (m_storage.HasEncryptionKeys()) {
        if (m_storage.IsLocked()) {
            throw std::runtime_error("Wallet locked; Unable to write spend key");
        }
        if (!batch.WriteSilentPaymentsSpendCryptedKey(GetID(), m_spend_crypted_key, m_address.m_spend_pubkey)) {
            throw std::runtime_error("Unable to write spend key to database");
        }
    } else {
        if (!batch.WriteSilentPaymentsSpendKey(GetID(), m_spend_key.GetPrivKey(), m_address.m_spend_pubkey)) {
            throw std::runtime_error("Unable to write spend key to database");
        }
    }
    // Store the scan key
    // This key cannot be encrypted
    if (!batch.WriteSilentPaymentsScanKey(GetID(), m_scan_key.GetPrivKey(), m_address.m_scan_pubkey)) {
        throw std::runtime_error("Unable to write scan key to database");
    }

    // Store creation time and max label used
    batch.WriteSilentPaymentsMetadata(GetID(), m_creation_time, m_labels_used);

    // Setup labels and change
    SetupLabels(labels_size);
}

void SilentPaymentsSPKM::SetupLabels(int64_t labels_size)
{
    // Create the label curve points map
    for (arith_uint256 i = 1; i < labels_size; ++i) {
        uint256 label_data = ArithToUint256(i);
        CKey label;
        label.Set(label_data.begin(), label_data.end(), /*compressed=*/true);
        m_sp_labels.emplace(i.GetLow64(), label.GetPubKey());
    }

    // Derive the change label and set the change destination
    HashWriter hasher;
    hasher.write(m_scan_key);
    m_change_label.first = hasher.GetSHA256();
    CKey change_label;
    change_label.Set(m_change_label.first.begin(), m_change_label.first.end(), /*compressed=*/true);
    m_change_label.second = change_label.GetPubKey();
    m_change_address.m_scan_pubkey = m_address.m_scan_pubkey;
    m_change_address.m_spend_pubkey = m_address.m_spend_pubkey.TweakAdd(m_change_label.first.data());
}

util::Result<CTxDestination> SilentPaymentsSPKM::GetNewDestination(const OutputType type)
{
    LOCK(cs_sp_man);
    if (type != OutputType::SILENT_PAYMENT) {
        throw std::runtime_error(std::string(__func__) + ": Types are inconsistent. Stored type does not match type of newly generated address");
    }

    return CTxDestination{m_address};
}

isminetype SilentPaymentsSPKM::IsMine(const CScript& script) const
{
    return m_spk_tweaks.count(script) > 0 ? ISMINE_SPENDABLE : ISMINE_NO;
}

bool SilentPaymentsSPKM::CheckDecryptionKey(const CKeyingMaterial& master_key, bool accept_no_keys)
{
    LOCK(cs_sp_man);
    assert(!m_spend_key.IsValid());

    CKey key;
    if (!DecryptKey(master_key, m_spend_crypted_key, m_address.m_spend_pubkey, key)) {
        LogPrintf("The wallet is probably corrupted: Unable to decrypt silent payments spend key");
        throw std::runtime_error("Error unlocking wallet: unable to decrypt silent payments spend key. Your wallet file may be corrupt.");
    }
    return true;
}

bool SilentPaymentsSPKM::Encrypt(const CKeyingMaterial& master_key, WalletBatch* batch)
{
    LOCK(cs_sp_man);
    assert(m_spend_key.IsValid());
    assert(m_spend_crypted_key.empty());

    CPubKey pubkey = m_spend_key.GetPubKey();
    CKeyingMaterial secret(m_spend_key.begin(), m_spend_key.end());
    std::vector<unsigned char> crypted_secret;
    if (!EncryptSecret(master_key, secret, pubkey.GetHash(), crypted_secret)) {
        return false;
    }
    m_spend_crypted_key = crypted_secret;
    batch->WriteSilentPaymentsSpendCryptedKey(GetID(), crypted_secret, pubkey);
    m_spend_key.Invalidate();
    return true;
}

util::Result<CTxDestination> SilentPaymentsSPKM::GetReservedDestination(const OutputType type, bool internal, int64_t& index, CKeyPool& keypool)
{
    LOCK(cs_sp_man);
    if (type != OutputType::SILENT_PAYMENT) {
        throw std::runtime_error(std::string(__func__) + ": Types are inconsistent. Stored type does not match type of newly generated address");
    }

    // Set index to 0 so callers don't get confused
    index = 0;
    return CTxDestination{m_change_address};
}

bool SilentPaymentsSPKM::TopUp(unsigned int size)
{
    // Nothing to do here
    return true;
}

std::optional<int64_t> SilentPaymentsSPKM::GetOldestKeyPoolTime() const
{
    // This is only used for getwalletinfo output and isn't relevant to silent payments wallets.
    return std::nullopt;
}

unsigned int SilentPaymentsSPKM::GetKeyPoolSize() const
{
    // Keypool size doesn't make sense for silent payments, just return 0
    return 0;
}

int64_t SilentPaymentsSPKM::GetTimeFirstKey() const
{
    LOCK(cs_sp_man);
    return m_creation_time;
}

std::unique_ptr<CKeyMetadata> SilentPaymentsSPKM::GetMetadata(const CTxDestination& dest) const
{
    // The concept of metadata for individual silent payments addresses doesn't really work, so return nothing for now
    return nullptr;
}

std::unique_ptr<FlatSigningProvider> SilentPaymentsSPKM::GetSigningProvider(const CScript& script, bool include_private) const
{
    std::unique_ptr<FlatSigningProvider> out_keys = std::make_unique<FlatSigningProvider>();

    // We can only provide solving data for the scripts we have already discovered
    if (m_spk_tweaks.count(script) == 0) {
        return out_keys;
    }

    const uint256& tweak = m_spk_tweaks.at(script);
    CPubKey output_pubkey = m_address.m_spend_pubkey.TweakAdd(tweak.data());

    out_keys->pubkeys.emplace(output_pubkey.GetID(), output_pubkey);

    if (include_private) {
        CKey output_key;
        if (m_storage.HasEncryptionKeys()) {
            if (!m_storage.IsLocked()) {
                DecryptKey(m_storage.GetEncryptionKey(), m_spend_crypted_key, m_address.m_spend_pubkey, output_key);
                output_key.TweakAdd(tweak.data());
            }
        } else {
            output_key = m_spend_key;
            output_key.TweakAdd(tweak.data());
        }
        if (output_key.IsValid()) {
            assert(output_key.GetPubKey() == output_pubkey);
            out_keys->keys.emplace(output_key.GetPubKey().GetID(), output_key);
        }
    }

    return out_keys;
}

std::unique_ptr<SigningProvider> SilentPaymentsSPKM::GetSolvingProvider(const CScript& script) const
{
    return GetSigningProvider(script, false);
}

bool SilentPaymentsSPKM::CanProvide(const CScript& script, SignatureData& sigdata)
{
    return m_spk_tweaks.count(script) > 0;
}

bool SilentPaymentsSPKM::SignTransaction(CMutableTransaction& tx, const std::map<COutPoint, Coin>& coins, int sighash, std::map<int, bilingual_str>& input_errors) const
{
    std::unique_ptr<FlatSigningProvider> keys = std::make_unique<FlatSigningProvider>();
    for (const auto& coin_pair: coins) {
        std::unique_ptr<FlatSigningProvider> coin_keys = GetSigningProvider(coin_pair.second.out.scriptPubKey, /*include_private=*/true);
        if (!coin_keys) continue;
        keys->Merge(std::move(*coin_keys));
    }

    return ::SignTransaction(tx, keys.get(), coins, sighash, input_errors);
}

SigningResult SilentPaymentsSPKM::SignMessage(const std::string& message, const PKHash& pkhash, std::string& str_sig) const
{
    // Message signing is not available for taproot outputs, so doesn't apply here
    return SigningResult::SIGNING_FAILED;
}
TransactionError SilentPaymentsSPKM::FillPSBT(PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, int sighash_type, bool sign, bool bip32derivs, int* n_signed, bool finalize) const
{
    if (n_signed) {
        *n_signed = 0;
    }
    for (unsigned int i = 0; i < psbt.tx->vin.size(); ++i) {
        const CTxIn& txin = psbt.tx->vin[i];
        PSBTInput& input = psbt.inputs.at(i);

        if (PSBTInputSigned(input)) {
            continue;
        }

        // Get the Sighash type
        if (sign && input.sighash_type != std::nullopt && *input.sighash_type != sighash_type) {
            return TransactionError::SIGHASH_MISMATCH;
        }

        // Get the scriptPubKey to know which SigningProvider to use
        CScript script;
        if (!input.witness_utxo.IsNull()) {
            script = input.witness_utxo.scriptPubKey;
        } else if (input.non_witness_utxo) {
            if (txin.prevout.n >= input.non_witness_utxo->vout.size()) {
                return TransactionError::MISSING_INPUTS;
            }
            script = input.non_witness_utxo->vout[txin.prevout.n].scriptPubKey;
        } else {
            // There's no UTXO so we can just skip this now
            continue;
        }
        SignatureData sigdata;
        input.FillSignatureData(sigdata);

        std::unique_ptr<FlatSigningProvider> keys = GetSigningProvider(script, /*include_private=*/sign);
        SignPSBTInput(HidingSigningProvider(keys.get(), /*hide_secret=*/!sign, /*hide_origin=*/!bip32derivs), psbt, i, &txdata, sighash_type, nullptr, finalize);

        bool signed_one = PSBTInputSigned(input);
        if (n_signed && (signed_one || !sign)) {
            // If sign is false, we assume that we _could_ sign if we get here. This
            // will never have false negatives; it is hard to tell under what i
            // circumstances it could have false positives.
            (*n_signed)++;
        }
    }

    // No need to fill in output data since there is no bip32 derivation done or scripts.

    return TransactionError::OK;
}

uint256 SilentPaymentsSPKM::GetID() const
{
    return m_id;
}

std::unordered_set<CScript, SaltedSipHasher> SilentPaymentsSPKM::GetScriptPubKeys() const
{
    std::unordered_set<CScript, SaltedSipHasher> spks;
    std::transform(m_spk_tweaks.cbegin(), m_spk_tweaks.cend(), std::inserter(spks, spks.end()), [](const auto& pair) { return pair.first; });
    return spks;
}

isminetype SilentPaymentsSPKM::IsMineSilentPayments(const CTransaction& tx, const std::map<COutPoint, Coin>& coins)
{
    return ISMINE_NO;
}
}
