#include <wallet/silentpayments.h>
#include <test/data/bip352_send_and_receive_vectors.json.h>

#include <test/util/setup_common.h>
#include <hash.h>

#include <boost/test/unit_test.hpp>
#include <test/util/json.h>
#include <vector>
#include <util/bip32.h>
#include <wallet/wallet.h>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(silentpayment_tests, BasicTestingSetup)

CKey ParseHexToCKey(std::string hex) {
    CKey output;
    auto hex_data = ParseHex(hex);
    output.Set(hex_data.begin(), hex_data.end(), true);
    return output;
};

CKey GetKeyFromBIP32Path(std::vector<std::byte> seed, std::vector<uint32_t> path)
{
    CExtKey key_parent, key_child;
    key_parent.SetSeed(seed);
    for (auto index : path) {
        BOOST_CHECK(key_parent.Derive(key_child, index));
        std::swap(key_parent, key_child);
    }
    return key_parent.key;
}

BOOST_AUTO_TEST_CASE(bip352_send_and_receive_test_vectors)
{
    UniValue tests;
    tests.read(json_tests::bip352_send_and_receive_vectors);

    for (const auto& vec : tests.getValues()) {
        // run sending tests
        BOOST_TEST_MESSAGE(vec["comment"].get_str());
        for (const auto& sender : vec["sending"].getValues()) {
            const auto& given = sender["given"];
            const auto& expected = sender["expected"];

            std::vector<COutPoint> outpoints;
            for (const auto& outpoint : sender["given"]["outpoints"].getValues()) {
                outpoints.emplace_back(uint256S(outpoint[0].get_str()), outpoint[1].getInt<uint32_t>());
            }

            std::vector<std::pair<CKey, bool>> sender_secret_keys;
            for (const auto& key : given["input_priv_keys"].getValues()) {
                sender_secret_keys.emplace_back(ParseHexToCKey(key[0].get_str()), key[1].get_bool());
            }
            std::vector<CRecipient> silent_payment_addresses;
            for (const auto& recipient : given["recipients"].getValues()) {
                std::string silent_payment_address = recipient[0].get_str();
                CAmount amount = recipient[1].get_real() * COIN;
                const auto& sp = DecodeDestination(silent_payment_address);
                silent_payment_addresses.push_back(CRecipient{sp, amount, false});
            }

            // silent payments logic
            CKey scalar_ecdh_input = PrepareScalarECDHInput(sender_secret_keys, outpoints);

            std::map<size_t, V0SilentPaymentDestination> sp_dests;
            for (size_t i = 0; i < silent_payment_addresses.size(); ++i) {
                if (const auto* sp = std::get_if<V0SilentPaymentDestination>(&silent_payment_addresses.at(i).dest)) {
                    sp_dests[i] = *sp;
                }
            }
            std::map<size_t, WitnessV1Taproot> sp_tr_dests = GenerateSilentPaymentTaprootDestinations(scalar_ecdh_input, sp_dests);

            for (const auto& [out_idx, tr_dest] : sp_tr_dests) {
                assert(out_idx < silent_payment_addresses.size());
                silent_payment_addresses[out_idx].dest = tr_dest;
            }

            std::vector<CRecipient> expected_spks;
            for (const auto& recipient : expected["outputs"].getValues()) {
                std::string pubkey_hex = recipient[0].get_str();
                CAmount amount = recipient[1].get_real() * COIN;
                auto tap = WitnessV1Taproot(XOnlyPubKey(ParseHex(pubkey_hex)));
                expected_spks.push_back(CRecipient{tap, amount, false});
            }

            BOOST_CHECK(silent_payment_addresses.size() == expected_spks.size());
            for (const auto& spk : silent_payment_addresses) {
                BOOST_CHECK(std::find(expected_spks.begin(), expected_spks.end(), spk) != expected_spks.end());
            }
        }

        // Test receiving
        for (const auto& recipient : vec["receiving"].getValues()) {
            // TODO: implement labels for Bitcoin Core, until then skip the receiving with labels tests
            if (recipient["supports_labels"].get_bool()) {
                BOOST_TEST_MESSAGE("Labels not implemented; skipping..");
                continue;
            }

            const auto& given = recipient["given"];
            const auto& expected = recipient["expected"];

            std::vector<COutPoint> outpoints;
            for (const auto& outpoint : recipient["given"]["outpoints"].getValues()) {
                outpoints.emplace_back(uint256S(outpoint[0].get_str()), outpoint[1].getInt<uint32_t>());
            }

            std::vector<CPubKey> input_pub_keys;
            for (const auto& pubkey : given["input_pub_keys"].getValues()) {
                // All pubkeys must be in compressed format
                auto pubkey_bytes = ParseHex(pubkey.get_str());
                if (pubkey_bytes.size() == 32) {
                    // XOnlyPubKeys are always even
                    pubkey_bytes.insert(pubkey_bytes.begin(), 2);
                }
                input_pub_keys.emplace_back(pubkey_bytes);
            }
            std::vector<XOnlyPubKey> output_pub_keys;
            for (const auto& pubkey : given["outputs"].getValues()) {
                output_pub_keys.emplace_back(ParseHex(pubkey.get_str()));
            }

            std::string hex_str = given["bip32_seed"].get_str();
            std::vector<std::byte> seed{ParseHex<std::byte>(hex_str)};
            std::vector<uint32_t> scan_keypath;
            BOOST_CHECK(ParseHDKeypath("m/352'/0'/0'/1'/0", scan_keypath));
            std::vector<uint32_t> spend_keypath;
            BOOST_CHECK(ParseHDKeypath("m/352'/0'/0'/0'/0", spend_keypath));
            CKey scan_priv_key = GetKeyFromBIP32Path(seed, scan_keypath);
            CKey spend_priv_key = GetKeyFromBIP32Path(seed, spend_keypath);
            CPubKey spend_pubkey = spend_priv_key.GetPubKey();

            // Scanning
            CPubKey sum_input_pub_keys = CPubKey::Combine(input_pub_keys);

            const auto expected_addresses = expected["addresses"].getValues();
            // We know there is only one address, but if we support labels, this could be multiple addresses
            CPubKey ecdh_pubkey = ComputeECDHSharedSecret(scan_priv_key, sum_input_pub_keys, HashOutpoints(outpoints));
            std::vector<uint256> found_tweaks = GetTxOutputTweaks(spend_priv_key.GetPubKey(), ecdh_pubkey, output_pub_keys);

            std::vector<XOnlyPubKey> expected_outputs;
            for (const auto& output : expected["outputs"].getValues()) {
                std::string pubkey_hex = output["pub_key"].get_str();
                const auto pubkey = XOnlyPubKey(ParseHex(pubkey_hex));
                expected_outputs.push_back(pubkey);
            }
            std::vector<XOnlyPubKey> outputs;
            for (const uint256& tweak : found_tweaks) {
                CPubKey pubkey = spend_pubkey.TweakAdd(tweak.data());
                CKey privkey{spend_priv_key};
                privkey.TweakAdd(tweak.data());
                BOOST_CHECK(privkey.VerifyPubKey(pubkey));
                outputs.push_back(XOnlyPubKey{pubkey});
            }
            BOOST_CHECK(outputs == expected_outputs);
        }
    }
}
BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
