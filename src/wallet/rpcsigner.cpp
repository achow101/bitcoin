// Copyright (c) 2018-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>
#include <core_io.h>
#include <key_io.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <validation.h>
#include <wallet/rpcdump.h>
#include <wallet/rpcwallet.h>

#include <univalue.h>

static UniValue enumeratesigners(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "enumeratesigners\n"
            "Returns a list of external signers from -signer and associates them\n"
            "with the wallet until you stop bitcoind.\n"
            "{\n"
            "  \"signers\" : [                                (json array of objects)\n"
            "    {\n"
            "      \"masterkeyfingerprint\" : \"fingerprint\" (string) Master key fingerprint\n"
            "    }\n"
            "    ,...\n"
            "  ]\n"
            "}\n"
        );
    }

    const std::string command = gArgs.GetArg("-signer", DEFAULT_EXTERNAL_SIGNER);
    if (command == "") throw JSONRPCError(RPC_WALLET_ERROR, "Error: restart bitcoind with -signer=<cmd>");
    std::string chain = gArgs.GetChainName();
    const bool mainnet = chain == CBaseChainParams::MAIN;
    UniValue signers;
    try {
        signers = ExternalSigner::Enumerate(command, pwallet->m_external_signers, mainnet);
    } catch (const ExternalSignerException& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }
    UniValue result(UniValue::VOBJ);
    result.pushKV("signers", signers);
    return result;
}

ExternalSigner *GetSignerForJSONRPCRequest(const JSONRPCRequest& request, int index, CWallet* pwallet) {
    if (pwallet->m_external_signers.empty()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "First call enumeratesigners");
    }

    // If no fingerprint is specified, return the only available signer
    if (request.params.size() < size_t(index + 1) || request.params[index].isNull()) {
        if (pwallet->m_external_signers.size() > 1) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Multiple signers found, please specify which to use");
        }
        return &pwallet->m_external_signers.front();
    }

    const std::string fingerprint = request.params[index].get_str();
    for (ExternalSigner &candidate : pwallet->m_external_signers) {
        if (candidate.m_fingerprint == fingerprint) return &candidate;
    }
    throw JSONRPCError(RPC_WALLET_ERROR, "Signer fingerprint not found");
}

UniValue signerdissociate(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            "signerdissociate ( fingerprint )\n"
            "Disossociates external signer from the wallet.\n"
            "\nArguments:\n"
            "1. \"fingerprint\"   (string, optional) Master key fingerprint of signer\n"
        );
    }

    ExternalSigner *signer = GetSignerForJSONRPCRequest(request, 0, pwallet);

    assert(signer != nullptr);
    std::vector<ExternalSigner>::iterator position = std::find(pwallet->m_external_signers.begin(), pwallet->m_external_signers.end(), *signer);
    if (position != pwallet->m_external_signers.end()) pwallet->m_external_signers.erase(position);

    return NullUniValue;
}

static UniValue signerdisplayaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.empty() || request.params.size() > 2) {
        throw std::runtime_error(
            "signerdisplayaddress\n"
            "Display address on an external signer for verification.\n"
            "\nArguments:\n"
            "1. \"address\"       (string, required) The bitcoin address to display.\n"
            "2. \"fingerprint\"   (string, optional) Master key fingerprint of signer\n"
        );
    }

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ExternalSigner *signer = GetSignerForJSONRPCRequest(request, 1, pwallet);

    LOCK(pwallet->cs_wallet);

    CTxDestination dest = DecodeDestination(request.params[0].get_str());

    // Make sure the destination is valid
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    const CKeyMetadata* meta = nullptr;
    CKeyID key_id = GetKeyForDestination(*pwallet, dest);
    if (!key_id.IsNull()) {
        auto it = pwallet->mapKeyMetadata.find(key_id);
        if (it != pwallet->mapKeyMetadata.end()) {
            meta = &it->second;
        }
    }
    // TODO: use inferred descriptor (preferably with xpub at the account level)
    CScript scriptPubKey = GetScriptForDestination(dest);
    if (!meta) {
        auto it = pwallet->m_script_metadata.find(CScriptID(scriptPubKey));
        if (it != pwallet->m_script_metadata.end()) {
            meta = &it->second;
        }
    }
    if (!meta || meta->key_origin.IsNull()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Missing BIP32 derivation data");
    }

    std::string path = meta->hdKeypath;
    path.erase(0,2); // Unsafe, but to be replaced with inferred descriptor

    KeyOriginInfo info;
    if (!pwallet->GetKeyOrigin(key_id, info)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Internal keypath is broken");
    }

    bool solvable = IsSolvable(*pwallet, scriptPubKey);
    if (!solvable) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Address is not solvable");
    }

    std::string inferredDescriptor = InferDescriptor(scriptPubKey, *pwallet)->ToString();

    // TODO: Use the inferred descriptor directly. Unfortunately it's currently
    //       not useful (or is it??).

    std::string prefix = "";
    std::string postfix = "";

    if (inferredDescriptor.find("wpkh") == 0) {
        prefix = "wpkh(";
        postfix = ")";
    } else if (inferredDescriptor.find("sh(wpkh") == 0) {
        prefix = "sh(wpkh(";
        postfix = "))";
    } else if (inferredDescriptor.find("pkh") == 0) {
        prefix = "pkh(";
        postfix = ")";
    } else {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to produce descriptor");
    }
    std::string descriptor = prefix + strprintf("%08x/", ReadBE32(info.fingerprint)) + WriteHDKeypath(info.path).erase(0,2) + postfix;
    signer->displayAddress(descriptor);

    return UniValue(UniValue::VNULL);
}

UniValue signerfetchkeys(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1) {
        throw std::runtime_error(
            "signerfetchkeys ( fingerprint )\n"
            "Obtains keys from external signer and imports them into the wallet.\n"
            "Call enumeratesigners before using this.\n"
            "\nArguments:\n"
            "1. \"fingerprint\"   (string, optional) Master key fingerprint of signer\n"
            "\nResult (same as for importmulti):\n"
            "[{ \"success\": true }"
        );
    }

    ExternalSigner *signer = GetSignerForJSONRPCRequest(request, 0, pwallet);

    UniValue descriptors = UniValue(UniValue::VARR);
    std::string desc_prefix = "";
    std::string desc_suffix = "";
    std::string purpose = "";
    switch(pwallet->m_default_address_type) {
        case OutputType::LEGACY: {
            desc_prefix = "pkh(";
            desc_suffix = ")";
            purpose = "44h";
            break;
        }
        case OutputType::P2SH_SEGWIT: {
            desc_prefix = "sh(wpkh(";
            desc_suffix = "))";
            purpose = "49h";
            break;
        }
        case OutputType::BECH32: {
            desc_prefix = "wpkh(";
            desc_suffix = ")";
            purpose = "84h";
            break;
        }
        case OutputType::CHANGE_AUTO: {
            assert(false);
        }
    }

    const std::string receive_desc = desc_prefix + signer->m_fingerprint + "/" + purpose + "/" + (signer->m_mainnet ? "0h" : "1h") + "/0h/0/*" + desc_suffix;
    UniValue receive_descriptors = signer->getKeys(receive_desc);
    if (!receive_descriptors.isArray()) JSONRPCError(RPC_WALLET_ERROR, "Expected an array of receive descriptors");
    for (const UniValue& descriptor : receive_descriptors.getValues()) {
        descriptors.push_back(descriptor);
    }


    switch(pwallet->m_default_change_type) {
        case OutputType::LEGACY: {
            desc_prefix = "pkh(";
            desc_suffix = ")";
            purpose = "44h";
            break;
        }
        case OutputType::P2SH_SEGWIT: {
            desc_prefix = "sh(wpkh(";
            desc_suffix = "))";
            purpose = "49h";
            break;
        }
        case OutputType::BECH32: {
            desc_prefix = "wpkh(";
            desc_suffix = ")";
            purpose = "84h";
            break;
        }
        case OutputType::CHANGE_AUTO: {
            // Use same values as for receive descriptor
            break;
        }
    }

    const std::string change_desc = desc_prefix + signer->m_fingerprint + "/" + purpose + "/" + (signer->m_mainnet ? "0h" : "1h") + "/0h/1/*" + desc_suffix;
    UniValue change_descriptors = signer->getKeys(change_desc);
    if (!change_descriptors.isArray()) JSONRPCError(RPC_WALLET_ERROR, "Expected an array of change descriptors");
    for (const UniValue& descriptor : change_descriptors.getValues()) {
        descriptors.push_back(descriptor);
    }

    if (receive_descriptors.size() != change_descriptors.size()) JSONRPCError(RPC_WALLET_ERROR, "Expected same number of receive and change descriptors");

    // Use importmulti to process the descriptors:
    UniValue importdata(UniValue::VARR);

    uint64_t keypool_target_size = 0;
    keypool_target_size = gArgs.GetArg("-keypool", DEFAULT_KEYPOOL_SIZE);

    if (keypool_target_size == 0) JSONRPCError(RPC_WALLET_ERROR, "-keypool must be > 0");

    for (unsigned int i = 0; i < descriptors.size(); ++i) {
        const UniValue& descriptor = descriptors.getValues()[i];
        // TODO: sanity check the descriptors:
        // * check if they're valid descriptors
        // * check that it's the fingerprint we asked for
        // * check it's the deriviation path we asked for
        UniValue key_data(UniValue::VOBJ);
        key_data.pushKV("desc", descriptor);
        if (receive_descriptors.size() == 1) {
            // TODO: check that the descriptor is ranged
            UniValue range(UniValue::VOBJ);
            // TODO: base range start and end on what's currently in the keypool
            range.pushKV("start", 0);
            range.pushKV("end", keypool_target_size - 1);
            key_data.pushKV("range", range);
        } else {
            // TODO: check that the descriptor is not ranged
        }
        if (i >= receive_descriptors.size()) {
            key_data.pushKV("internal", true);
        }
        key_data.pushKV("keypool", true);
        key_data.pushKV("watchonly", true);
        importdata.push_back(key_data);
    }

    UniValue result(UniValue::VARR);
    {
        auto locked_chain = pwallet->chain().lock();
        int64_t now = chainActive.Tip() ? chainActive.Tip()->GetMedianTimePast() : 0;
        LOCK(pwallet->cs_wallet);
        EnsureWalletIsUnlocked(pwallet);
        for (const UniValue& data : importdata.getValues()) {
            // TODO: prevent inserting the same key twice
            result.push_back(ProcessImport(pwallet, data, now));
        }
    }

    return result;
}

bool signer_process_psbt(ExternalSigner *signer, PartiallySignedTransaction &psbtx) {
    assert(signer != nullptr);

    // Check if signer fingerpint matches any input master key fingerprint
    bool match = false;
    for (unsigned int i = 0; i < psbtx.inputs.size(); ++i) {
        const PSBTInput& input = psbtx.inputs[i];
        for (auto entry : input.hd_keypaths) {
            if (signer->m_fingerprint == strprintf("%08x", ReadBE32(entry.second.fingerprint))) match = true;
        }
    }

    if (!match) JSONRPCError(RPC_WALLET_ERROR, "Signer fingerprint does not match any of the inputs");

    // Serialize the PSBT
    // TODO: ExternalSigner signTransaction should take PartiallySignedTransaction argument and serialize that
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << psbtx;

    const UniValue signer_result = signer->signTransaction(EncodeBase64(ssTx.str()));
    if (!find_value(signer_result, "psbt").isStr()) JSONRPCError(RPC_WALLET_ERROR, "Unexpected result from signer");

    // Process result from signer:
    std::string signer_psbt_error;
    PartiallySignedTransaction signer_psbtx;
    if (!DecodePSBT(signer_psbtx, find_value(signer_result, "psbt").get_str(), signer_psbt_error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", signer_psbt_error));
    }

    // TODO: deduplicate completeness check from finalizepsbt:
    // Finalize input signatures -- in case we have partial signatures that add up to a complete
    //   signature, but have not combined them yet (e.g. because the combiner that created this
    //   PartiallySignedTransaction did not understand them), this will combine them into a final
    //   script.
    bool complete = true;
    for (unsigned int i = 0; i < signer_psbtx.tx->vin.size(); ++i) {
        complete &= SignPSBTInput(DUMMY_SIGNING_PROVIDER, signer_psbtx, i, SIGHASH_ALL); // Or use SIGHASH type in the PSBT??
    }

    psbtx = signer_psbtx;

    return complete;
}

UniValue signerprocesspsbt(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            RPCHelpMan{"signerprocesspsbt",
                "\nSign PSBT inputs using external signer\n"
                "that we can sign for." +
                    HelpRequiringPassphrase(pwallet) + "\n",
                {
                    {"psbt", RPCArg::Type::STR, /* opt */ false, /* default_val */ "", "The transaction base64 string"},
                    {"fingerprint", RPCArg::Type::STR, /* opt */ true, /* default_val */ "", "master key fingerprint of signer"},
                }}
                .ToString() +
            "\nResult:\n"
            "{\n"
            "  \"psbt\" : \"value\",          (string) The base64-encoded partially signed transaction\n"
            "  \"complete\" : true|false,   (boolean) If the transaction has a complete set of signatures\n"
            "  ]\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("signerprocesspsbt", "\"psbt\"")
        );

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VSTR});

    // Unserialize the transaction
    PartiallySignedTransaction psbtx;
    std::string error;
    if (!DecodePSBT(psbtx, request.params[0].get_str(), error)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", error));
    }

    ExternalSigner *signer = GetSignerForJSONRPCRequest(request, 1, pwallet);

    bool complete = signer_process_psbt(signer, psbtx);

    UniValue result(UniValue::VOBJ);
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << psbtx;
    result.pushKV("psbt", EncodeBase64(ssTx.str()));
    result.pushKV("complete", complete);
    return result;
}

// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                                actor (function)                argNames
    //  --------------------- ------------------------          -----------------------         ----------
    { "signer",             "enumeratesigners",                 &enumeratesigners,              {} },
    { "signer",             "signerdissociate",                 &signerdissociate,              {"fingerprint"} },
    { "signer",             "signerdisplayaddress",             &signerdisplayaddress,          {"address", "fingerprint"} },
    { "signer",             "signerfetchkeys",                  &signerfetchkeys,               {"fingerprint"} },
    { "signer",             "signerprocesspsbt",                &signerprocesspsbt,             {"psbt", "fingerprint"} },
};
// clang-format on

void RegisterSignerRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
