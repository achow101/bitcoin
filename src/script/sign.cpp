// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/sign.h>

#include <key.h>
#include <keystore.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <uint256.h>


typedef std::vector<unsigned char> valtype;

TransactionSignatureCreator::TransactionSignatureCreator(const CKeyStore* keystoreIn, const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, int nHashTypeIn) : BaseSignatureCreator(keystoreIn), txTo(txToIn), nIn(nInIn), nHashType(nHashTypeIn), amount(amountIn), checker(txTo, nIn, amountIn) {}

bool TransactionSignatureCreator::CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& address, const CScript& scriptCode, SigVersion sigversion) const
{
    CKey key;
    if (!keystore->GetKey(address, key))
        return false;

    // Signing with uncompressed keys is disabled in witness scripts
    if (sigversion == SIGVERSION_WITNESS_V0 && !key.IsCompressed())
        return false;

    uint256 hash = SignatureHash(scriptCode, *txTo, nIn, nHashType, amount, sigversion);
    if (!key.Sign(hash, vchSig))
        return false;
    vchSig.push_back((unsigned char)nHashType);
    return true;
}

static bool Sign1(const CKeyID& address, const BaseSignatureCreator& creator, const CScript& scriptCode, std::vector<valtype>& ret, SigVersion sigversion)
{
    std::vector<unsigned char> vchSig;
    if (!creator.CreateSig(vchSig, address, scriptCode, sigversion))
        return false;
    ret.push_back(vchSig);
    return true;
}

static bool SignN(const std::vector<valtype>& multisigdata, const BaseSignatureCreator& creator, const CScript& scriptCode, std::vector<valtype>& ret, SigVersion sigversion, std::vector<CPubKey>& key_ret)
{
    int nSigned = 0;
    int nRequired = multisigdata.front()[0];
    for (unsigned int i = 1; i < multisigdata.size()-1 && nSigned < nRequired; i++)
    {
        const valtype& pubkey = multisigdata[i];
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (Sign1(keyID, creator, scriptCode, ret, sigversion)) {
            key_ret.push_back(CPubKey(pubkey));
            ++nSigned;
        }
    }
    return nSigned==nRequired;
}

/**
 * Sign scriptPubKey using signature made with creator.
 * Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
 * unless whichTypeRet is TX_SCRIPTHASH, in which case scriptSigRet is the redemption script.
 * Returns false if scriptPubKey could not be completely satisfied.
 */
static bool SignStep(const BaseSignatureCreator& creator, const CScript& scriptPubKey,
                     std::vector<valtype>& ret, txnouttype& whichTypeRet, SigVersion sigversion)
{
    CScript scriptRet;
    uint160 h160;
    ret.clear();
    std::vector<CPubKey> key_ret;

    std::vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichTypeRet, vSolutions))
        return false;

    CKeyID keyID;
    switch (whichTypeRet)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
    case TX_WITNESS_UNKNOWN:
        return false;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        return Sign1(keyID, creator, scriptPubKey, ret, sigversion);
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (!Sign1(keyID, creator, scriptPubKey, ret, sigversion))
            return false;
        else
        {
            CPubKey vch;
            creator.KeyStore().GetPubKey(keyID, vch);
            ret.push_back(ToByteVector(vch));
        }
        return true;
    case TX_SCRIPTHASH:
        if (creator.KeyStore().GetCScript(uint160(vSolutions[0]), scriptRet)) {
            ret.push_back(std::vector<unsigned char>(scriptRet.begin(), scriptRet.end()));
            return true;
        }
        return false;

    case TX_MULTISIG:
        ret.push_back(valtype()); // workaround CHECKMULTISIG bug
        return (SignN(vSolutions, creator, scriptPubKey, ret, sigversion, key_ret));

    case TX_WITNESS_V0_KEYHASH:
        ret.push_back(vSolutions[0]);
        return true;

    case TX_WITNESS_V0_SCRIPTHASH:
        CRIPEMD160().Write(&vSolutions[0][0], vSolutions[0].size()).Finalize(h160.begin());
        if (creator.KeyStore().GetCScript(h160, scriptRet)) {
            ret.push_back(std::vector<unsigned char>(scriptRet.begin(), scriptRet.end()));
            return true;
        }
        return false;

    default:
        return false;
    }
}


// SignStep but returning the scriptsig/witnesscript stack, public keys used, and signatures, completely separately.
static bool SignSigsOnly(const BaseSignatureCreator& creator, const CScript& scriptPubKey,
                     std::vector<valtype>& sig_ret, txnouttype& whichTypeRet, SigVersion sigversion,
                     std::vector<CPubKey>& key_ret, std::vector<valtype>& script_ret,
                     std::map<uint160, CScript>& redeem_scripts, std::map<uint256, CScript>& witness_scripts)
{
    CScript scriptRet;
    uint160 h160;
    sig_ret.clear();
    key_ret.clear();
    script_ret.clear();

    std::vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, whichTypeRet, vSolutions))
        return false;

    CKeyID keyID;
    switch (whichTypeRet)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        return false;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        key_ret.push_back(CPubKey(vSolutions[0]));
        if (!Sign1(keyID, creator, scriptPubKey, sig_ret, sigversion)) {
            return false;
        }
        return true;
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (!Sign1(keyID, creator, scriptPubKey, sig_ret, sigversion))
            return false;
        else
        {
            script_ret = sig_ret;
            CPubKey vch;
            creator.KeyStore().GetPubKey(keyID, vch);
            key_ret.push_back(vch);
            script_ret.push_back(ToByteVector(vch));
        }
        return true;
    case TX_SCRIPTHASH: {
            auto redeem_script_it = redeem_scripts.find(uint160(vSolutions[0]));
            if (redeem_script_it != redeem_scripts.end()) {
                script_ret.push_back(std::vector<unsigned char>(redeem_script_it->second.begin(), redeem_script_it->second.end()));
                return true;
            }
            return false;
        }

    case TX_MULTISIG:
        script_ret.push_back(valtype()); // workaround CHECKMULTISIG bug
        SignN(vSolutions, creator, scriptPubKey, sig_ret, sigversion, key_ret);
        script_ret.insert(script_ret.end(), sig_ret.begin(), sig_ret.end());
        return true;

    case TX_WITNESS_V0_KEYHASH:
        script_ret.push_back(vSolutions[0]);
        return true;

    case TX_WITNESS_V0_SCRIPTHASH: {
            auto witness_script_it = witness_scripts.find(uint256(vSolutions[0]));
            if (witness_script_it != witness_scripts.end()) {
                script_ret.push_back(std::vector<unsigned char>(witness_script_it->second.begin(), witness_script_it->second.end()));
                return true;
            }
            return false;
        }

    default:
        return false;
    }
}

static CScript PushAll(const std::vector<valtype>& values)
{
    CScript result;
    for (const valtype& v : values) {
        if (v.size() == 0) {
            result << OP_0;
        } else if (v.size() == 1 && v[0] >= 1 && v[0] <= 16) {
            result << CScript::EncodeOP_N(v[0]);
        } else {
            result << v;
        }
    }
    return result;
}

bool ProduceSignature(const BaseSignatureCreator& creator, const CScript& fromPubKey, SignatureData& sigdata)
{
    CScript script = fromPubKey;
    std::vector<valtype> result;
    txnouttype whichType;
    bool solved = SignStep(creator, script, result, whichType, SIGVERSION_BASE);
    bool P2SH = false;
    CScript subscript;
    sigdata.scriptWitness.stack.clear();

    if (solved && whichType == TX_SCRIPTHASH)
    {
        // Solver returns the subscript that needs to be evaluated;
        // the final scriptSig is the signatures from that
        // and then the serialized subscript:
        script = subscript = CScript(result[0].begin(), result[0].end());
        solved = solved && SignStep(creator, script, result, whichType, SIGVERSION_BASE) && whichType != TX_SCRIPTHASH;
        P2SH = true;
    }

    if (solved && whichType == TX_WITNESS_V0_KEYHASH)
    {
        CScript witnessscript;
        witnessscript << OP_DUP << OP_HASH160 << ToByteVector(result[0]) << OP_EQUALVERIFY << OP_CHECKSIG;
        txnouttype subType;
        solved = solved && SignStep(creator, witnessscript, result, subType, SIGVERSION_WITNESS_V0);
        sigdata.scriptWitness.stack = result;
        result.clear();
    }
    else if (solved && whichType == TX_WITNESS_V0_SCRIPTHASH)
    {
        CScript witnessscript(result[0].begin(), result[0].end());
        txnouttype subType;
        solved = solved && SignStep(creator, witnessscript, result, subType, SIGVERSION_WITNESS_V0) && subType != TX_SCRIPTHASH && subType != TX_WITNESS_V0_SCRIPTHASH && subType != TX_WITNESS_V0_KEYHASH;
        result.push_back(std::vector<unsigned char>(witnessscript.begin(), witnessscript.end()));
        sigdata.scriptWitness.stack = result;
        result.clear();
    }

    if (P2SH) {
        result.push_back(std::vector<unsigned char>(subscript.begin(), subscript.end()));
    }
    sigdata.scriptSig = PushAll(result);

    // Test solution
    return solved && VerifyScript(sigdata.scriptSig, fromPubKey, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker());
}

SignatureData DataFromTransaction(const CMutableTransaction& tx, unsigned int nIn)
{
    SignatureData data;
    assert(tx.vin.size() > nIn);
    data.scriptSig = tx.vin[nIn].scriptSig;
    data.scriptWitness = tx.vin[nIn].scriptWitness;
    return data;
}

void UpdateTransaction(CMutableTransaction& tx, unsigned int nIn, const SignatureData& data)
{
    assert(tx.vin.size() > nIn);
    tx.vin[nIn].scriptSig = data.scriptSig;
    tx.vin[nIn].scriptWitness = data.scriptWitness;
}

bool SignSignature(const CKeyStore &keystore, const CScript& fromPubKey, CMutableTransaction& txTo, unsigned int nIn, const CAmount& amount, int nHashType)
{
    assert(nIn < txTo.vin.size());

    CTransaction txToConst(txTo);
    TransactionSignatureCreator creator(&keystore, &txToConst, nIn, amount, nHashType);

    SignatureData sigdata;
    bool ret = ProduceSignature(creator, fromPubKey, sigdata);
    UpdateTransaction(txTo, nIn, sigdata);
    return ret;
}

bool SignSignature(const CKeyStore &keystore, const CTransaction& txFrom, CMutableTransaction& txTo, unsigned int nIn, int nHashType)
{
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    return SignSignature(keystore, txout.scriptPubKey, txTo, nIn, txout.nValue, nHashType);
}

static std::vector<valtype> CombineMultisig(const CScript& scriptPubKey, const BaseSignatureChecker& checker,
                               const std::vector<valtype>& vSolutions,
                               const std::vector<valtype>& sigs1, const std::vector<valtype>& sigs2, SigVersion sigversion)
{
    // Combine all the signatures we've got:
    std::set<valtype> allsigs;
    for (const valtype& v : sigs1)
    {
        if (!v.empty())
            allsigs.insert(v);
    }
    for (const valtype& v : sigs2)
    {
        if (!v.empty())
            allsigs.insert(v);
    }

    // Build a map of pubkey -> signature by matching sigs to pubkeys:
    assert(vSolutions.size() > 1);
    unsigned int nSigsRequired = vSolutions.front()[0];
    unsigned int nPubKeys = vSolutions.size()-2;
    std::map<valtype, valtype> sigs;
    for (const valtype& sig : allsigs)
    {
        for (unsigned int i = 0; i < nPubKeys; i++)
        {
            const valtype& pubkey = vSolutions[i+1];
            if (sigs.count(pubkey))
                continue; // Already got a sig for this pubkey

            if (checker.CheckSig(sig, pubkey, scriptPubKey, sigversion))
            {
                sigs[pubkey] = sig;
                break;
            }
        }
    }
    // Now build a merged CScript:
    unsigned int nSigsHave = 0;
    std::vector<valtype> result; result.push_back(valtype()); // pop-one-too-many workaround
    for (unsigned int i = 0; i < nPubKeys && nSigsHave < nSigsRequired; i++)
    {
        if (sigs.count(vSolutions[i+1]))
        {
            result.push_back(sigs[vSolutions[i+1]]);
            ++nSigsHave;
        }
    }
    // Fill any missing with OP_0:
    for (unsigned int i = nSigsHave; i < nSigsRequired; i++)
        result.push_back(valtype());

    return result;
}

namespace
{
struct Stacks
{
    std::vector<valtype> script;
    std::vector<valtype> witness;

    Stacks() {}
    explicit Stacks(const std::vector<valtype>& scriptSigStack_) : script(scriptSigStack_), witness() {}
    explicit Stacks(const SignatureData& data) : witness(data.scriptWitness.stack) {
        EvalScript(script, data.scriptSig, SCRIPT_VERIFY_STRICTENC, BaseSignatureChecker(), SIGVERSION_BASE);
    }

    SignatureData Output() const {
        SignatureData result;
        result.scriptSig = PushAll(script);
        result.scriptWitness.stack = witness;
        return result;
    }
};
}

// Iterates through all inputs of the partially signed transaction and just produces signatures for what it can and adds them to the psbt partial sigs
bool SignPartialTransaction(PartiallySignedTransaction& psbt, const CKeyStore* keystore, int nHashType)
{
    CMutableTransaction mtx = psbt.tx;
    bool solved = true;
    for (unsigned int i = 0; i < mtx.vin.size(); ++i) {
        CTxIn& txin = mtx.vin[i];
        PartiallySignedInput psbt_in = psbt.inputs[i];

        // Find the non witness utxo first
        CTxOut utxo;
        if (psbt_in.non_witness_utxo) {
            utxo = psbt_in.non_witness_utxo->vout[txin.prevout.n];
        }
        // Now find the witness utxo if the non witness doesn't exist
        else if (!psbt_in.witness_utxo.IsNull()) {
            utxo = psbt_in.witness_utxo;
        }
        // If there is no nonwitness or witness utxo, then this input is fully signed and we are done here
        else {
            continue;
        }

        CScript script = utxo.scriptPubKey;
        const CAmount& amount = utxo.nValue;

        MutableTransactionSignatureCreator creator(keystore, &mtx, i, amount, nHashType);

        std::vector<valtype> sig_ret;
        std::vector<valtype> script_ret; // Only for the signer to put redemscripts to be used later.
        std::vector<CPubKey> key_ret;
        txnouttype whichType;
        solved = SignSigsOnly(creator, script, sig_ret, whichType, SIGVERSION_BASE, key_ret, script_ret, psbt.redeem_scripts, psbt.witness_scripts);

        if (solved && whichType == TX_SCRIPTHASH)
        {
            script = CScript(script_ret[0].begin(), script_ret[0].end());
            solved = solved && SignSigsOnly(creator, script, sig_ret, whichType, SIGVERSION_BASE, key_ret, script_ret, psbt.redeem_scripts, psbt.witness_scripts) && whichType != TX_SCRIPTHASH;
        }

        if (solved && whichType == TX_WITNESS_V0_KEYHASH)
        {
            CScript witnessscript;
            witnessscript << OP_DUP << OP_HASH160 << ToByteVector(script_ret[0]) << OP_EQUALVERIFY << OP_CHECKSIG;
            txnouttype subType;
            solved = solved && SignSigsOnly(creator, witnessscript, sig_ret, subType, SIGVERSION_WITNESS_V0, key_ret, script_ret, psbt.redeem_scripts, psbt.witness_scripts);
        }
        else if (solved && whichType == TX_WITNESS_V0_SCRIPTHASH)
        {
            CScript witnessscript(script_ret[0].begin(), script_ret[0].end());
            txnouttype subType;
            solved = solved && SignSigsOnly(creator, witnessscript, sig_ret, subType, SIGVERSION_WITNESS_V0, key_ret, script_ret, psbt.redeem_scripts, psbt.witness_scripts) && subType != TX_SCRIPTHASH && subType != TX_WITNESS_V0_SCRIPTHASH && subType != TX_WITNESS_V0_KEYHASH;
        }

        // Add to partial sigs
        bool P2SH = false;
        bool witness = false;
        bool WSH = false;
        CScript redeemscript;
        CScript witnessscript;
        SignatureData sigdata;
        if (solved) {
            for (unsigned int j = 0; j < key_ret.size(); ++j) {
                psbt.inputs[i].partial_sigs.emplace(key_ret[j], sig_ret[j]);
            }

            // Combine partial sigs and create full scriptsig
            std::vector<valtype> vSolutions;
            CScript spk = utxo.scriptPubKey;
            bool loop = true;
            script_ret.clear();
            while (loop) {
                loop = false;
                uint160 h160;
                CScript script_ret2;
                CKeyID keyID;
                CPubKey vch;
                if (Solver(spk, whichType, vSolutions)) {
                    switch (whichType)
                    {
                    case TX_PUBKEY:
                        script_ret.push_back(psbt.inputs[i].partial_sigs.find(CPubKey(vSolutions[0]))->second);
                        break;
                    case TX_WITNESS_V0_KEYHASH:
                        witness = true;
                    case TX_PUBKEYHASH:
                        keyID = CKeyID(uint160(vSolutions[0]));
                        creator.KeyStore().GetPubKey(keyID, vch);
                        script_ret.push_back(psbt.inputs[i].partial_sigs.find(vch)->second);
                        script_ret.push_back(ToByteVector(vch));
                        break;
                    case TX_SCRIPTHASH:
                        P2SH = true;
                        {
                            auto redeem_script_it = psbt.redeem_scripts.find(uint160(vSolutions[0]));
                            if (redeem_script_it != psbt.redeem_scripts.end()) {
                                spk = redeemscript = redeem_script_it->second;
                            } else {
                                break;
                            }
                        }
                        loop = true;
                        break;
                    case TX_MULTISIG: {
                        script_ret.push_back(valtype()); // workaround CHECKMULTISIG bug
                        SignatureData dummy_sigdata;
                        dummy_sigdata.scriptSig = spk;
                        Stacks redeemscript_stack(dummy_sigdata);
                        unsigned int nSigsRequired = redeemscript_stack.script.front()[0];
                        unsigned int nSigsHave = 0;
                        unsigned int nPubKeys = redeemscript_stack.script.size()-2;
                        for (unsigned int j = 0; j < nPubKeys && nSigsHave < nSigsRequired; ++j)
                        {
                            auto sig_it = psbt.inputs[i].partial_sigs.find(CPubKey(redeemscript_stack.script[j + 1]));
                            if (sig_it != psbt.inputs[i].partial_sigs.end()) {
                                script_ret.push_back(sig_it->second);
                                ++nSigsHave;
                            }
                        }
                        break;
                    }
                    case TX_WITNESS_V0_SCRIPTHASH:
                        witness = true;
                        WSH = true;
                        {
                            auto witness_script_it = psbt.witness_scripts.find(uint256(vSolutions[0]));
                            if (witness_script_it != psbt.witness_scripts.end()) {
                                spk = witnessscript = witness_script_it->second;
                            } else {
                                break;
                            }
                        }
                        loop = true;
                        break;

                    case TX_NONSTANDARD:
                    case TX_NULL_DATA:
                    default:
                        break;
                    }
                }
            }
        }

        if (witness) {
            if (WSH) {
                script_ret.push_back(std::vector<unsigned char>(witnessscript.begin(), witnessscript.end()));
            }
            sigdata.scriptWitness.stack = script_ret;
            script_ret.clear();
        }
        if (P2SH) {
            script_ret.push_back(std::vector<unsigned char>(redeemscript.begin(), redeemscript.end()));
        }
        sigdata.scriptSig = PushAll(script_ret);

        // Test solution
        ScriptError serror = SCRIPT_ERR_OK;
        if (VerifyScript(sigdata.scriptSig, utxo.scriptPubKey, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, creator.Checker(), &serror)) {
            // signatures are complete
            // Add scriptsig/scriptwitness to transaction
            psbt.tx.vin[i].scriptSig = sigdata.scriptSig;
            psbt.tx.vin[i].scriptWitness = sigdata.scriptWitness;
        }
        else {
            solved = false;
        }
    }

    return solved;
}

static Stacks CombineSignatures(const CScript& scriptPubKey, const BaseSignatureChecker& checker,
                                 const txnouttype txType, const std::vector<valtype>& vSolutions,
                                 Stacks sigs1, Stacks sigs2, SigVersion sigversion)
{
    switch (txType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
    case TX_WITNESS_UNKNOWN:
        // Don't know anything about this, assume bigger one is correct:
        if (sigs1.script.size() >= sigs2.script.size())
            return sigs1;
        return sigs2;
    case TX_PUBKEY:
    case TX_PUBKEYHASH:
        // Signatures are bigger than placeholders or empty scripts:
        if (sigs1.script.empty() || sigs1.script[0].empty())
            return sigs2;
        return sigs1;
    case TX_WITNESS_V0_KEYHASH:
        // Signatures are bigger than placeholders or empty scripts:
        if (sigs1.witness.empty() || sigs1.witness[0].empty())
            return sigs2;
        return sigs1;
    case TX_SCRIPTHASH:
        if (sigs1.script.empty() || sigs1.script.back().empty())
            return sigs2;
        else if (sigs2.script.empty() || sigs2.script.back().empty())
            return sigs1;
        else
        {
            // Recur to combine:
            valtype spk = sigs1.script.back();
            CScript pubKey2(spk.begin(), spk.end());

            txnouttype txType2;
            std::vector<std::vector<unsigned char> > vSolutions2;
            Solver(pubKey2, txType2, vSolutions2);
            sigs1.script.pop_back();
            sigs2.script.pop_back();
            Stacks result = CombineSignatures(pubKey2, checker, txType2, vSolutions2, sigs1, sigs2, sigversion);
            result.script.push_back(spk);
            return result;
        }
    case TX_MULTISIG:
        return Stacks(CombineMultisig(scriptPubKey, checker, vSolutions, sigs1.script, sigs2.script, sigversion));
    case TX_WITNESS_V0_SCRIPTHASH:
        if (sigs1.witness.empty() || sigs1.witness.back().empty())
            return sigs2;
        else if (sigs2.witness.empty() || sigs2.witness.back().empty())
            return sigs1;
        else
        {
            // Recur to combine:
            CScript pubKey2(sigs1.witness.back().begin(), sigs1.witness.back().end());
            txnouttype txType2;
            std::vector<valtype> vSolutions2;
            Solver(pubKey2, txType2, vSolutions2);
            sigs1.witness.pop_back();
            sigs1.script = sigs1.witness;
            sigs1.witness.clear();
            sigs2.witness.pop_back();
            sigs2.script = sigs2.witness;
            sigs2.witness.clear();
            Stacks result = CombineSignatures(pubKey2, checker, txType2, vSolutions2, sigs1, sigs2, SIGVERSION_WITNESS_V0);
            result.witness = result.script;
            result.script.clear();
            result.witness.push_back(valtype(pubKey2.begin(), pubKey2.end()));
            return result;
        }
    default:
        return Stacks();
    }
}

SignatureData CombineSignatures(const CScript& scriptPubKey, const BaseSignatureChecker& checker,
                          const SignatureData& scriptSig1, const SignatureData& scriptSig2)
{
    txnouttype txType;
    std::vector<std::vector<unsigned char> > vSolutions;
    Solver(scriptPubKey, txType, vSolutions);

    return CombineSignatures(scriptPubKey, checker, txType, vSolutions, Stacks(scriptSig1), Stacks(scriptSig2), SIGVERSION_BASE).Output();
}

namespace {
/** Dummy signature checker which accepts all signatures. */
class DummySignatureChecker : public BaseSignatureChecker
{
public:
    DummySignatureChecker() {}

    bool CheckSig(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override
    {
        return true;
    }
};
const DummySignatureChecker dummyChecker;
} // namespace

const BaseSignatureChecker& DummySignatureCreator::Checker() const
{
    return dummyChecker;
}

bool DummySignatureCreator::CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode, SigVersion sigversion) const
{
    // Create a dummy signature that is a valid DER-encoding
    vchSig.assign(72, '\000');
    vchSig[0] = 0x30;
    vchSig[1] = 69;
    vchSig[2] = 0x02;
    vchSig[3] = 33;
    vchSig[4] = 0x01;
    vchSig[4 + 33] = 0x02;
    vchSig[5 + 33] = 32;
    vchSig[6 + 33] = 0x01;
    vchSig[6 + 33 + 32] = SIGHASH_ALL;
    return true;
}

PartiallySignedTransaction::PartiallySignedTransaction() : tx(), redeem_scripts(), witness_scripts(), inputs() {}
PartiallySignedTransaction::PartiallySignedTransaction(CMutableTransaction& tx, std::map<uint160, CScript>& redeem_scripts, std::map<uint256, CScript>& witness_scripts, std::vector<PartiallySignedInput>& inputs)
{
    this->tx = tx;
    this->redeem_scripts = redeem_scripts;
    this->witness_scripts = witness_scripts;
    this->inputs = inputs;

    sanitize_for_serialization();
}

void PartiallySignedTransaction::sanitize_for_serialization()
{
    // Remove sigs from inputs
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        CTxIn& in = tx.vin[i];
        PartiallySignedInput psbt_in = inputs[i];
        CTxOut vout;
        if (psbt_in.non_witness_utxo) {
            vout = psbt_in.non_witness_utxo->vout[in.prevout.n];
        }
        else if (!psbt_in.witness_utxo.IsNull()) {
            vout = psbt_in.witness_utxo;
        }
        else {
            // There is no input here, skip
            continue;
        }

        // Check the input for sigs. Remove partial sigs. Assume that they are already in partial_sigs
        ScriptError serror = SCRIPT_ERR_OK;
        const CAmount& amount = vout.nValue;
        const CTransaction const_tx(tx);
        if (!VerifyScript(in.scriptSig, vout.scriptPubKey, &in.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&const_tx, i, amount), &serror)) {
            in.scriptSig.clear();
            in.scriptWitness.SetNull();
        }
        // If this passes, then remove all input data for this input
        else {
            inputs[i].SetNull();
        }
    }
}

void PartiallySignedInput::SetNull()
{
    non_witness_utxo = CTransactionRef();
    witness_utxo.SetNull();
    partial_sigs.clear();
    unknown.clear();
}

bool PartiallySignedInput::IsNull()
{
    return !non_witness_utxo && witness_utxo.IsNull() && partial_sigs.empty() && unknown.empty();
}
