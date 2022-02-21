// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/walletdb.h>

#include <fs.h>
#include <key_io.h>
#include <protocol.h>
#include <serialize.h>
#include <sync.h>
#include <util/bip32.h>
#include <util/system.h>
#include <util/time.h>
#include <util/translation.h>
#ifdef USE_BDB
#include <wallet/bdb.h>
#endif
#ifdef USE_SQLITE
#include <wallet/sqlite.h>
#endif
#include <wallet/wallet.h>

#include <atomic>
#include <optional>
#include <string>

namespace wallet {
namespace DBKeys {
const std::string ACENTRY{"acentry"};
const std::string ACTIVEEXTERNALSPK{"activeexternalspk"};
const std::string ACTIVEINTERNALSPK{"activeinternalspk"};
const std::string BESTBLOCK_NOMERKLE{"bestblock_nomerkle"};
const std::string BESTBLOCK{"bestblock"};
const std::string CRYPTED_KEY{"ckey"};
const std::string CSCRIPT{"cscript"};
const std::string DEFAULTKEY{"defaultkey"};
const std::string DESTDATA{"destdata"};
const std::string FLAGS{"flags"};
const std::string HDCHAIN{"hdchain"};
const std::string KEYMETA{"keymeta"};
const std::string KEY{"key"};
const std::string LOCKED_UTXO{"lockedutxo"};
const std::string MASTER_KEY{"mkey"};
const std::string MINVERSION{"minversion"};
const std::string NAME{"name"};
const std::string OLD_KEY{"wkey"};
const std::string ORDERPOSNEXT{"orderposnext"};
const std::string POOL{"pool"};
const std::string PURPOSE{"purpose"};
const std::string SETTINGS{"settings"};
const std::string TX{"tx"};
const std::string TXOUT{"txout"};
const std::string VERSION{"version"};
const std::string WALLETDESCRIPTOR{"walletdescriptor"};
const std::string WALLETDESCRIPTORCACHE{"walletdescriptorcache"};
const std::string WALLETDESCRIPTORLHCACHE{"walletdescriptorlhcache"};
const std::string WALLETDESCRIPTORCKEY{"walletdescriptorckey"};
const std::string WALLETDESCRIPTORKEY{"walletdescriptorkey"};
const std::string WATCHMETA{"watchmeta"};
const std::string WATCHS{"watchs"};
} // namespace DBKeys

//
// WalletBatch
//

bool WalletBatch::WriteName(const std::string& strAddress, const std::string& strName)
{
    return WriteIC(std::make_pair(DBKeys::NAME, strAddress), strName);
}

bool WalletBatch::EraseName(const std::string& strAddress)
{
    // This should only be used for sending addresses, never for receiving addresses,
    // receiving addresses must always have an address book entry if they're not change return.
    return EraseIC(std::make_pair(DBKeys::NAME, strAddress));
}

bool WalletBatch::WritePurpose(const std::string& strAddress, const std::string& strPurpose)
{
    return WriteIC(std::make_pair(DBKeys::PURPOSE, strAddress), strPurpose);
}

bool WalletBatch::ErasePurpose(const std::string& strAddress)
{
    return EraseIC(std::make_pair(DBKeys::PURPOSE, strAddress));
}

bool WalletBatch::WriteTx(const CWalletTx& wtx)
{
    return WriteIC(std::make_pair(DBKeys::TX, wtx.GetHash()), wtx);
}

bool WalletBatch::EraseTx(uint256 hash)
{
    return EraseIC(std::make_pair(DBKeys::TX, hash));
}

bool WalletBatch::WriteKeyMetadata(const CKeyMetadata& meta, const CPubKey& pubkey, const bool overwrite)
{
    return WriteIC(std::make_pair(DBKeys::KEYMETA, pubkey), meta, overwrite);
}

bool WalletBatch::WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata& keyMeta)
{
    if (!WriteKeyMetadata(keyMeta, vchPubKey, false)) {
        return false;
    }

    // hash pubkey/privkey to accelerate wallet load
    std::vector<unsigned char> vchKey;
    vchKey.reserve(vchPubKey.size() + vchPrivKey.size());
    vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
    vchKey.insert(vchKey.end(), vchPrivKey.begin(), vchPrivKey.end());

    return WriteIC(std::make_pair(DBKeys::KEY, vchPubKey), std::make_pair(vchPrivKey, Hash(vchKey)), false);
}

bool WalletBatch::WriteCryptedKey(const CPubKey& vchPubKey,
                                const std::vector<unsigned char>& vchCryptedSecret,
                                const CKeyMetadata &keyMeta)
{
    if (!WriteKeyMetadata(keyMeta, vchPubKey, true)) {
        return false;
    }

    // Compute a checksum of the encrypted key
    uint256 checksum = Hash(vchCryptedSecret);

    const auto key = std::make_pair(DBKeys::CRYPTED_KEY, vchPubKey);
    if (!WriteIC(key, std::make_pair(vchCryptedSecret, checksum), false)) {
        // It may already exist, so try writing just the checksum
        std::vector<unsigned char> val;
        if (!m_batch->Read(key, val)) {
            return false;
        }
        if (!WriteIC(key, std::make_pair(val, checksum), true)) {
            return false;
        }
    }
    EraseIC(std::make_pair(DBKeys::KEY, vchPubKey));
    return true;
}

bool WalletBatch::WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey)
{
    return WriteIC(std::make_pair(DBKeys::MASTER_KEY, nID), kMasterKey, true);
}

bool WalletBatch::WriteCScript(const uint160& hash, const CScript& redeemScript)
{
    return WriteIC(std::make_pair(DBKeys::CSCRIPT, hash), redeemScript, false);
}

bool WalletBatch::WriteWatchOnly(const CScript &dest, const CKeyMetadata& keyMeta)
{
    if (!WriteIC(std::make_pair(DBKeys::WATCHMETA, dest), keyMeta)) {
        return false;
    }
    return WriteIC(std::make_pair(DBKeys::WATCHS, dest), uint8_t{'1'});
}

bool WalletBatch::EraseWatchOnly(const CScript &dest)
{
    if (!EraseIC(std::make_pair(DBKeys::WATCHMETA, dest))) {
        return false;
    }
    return EraseIC(std::make_pair(DBKeys::WATCHS, dest));
}

bool WalletBatch::WriteBestBlock(const CBlockLocator& locator)
{
    WriteIC(DBKeys::BESTBLOCK, CBlockLocator()); // Write empty block locator so versions that require a merkle branch automatically rescan
    return WriteIC(DBKeys::BESTBLOCK_NOMERKLE, locator);
}

bool WalletBatch::ReadBestBlock(CBlockLocator& locator)
{
    if (m_batch->Read(DBKeys::BESTBLOCK, locator) && !locator.vHave.empty()) return true;
    return m_batch->Read(DBKeys::BESTBLOCK_NOMERKLE, locator);
}

bool WalletBatch::WriteOrderPosNext(int64_t nOrderPosNext)
{
    return WriteIC(DBKeys::ORDERPOSNEXT, nOrderPosNext);
}

bool WalletBatch::ReadPool(int64_t nPool, CKeyPool& keypool)
{
    return m_batch->Read(std::make_pair(DBKeys::POOL, nPool), keypool);
}

bool WalletBatch::WritePool(int64_t nPool, const CKeyPool& keypool)
{
    return WriteIC(std::make_pair(DBKeys::POOL, nPool), keypool);
}

bool WalletBatch::ErasePool(int64_t nPool)
{
    return EraseIC(std::make_pair(DBKeys::POOL, nPool));
}

bool WalletBatch::WriteMinVersion(int nVersion)
{
    return WriteIC(DBKeys::MINVERSION, nVersion);
}

bool WalletBatch::WriteActiveScriptPubKeyMan(uint8_t type, const uint256& id, bool internal)
{
    std::string key = internal ? DBKeys::ACTIVEINTERNALSPK : DBKeys::ACTIVEEXTERNALSPK;
    return WriteIC(make_pair(key, type), id);
}

bool WalletBatch::EraseActiveScriptPubKeyMan(uint8_t type, bool internal)
{
    const std::string key{internal ? DBKeys::ACTIVEINTERNALSPK : DBKeys::ACTIVEEXTERNALSPK};
    return EraseIC(make_pair(key, type));
}

bool WalletBatch::WriteDescriptorKey(const uint256& desc_id, const CPubKey& pubkey, const CPrivKey& privkey)
{
    // hash pubkey/privkey to accelerate wallet load
    std::vector<unsigned char> key;
    key.reserve(pubkey.size() + privkey.size());
    key.insert(key.end(), pubkey.begin(), pubkey.end());
    key.insert(key.end(), privkey.begin(), privkey.end());

    return WriteIC(std::make_pair(DBKeys::WALLETDESCRIPTORKEY, std::make_pair(desc_id, pubkey)), std::make_pair(privkey, Hash(key)), false);
}

bool WalletBatch::WriteCryptedDescriptorKey(const uint256& desc_id, const CPubKey& pubkey, const std::vector<unsigned char>& secret)
{
    if (!WriteIC(std::make_pair(DBKeys::WALLETDESCRIPTORCKEY, std::make_pair(desc_id, pubkey)), secret, false)) {
        return false;
    }
    EraseIC(std::make_pair(DBKeys::WALLETDESCRIPTORKEY, std::make_pair(desc_id, pubkey)));
    return true;
}

bool WalletBatch::WriteDescriptor(const uint256& desc_id, const WalletDescriptor& descriptor)
{
    return WriteIC(make_pair(DBKeys::WALLETDESCRIPTOR, desc_id), descriptor);
}

bool WalletBatch::WriteDescriptorDerivedCache(const CExtPubKey& xpub, const uint256& desc_id, uint32_t key_exp_index, uint32_t der_index)
{
    std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
    xpub.Encode(ser_xpub.data());
    return WriteIC(std::make_pair(std::make_pair(DBKeys::WALLETDESCRIPTORCACHE, desc_id), std::make_pair(key_exp_index, der_index)), ser_xpub);
}

bool WalletBatch::WriteDescriptorParentCache(const CExtPubKey& xpub, const uint256& desc_id, uint32_t key_exp_index)
{
    std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
    xpub.Encode(ser_xpub.data());
    return WriteIC(std::make_pair(std::make_pair(DBKeys::WALLETDESCRIPTORCACHE, desc_id), key_exp_index), ser_xpub);
}

bool WalletBatch::WriteDescriptorLastHardenedCache(const CExtPubKey& xpub, const uint256& desc_id, uint32_t key_exp_index)
{
    std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
    xpub.Encode(ser_xpub.data());
    return WriteIC(std::make_pair(std::make_pair(DBKeys::WALLETDESCRIPTORLHCACHE, desc_id), key_exp_index), ser_xpub);
}

bool WalletBatch::WriteDescriptorCacheItems(const uint256& desc_id, const DescriptorCache& cache)
{
    for (const auto& parent_xpub_pair : cache.GetCachedParentExtPubKeys()) {
        if (!WriteDescriptorParentCache(parent_xpub_pair.second, desc_id, parent_xpub_pair.first)) {
            return false;
        }
    }
    for (const auto& derived_xpub_map_pair : cache.GetCachedDerivedExtPubKeys()) {
        for (const auto& derived_xpub_pair : derived_xpub_map_pair.second) {
            if (!WriteDescriptorDerivedCache(derived_xpub_pair.second, desc_id, derived_xpub_map_pair.first, derived_xpub_pair.first)) {
                return false;
            }
        }
    }
    for (const auto& lh_xpub_pair : cache.GetCachedLastHardenedExtPubKeys()) {
        if (!WriteDescriptorLastHardenedCache(lh_xpub_pair.second, desc_id, lh_xpub_pair.first)) {
            return false;
        }
    }
    return true;
}

bool WalletBatch::WriteLockedUTXO(const COutPoint& output)
{
    return WriteIC(std::make_pair(DBKeys::LOCKED_UTXO, std::make_pair(output.hash, output.n)), uint8_t{'1'});
}

bool WalletBatch::EraseLockedUTXO(const COutPoint& output)
{
    return EraseIC(std::make_pair(DBKeys::LOCKED_UTXO, std::make_pair(output.hash, output.n)));
}

bool WalletBatch::WriteTxOut(const COutPoint& outpoint, const CTxOut& txout)
{
    return WriteIC(std::make_pair(DBKeys::TXOUT, outpoint), txout);
}

bool LoadKey(CWallet* pwallet, CDataStream& ssKey, CDataStream& ssValue, std::string& strErr)
{
    try {
        CPubKey vchPubKey;
        ssKey >> vchPubKey;
        if (!vchPubKey.IsValid())
        {
            strErr = "Error reading wallet database: CPubKey corrupt";
            return false;
        }
        CKey key;
        CPrivKey pkey;
        uint256 hash;

        ssValue >> pkey;

        // Old wallets store keys as DBKeys::KEY [pubkey] => [privkey]
        // ... which was slow for wallets with lots of keys, because the public key is re-derived from the private key
        // using EC operations as a checksum.
        // Newer wallets store keys as DBKeys::KEY [pubkey] => [privkey][hash(pubkey,privkey)], which is much faster while
        // remaining backwards-compatible.
        try
        {
            ssValue >> hash;
        }
        catch (const std::ios_base::failure&) {}

        bool fSkipCheck = false;

        if (!hash.IsNull())
        {
            // hash pubkey/privkey to accelerate wallet load
            std::vector<unsigned char> vchKey;
            vchKey.reserve(vchPubKey.size() + pkey.size());
            vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
            vchKey.insert(vchKey.end(), pkey.begin(), pkey.end());

            if (Hash(vchKey) != hash)
            {
                strErr = "Error reading wallet database: CPubKey/CPrivKey corrupt";
                return false;
            }

            fSkipCheck = true;
        }

        if (!key.Load(pkey, vchPubKey, fSkipCheck))
        {
            strErr = "Error reading wallet database: CPrivKey corrupt";
            return false;
        }
        if (!pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadKey(key, vchPubKey))
        {
            strErr = "Error reading wallet database: LegacyScriptPubKeyMan::LoadKey failed";
            return false;
        }
    } catch (const std::exception& e) {
        if (strErr.empty()) {
            strErr = e.what();
        }
        return false;
    }
    return true;
}

bool LoadCryptedKey(CWallet* pwallet, CDataStream& ssKey, CDataStream& ssValue, std::string& strErr)
{
    try {
        CPubKey vchPubKey;
        ssKey >> vchPubKey;
        if (!vchPubKey.IsValid())
        {
            strErr = "Error reading wallet database: CPubKey corrupt";
            return false;
        }
        std::vector<unsigned char> vchPrivKey;
        ssValue >> vchPrivKey;

        // Get the checksum and check it
        bool checksum_valid = false;
        if (!ssValue.eof()) {
            uint256 checksum;
            ssValue >> checksum;
            if ((checksum_valid = Hash(vchPrivKey) != checksum)) {
                strErr = "Error reading wallet database: Encrypted key corrupt";
                return false;
            }
        }

        if (!pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadCryptedKey(vchPubKey, vchPrivKey, checksum_valid))
        {
            strErr = "Error reading wallet database: LegacyScriptPubKeyMan::LoadCryptedKey failed";
            return false;
        }
    } catch (const std::exception& e) {
        if (strErr.empty()) {
            strErr = e.what();
        }
        return false;
    }
    return true;
}

bool LoadEncryptionKey(CWallet* pwallet, CDataStream& ssKey, CDataStream& ssValue, std::string& strErr)
{
    try {
        // Master encryption key is loaded into only the wallet and not any of the ScriptPubKeyMans.
        unsigned int nID;
        ssKey >> nID;
        CMasterKey kMasterKey;
        ssValue >> kMasterKey;
        if(pwallet->mapMasterKeys.count(nID) != 0)
        {
            strErr = strprintf("Error reading wallet database: duplicate CMasterKey id %u", nID);
            return false;
        }
        pwallet->mapMasterKeys[nID] = kMasterKey;
        if (pwallet->nMasterKeyMaxID < nID)
            pwallet->nMasterKeyMaxID = nID;

    } catch (const std::exception& e) {
        if (strErr.empty()) {
            strErr = e.what();
        }
        return false;
    }
    return true;
}

bool LoadHDChain(CWallet* pwallet, CDataStream& ssKey, CDataStream& ssValue, std::string& strErr)
{
    CHDChain chain;
    ssValue >> chain;
    pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadHDChain(chain);
    return true;
}

bool WalletBatch::IsKeyType(const std::string& strType)
{
    return (strType == DBKeys::KEY ||
            strType == DBKeys::MASTER_KEY || strType == DBKeys::CRYPTED_KEY);
}

std::unique_ptr<DatabaseCursor> WalletBatch::GetTypeCursor(const std::string& type)
{
    CDataStream prefix(0, 0);
    prefix << type;
    std::unique_ptr<DatabaseCursor> cursor = m_batch->GetPrefixCursor(prefix);
    return cursor;
}

DBErrors WalletBatch::LoadMinVersion(CWallet* pwallet)
{
    int nMinVersion = 0;
    if (m_batch->Read(DBKeys::MINVERSION, nMinVersion)) {
        if (nMinVersion > FEATURE_LATEST)
            return DBErrors::TOO_NEW;
        pwallet->LoadMinVersion(nMinVersion);
    }
    return DBErrors::LOAD_OK;
}

DBErrors WalletBatch::LoadWalletFlags(CWallet* pwallet)
{
    uint64_t flags;
    if (m_batch->Read(DBKeys::FLAGS, flags)) {
        if (!pwallet->LoadWalletFlags(flags)) {
            pwallet->WalletLogPrintf("Error reading wallet database: Unknown non-tolerable wallet flags found\n");
            return DBErrors::TOO_NEW;
        }
    }
    return DBErrors::LOAD_OK;
}

DBErrors WalletBatch::LoadLegacyWalletRecords(CWallet* pwallet, int last_client)
{
    DBErrors result = DBErrors::LOAD_OK;
    std::string err;

    // Load HD Chain
    CHDChain chain;
    if (m_batch->Read(DBKeys::HDCHAIN, chain)) {
        pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadHDChain(chain);
    }

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);

    // Load unencrypted keys
    std::unique_ptr<DatabaseCursor> cursor = GetTypeCursor(DBKeys::KEY);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for unencrypted keys\n");
        return DBErrors::CORRUPT;
    }

    int num_keys = 0;
    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next unencrypted key record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::KEY);
        if (!LoadKey(pwallet, ssKey, ssValue, err)) {
            result = DBErrors::CORRUPT;
            pwallet->WalletLogPrintf("%s\n", err);
        }
    }
    cursor.reset();

    // Load encrypted keys
    cursor = GetTypeCursor(DBKeys::CRYPTED_KEY);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for crypted keys\n");
        return DBErrors::CORRUPT;
    }

    int num_ckeys = 0;
    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next encrypted key record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::CRYPTED_KEY);
        if (!LoadCryptedKey(pwallet, ssKey, ssValue, err)) {
            result = DBErrors::CORRUPT;
            pwallet->WalletLogPrintf("%s\n", err);
        }
    }
    cursor.reset();

    // Load scripts
    cursor = GetTypeCursor(DBKeys::CSCRIPT);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for scripts\n");
        return DBErrors::CORRUPT;
    }

    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next script record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::CSCRIPT);
        uint160 hash;
        ssKey >> hash;
        CScript script;
        ssValue >> script;
        if (!pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadCScript(script))
        {
            pwallet->WalletLogPrintf("Error reading wallet database: LegacyScriptPubKeyMan::LoadCScript failed");
            return DBErrors::CORRUPT;
        }
    }
    cursor.reset();

    // Check whether rewrite is needed
    if (num_ckeys > 0) {
        // Rewrite encrypted wallets of versions 0.4.0 and 0.5.0rc:
        if (last_client == 40000 || last_client == 50000) return DBErrors::NEED_REWRITE;
    }

    // Load keymeta
    cursor = GetTypeCursor(DBKeys::KEYMETA);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for key metadata\n");
        return DBErrors::CORRUPT;
    }

    int num_keymeta = 0;
    std::map<uint160, CHDChain> hd_chains;
    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next keymeta record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::KEYMETA);
        CPubKey vchPubKey;
        ssKey >> vchPubKey;
        CKeyMetadata keyMeta;
        ssValue >> keyMeta;
        num_keymeta++;
        pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadKeyMetadata(vchPubKey.GetID(), keyMeta);

        // Extract some CHDChain info from this metadata if it has any
        if (keyMeta.nVersion >= CKeyMetadata::VERSION_WITH_HDDATA && !keyMeta.hd_seed_id.IsNull() && keyMeta.hdKeypath.size() > 0) {
            // Get the path from the key origin or from the path string
            // Not applicable when path is "s" or "m" as those indicate a seed
            // See https://github.com/bitcoin/bitcoin/pull/12924
            bool internal = false;
            uint32_t index = 0;
            if (keyMeta.hdKeypath != "s" && keyMeta.hdKeypath != "m") {
                std::vector<uint32_t> path;
                if (keyMeta.has_key_origin) {
                    // We have a key origin, so pull it from its path vector
                    path = keyMeta.key_origin.path;
                } else {
                    // No key origin, have to parse the string
                    if (!ParseHDKeypath(keyMeta.hdKeypath, path)) {
                        pwallet->WalletLogPrintf("Error reading wallet database: keymeta with invalid HD keypath\n");
                        result = DBErrors::NONCRITICAL_ERROR;
                        continue;
                    }
                }

                // Extract the index and internal from the path
                // Path string is m/0'/k'/i'
                // Path vector is [0', k', i'] (but as ints OR'd with the hardened bit
                // k == 0 for external, 1 for internal. i is the index
                if (path.size() != 3) {
                    pwallet->WalletLogPrintf("Error reading wallet database: keymeta found with unexpected path\n");
                    result = DBErrors::NONCRITICAL_ERROR;
                    continue;
                }
                if (path[0] != 0x80000000) {
                    pwallet->WalletLogPrintf("Unexpected path index of 0x%08x (expected 0x80000000) for the element at index 0\n", path[0]);
                    result = DBErrors::NONCRITICAL_ERROR;
                    continue;
                }
                if (path[1] != 0x80000000 && path[1] != (1 | 0x80000000)) {
                    pwallet->WalletLogPrintf("Unexpected path index of 0x%08x (expected 0x80000000 or 0x80000001) for the element at index 1\n", path[1]);
                    result = DBErrors::NONCRITICAL_ERROR;
                    continue;
                }
                if ((path[2] & 0x80000000) == 0) {
                    pwallet->WalletLogPrintf("Unexpected path index of 0x%08x (expected to be greater than or equal to 0x80000000)\n", path[2]);
                    result = DBErrors::NONCRITICAL_ERROR;
                    continue;
                }
                internal = path[1] == (1 | 0x80000000);
                index = path[2] & ~0x80000000;
            }

            // Insert a new CHDChain, or get the one that already exists
            auto ins = hd_chains.emplace(keyMeta.hd_seed_id, CHDChain());
            CHDChain& chain = ins.first->second;
            if (ins.second) {
                // For new chains, we want to default to VERSION_HD_BASE until we see an internal
                chain.nVersion = CHDChain::VERSION_HD_BASE;
                chain.seed_id = keyMeta.hd_seed_id;
            }
            if (internal) {
                chain.nVersion = CHDChain::VERSION_HD_CHAIN_SPLIT;
                chain.nInternalChainCounter = std::max(chain.nInternalChainCounter, index + 1);
            } else {
                chain.nExternalChainCounter = std::max(chain.nExternalChainCounter, index + 1);
            }
        }
    }
    cursor.reset();

    // Set inactive chains
    if (hd_chains.size() > 0) {
        LegacyScriptPubKeyMan* legacy_spkm = pwallet->GetLegacyScriptPubKeyMan();
        if (!legacy_spkm) {
            pwallet->WalletLogPrintf("Inactive HD Chains found but no Legacy ScriptPubKeyMan\n");
            return DBErrors::CORRUPT;
        }
        for (const auto& chain_pair : hd_chains) {
            if (chain_pair.first != pwallet->GetLegacyScriptPubKeyMan()->GetHDChain().seed_id) {
                pwallet->GetLegacyScriptPubKeyMan()->AddInactiveHDChain(chain_pair.second);
            }
        }
    }

    // Load watchonly scripts
    cursor = GetTypeCursor(DBKeys::WATCHS);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for watchonly scripts\n");
        return DBErrors::CORRUPT;
    }

    int num_watchkeys = 0;
    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next watchonly script record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::WATCHS);
        num_watchkeys++;
        CScript script;
        ssKey >> script;
        uint8_t fYes;
        ssValue >> fYes;
        if (fYes == '1') {
            pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadWatchOnly(script);
        }
    }
    cursor.reset();

    // Load watchonly meta
    cursor = GetTypeCursor(DBKeys::WATCHMETA);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for watchonly meta\n");
        return DBErrors::CORRUPT;
    }

    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next watchonly metadata record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::WATCHMETA);
        CScript script;
        ssKey >> script;
        CKeyMetadata keyMeta;
        ssValue >> keyMeta;
        num_keymeta++;
        pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadScriptMetadata(CScriptID(script), keyMeta);
    }
    cursor.reset();

    // Load keypool
    cursor = GetTypeCursor(DBKeys::POOL);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for keypool entries\n");
        return DBErrors::CORRUPT;
    }

    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next keypool record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::POOL);
        int64_t nIndex;
        ssKey >> nIndex;
        CKeyPool keypool;
        ssValue >> keypool;

        pwallet->GetOrCreateLegacyScriptPubKeyMan()->LoadKeyPool(nIndex, keypool);
    }
    cursor.reset();

    // Deal with old "wkey" and "defaultkey" records.
    // These are not actually loaded, but we need to check for them

    // We don't want or need the default key, but if there is one set,
    // we want to make sure that it is valid so that we can detect corruption
    CPubKey default_pubkey;
    if (m_batch->Read(DBKeys::DEFAULTKEY, default_pubkey) && !default_pubkey.IsValid()) {
        pwallet->WalletLogPrintf("Error reading wallet database: Default Key corrupt");
        return DBErrors::CORRUPT;
    }

    // "wkey" records are unsupported, if we see any, throw an error
    cursor = GetTypeCursor(DBKeys::OLD_KEY);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for wkey (old_key) entries\n");
        return DBErrors::CORRUPT;
    }

    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next keypool record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::OLD_KEY);
        pwallet->WalletLogPrintf("Found unsupported 'wkey' record, try loading with version 0.18");
        return DBErrors::LOAD_FAIL;
    }
    cursor.reset();

    pwallet->WalletLogPrintf("Legacy Wallet Keys: %u plaintext, %u encrypted, %u w/ metadata, %u total.\n",
           num_keys, num_ckeys, num_keymeta, num_keys + num_ckeys);

    // nTimeFirstKey is only reliable if all keys have metadata
    if (pwallet->IsLegacy() && (num_keys + num_ckeys + num_watchkeys) != num_keymeta) {
        auto spk_man = pwallet->GetOrCreateLegacyScriptPubKeyMan();
        if (spk_man) {
            LOCK(spk_man->cs_KeyStore);
            spk_man->UpdateTimeFirstKey(1);
        }
    }

    return result;
}

DBErrors WalletBatch::LoadDescriptorWalletRecords(CWallet* pwallet)
{
    DBErrors result = DBErrors::LOAD_OK;
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);

    // Load descriptor record
    std::unique_ptr<DatabaseCursor> cursor = GetTypeCursor(DBKeys::WALLETDESCRIPTOR);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for descriptors\n");
        return DBErrors::CORRUPT;
    }

    int num_descs = 0;
    int num_keys = 0;
    int num_ckeys= 0;
    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next descriptor record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::WALLETDESCRIPTOR);
        uint256 id;
        ssKey >> id;
        WalletDescriptor desc;
        ssValue >> desc;
        pwallet->LoadDescriptorScriptPubKeyMan(id, desc);
        num_descs++;

        DescriptorCache cache;

        // Get key cache for this descriptor
        CDataStream prefix(0, 0);
        prefix << DBKeys::WALLETDESCRIPTORCACHE << id;
        std::unique_ptr<DatabaseCursor> sub_cursor = m_batch->GetPrefixCursor(prefix);
        if (!sub_cursor) {
            pwallet->WalletLogPrintf("Error getting database cursor for descriptor key cache\n");
            return DBErrors::CORRUPT;
        }
        while (true) {
            bool complete;
            bool ret = sub_cursor->Next(ssKey, ssValue, complete);
            if (complete) {
                break;
            } else if (!ret) {
                pwallet->WalletLogPrintf("Error reading next descriptor key cache record for wallet database\n");
                return DBErrors::CORRUPT;
            }
            std::string type;
            ssKey >> type;
            assert(type == DBKeys::WALLETDESCRIPTORCACHE);
            bool parent = true;
            uint256 desc_id;
            uint32_t key_exp_index;
            uint32_t der_index;
            ssKey >> desc_id;
            assert(desc_id == id);
            ssKey >> key_exp_index;

            // if the der_index exists, it's a derived xpub
            try
            {
                ssKey >> der_index;
                parent = false;
            }
            catch (...) {}

            std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
            ssValue >> ser_xpub;
            CExtPubKey xpub;
            xpub.Decode(ser_xpub.data());
            if (parent) {
                cache.CacheParentExtPubKey(key_exp_index, xpub);
            } else {
                cache.CacheDerivedExtPubKey(key_exp_index, der_index, xpub);
            }
        }
        sub_cursor.reset();

        // Get last hardened cache for this descriptor
        prefix.clear();
        prefix << DBKeys::WALLETDESCRIPTORLHCACHE << id;
        sub_cursor = m_batch->GetPrefixCursor(prefix);
        if (!sub_cursor) {
            pwallet->WalletLogPrintf("Error getting database cursor for descriptor last hardened cache\n");
            return DBErrors::CORRUPT;
        }
        while (true) {
            bool complete;
            bool ret = sub_cursor->Next(ssKey, ssValue, complete);
            if (complete) {
                break;
            } else if (!ret) {
                pwallet->WalletLogPrintf("Error reading next descriptor last hardened cache record for wallet database\n");
                return DBErrors::CORRUPT;
            }
            std::string type;
            ssKey >> type;
            assert(type == DBKeys::WALLETDESCRIPTORLHCACHE);
            uint256 desc_id;
            uint32_t key_exp_index;
            ssKey >> desc_id;
            assert(desc_id == id);
            ssKey >> key_exp_index;

            std::vector<unsigned char> ser_xpub(BIP32_EXTKEY_SIZE);
            ssValue >> ser_xpub;
            CExtPubKey xpub;
            xpub.Decode(ser_xpub.data());
            cache.CacheLastHardenedExtPubKey(key_exp_index, xpub);
        }
        sub_cursor.reset();

        // Set the cache for this descriptor
        auto spk_man = (DescriptorScriptPubKeyMan*)pwallet->GetScriptPubKeyMan(id);
        assert(spk_man);
        spk_man->SetCache(cache);

        // Get unencrypted keys
        prefix.clear();
        prefix << DBKeys::WALLETDESCRIPTORKEY << id;
        sub_cursor = m_batch->GetPrefixCursor(prefix);
        if (!sub_cursor) {
            pwallet->WalletLogPrintf("Error getting database cursor for descriptor unencrypted keys\n");
            return DBErrors::CORRUPT;
        }
        std::map<CKeyID, CKey> descriptor_keys;
        while (true) {
            bool complete;
            bool ret = sub_cursor->Next(ssKey, ssValue, complete);
            if (complete) {
                break;
            } else if (!ret) {
                pwallet->WalletLogPrintf("Error reading next descriptor unencrypted key record for wallet database\n");
                return DBErrors::CORRUPT;
            }
            std::string type;
            ssKey >> type;
            assert(type == DBKeys::WALLETDESCRIPTORKEY);
            uint256 desc_id;
            CPubKey pubkey;
            ssKey >> desc_id;
            assert(desc_id == id);
            ssKey >> pubkey;
            if (!pubkey.IsValid())
            {
                pwallet->WalletLogPrintf("Error reading wallet database: descriptor unencrypted key CPubKey corrupt");
                return DBErrors::CORRUPT;
            }
            CKey key;
            CPrivKey pkey;
            uint256 hash;

            num_keys++;
            ssValue >> pkey;
            ssValue >> hash;

            // hash pubkey/privkey to accelerate wallet load
            std::vector<unsigned char> to_hash;
            to_hash.reserve(pubkey.size() + pkey.size());
            to_hash.insert(to_hash.end(), pubkey.begin(), pubkey.end());
            to_hash.insert(to_hash.end(), pkey.begin(), pkey.end());

            if (Hash(to_hash) != hash)
            {
                pwallet->WalletLogPrintf("Error reading wallet database: descriptor unencrypted key CPubKey/CPrivKey corrupt");
                return DBErrors::CORRUPT;
            }

            if (!key.Load(pkey, pubkey, true))
            {
                pwallet->WalletLogPrintf("Error reading wallet database: descriptor unencrypted key CPrivKey corrupt");
                return DBErrors::CORRUPT;
            }
            descriptor_keys.insert(std::make_pair(pubkey.GetID(), key));
        }
        sub_cursor.reset();

        // Get encrypted keys
        prefix.clear();
        prefix << DBKeys::WALLETDESCRIPTORCKEY << id;
        sub_cursor = m_batch->GetPrefixCursor(prefix);
        if (!sub_cursor) {
            pwallet->WalletLogPrintf("Error getting database cursor for descriptor encrypted key\n");
            return DBErrors::CORRUPT;
        }
        std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char>>> descriptor_crypt_keys;
        while (true) {
            bool complete;
            bool ret = sub_cursor->Next(ssKey, ssValue, complete);
            if (complete) {
                break;
            } else if (!ret) {
                pwallet->WalletLogPrintf("Error reading next descriptor encrypted key record for wallet database\n");
                return DBErrors::CORRUPT;
            }
            std::string type;
            ssKey >> type;
            assert(type == DBKeys::WALLETDESCRIPTORCKEY);
            uint256 desc_id;
            CPubKey pubkey;
            ssKey >> desc_id;
            assert(desc_id == id);
            ssKey >> pubkey;
            if (!pubkey.IsValid())
            {
                pwallet->WalletLogPrintf("Error reading wallet database: descriptor encrypted key CPubKey corrupt");
                return DBErrors::CORRUPT;
            }
            std::vector<unsigned char> privkey;
            ssValue >> privkey;
            num_ckeys++;

            descriptor_crypt_keys.insert(std::make_pair(pubkey.GetID(), std::make_pair(pubkey, privkey)));
        }
        sub_cursor.reset();

        // Set the descriptor keys
        for (auto desc_key_pair : descriptor_keys) {
            spk_man->AddKey(desc_key_pair.first, desc_key_pair.second);
        }
        for (auto desc_key_pair : descriptor_crypt_keys) {
            spk_man->AddCryptedKey(desc_key_pair.first, desc_key_pair.second.first, desc_key_pair.second.second);
        }
    }
    cursor.reset();

    pwallet->WalletLogPrintf("Descriptors: %u, Descriptor Keys: %u plaintext, %u encrypted, %u total.\n",
           num_descs, num_keys, num_ckeys, num_keys + num_ckeys);

    return result;
}

DBErrors WalletBatch::LoadAddressBookRecords(CWallet* pwallet)
{
    DBErrors result = DBErrors::LOAD_OK;
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);

    // Load name record
    std::unique_ptr<DatabaseCursor> cursor = GetTypeCursor(DBKeys::NAME);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for address book names\n");
        return DBErrors::CORRUPT;
    }

    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next address book name record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::NAME);
        std::string strAddress;
        ssKey >> strAddress;
        std::string label;
        ssValue >> label;
        pwallet->m_address_book[DecodeDestination(strAddress)].SetLabel(label);
    }
    cursor.reset();

    // Load purpose record
    cursor = GetTypeCursor(DBKeys::PURPOSE);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for address book purpose\n");
        return DBErrors::CORRUPT;
    }

    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next address book purpose record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::PURPOSE);
        std::string strAddress;
        ssKey >> strAddress;
        ssValue >> pwallet->m_address_book[DecodeDestination(strAddress)].purpose;
    }
    cursor.reset();

    // Load destination data record
    cursor = GetTypeCursor(DBKeys::DESTDATA);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for address book destdata\n");
        return DBErrors::CORRUPT;
    }

    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next address book destdata record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::PURPOSE);
        std::string strAddress, strKey, strValue;
        ssKey >> strAddress;
        ssKey >> strKey;
        ssValue >> strValue;
        pwallet->LoadDestData(DecodeDestination(strAddress), strKey, strValue);
    }
    cursor.reset();

    return result;
}

DBErrors WalletBatch::LoadTxRecords(CWallet* pwallet, std::vector<uint256> upgraded_txs, bool& any_unordered)
{
    DBErrors result = DBErrors::LOAD_OK;
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);

    // Load tx record
    std::unique_ptr<DatabaseCursor> cursor = GetTypeCursor(DBKeys::TX);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for address book names\n");
        return DBErrors::CORRUPT;
    }

    bool corrupted_tx = false;
    any_unordered = false;
    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next address book name record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::TX);
        uint256 hash;
        ssKey >> hash;
        // LoadToWallet call below creates a new CWalletTx that fill_wtx
        // callback fills with transaction metadata.
        auto fill_wtx = [&](CWalletTx& wtx, bool new_tx) {
            if(!new_tx) {
                // There's some corruption here since the tx we just tried to load was already in the wallet.
                // We don't consider this type of corruption critical, and can fix it by removing tx data and
                // rescanning.
                pwallet->WalletLogPrintf("Error: Corrupt transaction found. This can be fixed by removing transactions from wallet and rescanning.\n");
                result = DBErrors::CORRUPT;
                return false;
            }
            ssValue >> wtx;
            if (wtx.GetHash() != hash)
                return false;

            // Undo serialize changes in 31600
            if (31404 <= wtx.fTimeReceivedIsTxTime && wtx.fTimeReceivedIsTxTime <= 31703)
            {
                if (!ssValue.empty())
                {
                    uint8_t fTmp;
                    uint8_t fUnused;
                    std::string unused_string;
                    ssValue >> fTmp >> fUnused >> unused_string;
                    pwallet->WalletLogPrintf("LoadWallet() upgrading tx ver=%d %d %s",
                                       wtx.fTimeReceivedIsTxTime, fTmp, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = fTmp;
                }
                else
                {
                    pwallet->WalletLogPrintf("LoadWallet() repairing tx ver=%d %s", wtx.fTimeReceivedIsTxTime, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = 0;
                }
                upgraded_txs.push_back(hash);
            }

            if (wtx.nOrderPos == -1)
                any_unordered = true;

            return true;
        };
        if (!pwallet->LoadToWallet(hash, fill_wtx)) {
            if (corrupted_tx) {
                result = DBErrors::CORRUPT;
            } else {
                result = DBErrors::NEED_RESCAN;
            }
        }
    }
    cursor.reset();

    // Load txout record
    cursor = GetTypeCursor(DBKeys::TXOUT);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for txout records\n");
        return DBErrors::CORRUPT;
    }

    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next txout record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::TXOUT);
        COutPoint outpoint;
        CTxOut txout;
        ssKey >> outpoint;
        ssValue >> txout;
        pwallet->m_txos.emplace(outpoint, txout);
    }
    cursor.reset();
    // Load locked utxo record
    cursor = GetTypeCursor(DBKeys::LOCKED_UTXO);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for address book names\n");
        return DBErrors::CORRUPT;
    }

    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next address book name record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::LOCKED_UTXO);
        uint256 hash;
        uint32_t n;
        ssKey >> hash;
        ssKey >> n;
        pwallet->LockCoin(COutPoint(hash, n));
    }
    cursor.reset();

    // Load orderposnext record
    m_batch->Read(DBKeys::ORDERPOSNEXT, pwallet->nOrderPosNext);

    return result;
}

DBErrors WalletBatch::LoadActiveSPKMs(CWallet* pwallet)
{
    DBErrors result = DBErrors::LOAD_OK;
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);

    // Load spk records
    std::set<std::pair<OutputType, bool>> seen_spks;
    for (auto& spk_key : {DBKeys::ACTIVEEXTERNALSPK, DBKeys::ACTIVEINTERNALSPK}) {
        std::unique_ptr<DatabaseCursor> cursor = GetTypeCursor(spk_key);
        if (!cursor) {
            pwallet->WalletLogPrintf("Error getting database cursor for active spkm\n");
            return DBErrors::CORRUPT;
        }

        while (true) {
            bool complete;
            bool ret = cursor->Next(ssKey, ssValue, complete);
            if (complete) {
                break;
            } else if (!ret) {
                pwallet->WalletLogPrintf("Error reading next active spkm record for wallet database\n");
                return DBErrors::CORRUPT;
            }
            std::string type;
            ssKey >> type;
            assert(type == spk_key);
            uint8_t output_type;
            ssKey >> output_type;
            uint256 id;
            ssValue >> id;

            bool internal = type == DBKeys::ACTIVEINTERNALSPK;
            auto [it, insert] = seen_spks.emplace(static_cast<OutputType>(output_type), internal);
            if (!insert) {
                pwallet->WalletLogPrintf("Multiple ScriptpubKeyMans specified for a single type");
                return DBErrors::CORRUPT;
            }
            pwallet->LoadActiveScriptPubKeyMan(id, static_cast<OutputType>(output_type), /*internal=*/internal);
        }
        cursor.reset();
    }
    return result;
}

DBErrors WalletBatch::LoadDecryptionKeys(CWallet* pwallet)
{
    DBErrors result = DBErrors::LOAD_OK;
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    CDataStream ssValue(SER_DISK, CLIENT_VERSION);

    // Load decryption key (mkey) records
    std::unique_ptr<DatabaseCursor> cursor = GetTypeCursor(DBKeys::MASTER_KEY);
    if (!cursor) {
        pwallet->WalletLogPrintf("Error getting database cursor for decryption keys\n");
        return DBErrors::CORRUPT;
    }

    while (true) {
        bool complete;
        bool ret = cursor->Next(ssKey, ssValue, complete);
        if (complete) {
            break;
        } else if (!ret) {
            pwallet->WalletLogPrintf("Error reading next decryption key record for wallet database\n");
            return DBErrors::CORRUPT;
        }
        std::string type;
        ssKey >> type;
        assert(type == DBKeys::MASTER_KEY);
        std::string err;
        if (!LoadEncryptionKey(pwallet, ssKey, ssValue, err)) {
            pwallet->WalletLogPrintf("%s\n", err);
            return DBErrors::CORRUPT;
        }
    }
    cursor.reset();
    return result;
}

DBErrors WalletBatch::LoadWallet(CWallet* pwallet)
{
    DBErrors result = DBErrors::LOAD_OK;
    int last_client = CLIENT_VERSION;
    bool any_unordered = false;
    std::vector<uint256> upgraded_txs;

    LOCK(pwallet->cs_wallet);
    try {
        if ((result = LoadMinVersion(pwallet)) != DBErrors::LOAD_OK) return result;

        // Load wallet flags, so they are known when processing other records.
        // The FLAGS key is absent during wallet creation.
        if ((result = LoadWalletFlags(pwallet)) != DBErrors::LOAD_OK) return result;

#ifndef ENABLE_EXTERNAL_SIGNER
        if (pwallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER)) {
            pwallet->WalletLogPrintf("Error: External signer wallet being loaded without external signer support compiled\n");
            return DBErrors::EXTERNAL_SIGNER_SUPPORT_REQUIRED;
        }
#endif

        // Last client version to open this wallet, was previously the file version number
        m_batch->Read(DBKeys::VERSION, last_client);

        // Load wallet version
        int wallet_version = pwallet->GetVersion();
        pwallet->WalletLogPrintf("Wallet File Version = %d\n", wallet_version);

        // Load legacy wallet keys
        result = LoadLegacyWalletRecords(pwallet, last_client);

        // Load descriptors
        result = std::max(LoadDescriptorWalletRecords(pwallet), result);

        // Load address book
        result = std::max(LoadAddressBookRecords(pwallet), result);

        // Load tx records
        result = std::max(LoadTxRecords(pwallet, upgraded_txs, any_unordered), result);

        // Load SPKMs
        result = std::max(LoadActiveSPKMs(pwallet), result);

        // Load decryption keys
        result = std::max(LoadDecryptionKeys(pwallet), result);
    } catch (...) {
        result = DBErrors::CORRUPT;
    }

    // Any wallet corruption at all: skip any rewriting or
    // upgrading, we don't want to make it worse.
    if (result != DBErrors::LOAD_OK)
        return result;

    for (const uint256& hash : upgraded_txs)
        WriteTx(pwallet->mapWallet.at(hash));

    if (last_client < CLIENT_VERSION) // Update
        m_batch->Write(DBKeys::VERSION, CLIENT_VERSION);

    if (any_unordered)
        result = pwallet->ReorderTransactions();

    // Upgrade all of the wallet keymetadata to have the hd master key id
    // This operation is not atomic, but if it fails, updated entries are still backwards compatible with older software
    try {
        pwallet->UpgradeKeyMetadata();
    } catch (...) {
        return DBErrors::CORRUPT;
    }

    // Upgrade all of the descriptor caches to cache the last hardened xpub
    // This operation is not atomic, but if it fails, only new entries are added so it is backwards compatible
    try {
        pwallet->UpgradeDescriptorCache();
    } catch (...) {
        result = DBErrors::CORRUPT;
    }

    return result;
}

DBErrors WalletBatch::FindWalletTx(std::vector<uint256>& vTxHash, std::list<CWalletTx>& vWtx)
{
    DBErrors result = DBErrors::LOAD_OK;

    try {
        int nMinVersion = 0;
        if (m_batch->Read(DBKeys::MINVERSION, nMinVersion)) {
            if (nMinVersion > FEATURE_LATEST)
                return DBErrors::TOO_NEW;
        }

        // Get cursor
        std::unique_ptr<DatabaseCursor> cursor = m_batch->GetCursor();
        if (!cursor)
        {
            LogPrintf("Error getting wallet database cursor\n");
            return DBErrors::CORRUPT;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            bool complete;
            bool ret = cursor->Next(ssKey, ssValue, complete);
            if (complete) {
                break;
            } else if (!ret) {
                cursor.reset();
                LogPrintf("Error reading next record from wallet database\n");
                return DBErrors::CORRUPT;
            }

            std::string strType;
            ssKey >> strType;
            if (strType == DBKeys::TX) {
                uint256 hash;
                ssKey >> hash;
                vTxHash.push_back(hash);
                vWtx.emplace_back(/*tx=*/nullptr, TxStateInactive{});
                ssValue >> vWtx.back();
            }
        }
    } catch (...) {
        result = DBErrors::CORRUPT;
    }

    return result;
}

DBErrors WalletBatch::ZapSelectTx(std::vector<uint256>& vTxHashIn, std::vector<uint256>& vTxHashOut)
{
    // build list of wallet TXs and hashes
    std::vector<uint256> vTxHash;
    std::list<CWalletTx> vWtx;
    DBErrors err = FindWalletTx(vTxHash, vWtx);
    if (err != DBErrors::LOAD_OK) {
        return err;
    }

    std::sort(vTxHash.begin(), vTxHash.end());
    std::sort(vTxHashIn.begin(), vTxHashIn.end());

    // erase each matching wallet TX
    bool delerror = false;
    std::vector<uint256>::iterator it = vTxHashIn.begin();
    for (const uint256& hash : vTxHash) {
        while (it < vTxHashIn.end() && (*it) < hash) {
            it++;
        }
        if (it == vTxHashIn.end()) {
            break;
        }
        else if ((*it) == hash) {
            if(!EraseTx(hash)) {
                LogPrint(BCLog::WALLETDB, "Transaction was found for deletion but returned database error: %s\n", hash.GetHex());
                delerror = true;
            }
            vTxHashOut.push_back(hash);
        }
    }

    if (delerror) {
        return DBErrors::CORRUPT;
    }
    return DBErrors::LOAD_OK;
}

void MaybeCompactWalletDB(WalletContext& context)
{
    static std::atomic<bool> fOneThread(false);
    if (fOneThread.exchange(true)) {
        return;
    }

    for (const std::shared_ptr<CWallet>& pwallet : GetWallets(context)) {
        WalletDatabase& dbh = pwallet->GetDatabase();

        unsigned int nUpdateCounter = dbh.nUpdateCounter;

        if (dbh.nLastSeen != nUpdateCounter) {
            dbh.nLastSeen = nUpdateCounter;
            dbh.nLastWalletUpdate = GetTime();
        }

        if (dbh.nLastFlushed != nUpdateCounter && GetTime() - dbh.nLastWalletUpdate >= 2) {
            if (dbh.PeriodicFlush()) {
                dbh.nLastFlushed = nUpdateCounter;
            }
        }
    }

    fOneThread = false;
}

bool WalletBatch::WriteDestData(const std::string &address, const std::string &key, const std::string &value)
{
    return WriteIC(std::make_pair(DBKeys::DESTDATA, std::make_pair(address, key)), value);
}

bool WalletBatch::EraseDestData(const std::string &address, const std::string &key)
{
    return EraseIC(std::make_pair(DBKeys::DESTDATA, std::make_pair(address, key)));
}


bool WalletBatch::WriteHDChain(const CHDChain& chain)
{
    return WriteIC(DBKeys::HDCHAIN, chain);
}

bool WalletBatch::WriteWalletFlags(const uint64_t flags)
{
    return WriteIC(DBKeys::FLAGS, flags);
}

bool WalletBatch::TxnBegin()
{
    return m_batch->TxnBegin();
}

bool WalletBatch::TxnCommit()
{
    return m_batch->TxnCommit();
}

bool WalletBatch::TxnAbort()
{
    return m_batch->TxnAbort();
}

std::unique_ptr<WalletDatabase> MakeDatabase(const fs::path& path, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error)
{
    bool exists;
    try {
        exists = fs::symlink_status(path).type() != fs::file_type::not_found;
    } catch (const fs::filesystem_error& e) {
        error = Untranslated(strprintf("Failed to access database path '%s': %s", fs::PathToString(path), fsbridge::get_filesystem_error_message(e)));
        status = DatabaseStatus::FAILED_BAD_PATH;
        return nullptr;
    }

    std::optional<DatabaseFormat> format;
    if (exists) {
        if (IsBDBFile(BDBDataFile(path))) {
            format = DatabaseFormat::BERKELEY;
        }
        if (IsSQLiteFile(SQLiteDataFile(path))) {
            if (format) {
                error = Untranslated(strprintf("Failed to load database path '%s'. Data is in ambiguous format.", fs::PathToString(path)));
                status = DatabaseStatus::FAILED_BAD_FORMAT;
                return nullptr;
            }
            format = DatabaseFormat::SQLITE;
        }
    } else if (options.require_existing) {
        error = Untranslated(strprintf("Failed to load database path '%s'. Path does not exist.", fs::PathToString(path)));
        status = DatabaseStatus::FAILED_NOT_FOUND;
        return nullptr;
    }

    if (!format && options.require_existing) {
        error = Untranslated(strprintf("Failed to load database path '%s'. Data is not in recognized format.", fs::PathToString(path)));
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        return nullptr;
    }

    if (format && options.require_create) {
        error = Untranslated(strprintf("Failed to create database path '%s'. Database already exists.", fs::PathToString(path)));
        status = DatabaseStatus::FAILED_ALREADY_EXISTS;
        return nullptr;
    }

    // A db already exists so format is set, but options also specifies the format, so make sure they agree
    if (format && options.require_format && format != options.require_format) {
        error = Untranslated(strprintf("Failed to load database path '%s'. Data is not in required format.", fs::PathToString(path)));
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        return nullptr;
    }

    // Format is not set when a db doesn't already exist, so use the format specified by the options if it is set.
    if (!format && options.require_format) format = options.require_format;

    // If the format is not specified or detected, choose the default format based on what is available. We prefer BDB over SQLite for now.
    if (!format) {
#ifdef USE_SQLITE
        format = DatabaseFormat::SQLITE;
#endif
#ifdef USE_BDB
        format = DatabaseFormat::BERKELEY;
#endif
    }

    if (format == DatabaseFormat::SQLITE) {
#ifdef USE_SQLITE
        return MakeSQLiteDatabase(path, options, status, error);
#endif
        error = Untranslated(strprintf("Failed to open database path '%s'. Build does not support SQLite database format.", fs::PathToString(path)));
        status = DatabaseStatus::FAILED_BAD_FORMAT;
        return nullptr;
    }

#ifdef USE_BDB
    return MakeBerkeleyDatabase(path, options, status, error);
#endif
    error = Untranslated(strprintf("Failed to open database path '%s'. Build does not support Berkeley DB database format.", fs::PathToString(path)));
    status = DatabaseStatus::FAILED_BAD_FORMAT;
    return nullptr;
}

/** Return object for accessing dummy database with no read/write capabilities. */
std::unique_ptr<WalletDatabase> CreateDummyWalletDatabase()
{
    return std::make_unique<DummyDatabase>();
}

/** Return object for accessing temporary in-memory database. */
std::unique_ptr<WalletDatabase> CreateMockWalletDatabase()
{
    DatabaseOptions options;
#ifdef USE_SQLITE
    return std::make_unique<SQLiteDatabase>("", "", options, true);
#elif USE_BDB
    return std::make_unique<BerkeleyDatabase>(std::make_shared<BerkeleyEnvironment>(), "", options);
#endif
}
} // namespace wallet
