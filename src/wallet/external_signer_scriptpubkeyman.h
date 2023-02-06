// Copyright (c) 2019-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_EXTERNAL_SIGNER_SCRIPTPUBKEYMAN_H
#define BITCOIN_WALLET_EXTERNAL_SIGNER_SCRIPTPUBKEYMAN_H

#include <wallet/scriptpubkeyman.h>

#include <memory>

namespace wallet {
class ExternalSignerScriptPubKeyMan : public DescriptorScriptPubKeyMan
{
  public:
  ExternalSignerScriptPubKeyMan(WalletStorage& storage, std::function<void(const std::set<CScript>&, ScriptPubKeyMan*)> topup_callback, WalletDescriptor& descriptor, int64_t keypool_size)
      :   DescriptorScriptPubKeyMan(storage, topup_callback, descriptor, keypool_size)
      {}
  ExternalSignerScriptPubKeyMan(WalletStorage& storage, std::function<void(const std::set<CScript>&, ScriptPubKeyMan*)> topup_callback, int64_t keypool_size)
      :   DescriptorScriptPubKeyMan(storage, topup_callback, keypool_size)
      {}

  /** Provide a descriptor at setup time
  * Returns false if already setup or setup fails, true if setup is successful
  */
  bool SetupDescriptor(std::unique_ptr<Descriptor>desc);

  static ExternalSigner GetExternalSigner();

  bool DisplayAddress(const CScript scriptPubKey, const ExternalSigner &signer) const;

  TransactionError FillPSBT(PartiallySignedTransaction& psbt, const PrecomputedTransactionData& txdata, int sighash_type = 1 /* SIGHASH_ALL */, bool sign = true, bool bip32derivs = false, int* n_signed = nullptr, bool finalize = true) const override;
};
} // namespace wallet
#endif // BITCOIN_WALLET_EXTERNAL_SIGNER_SCRIPTPUBKEYMAN_H
