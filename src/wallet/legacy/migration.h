#ifndef BITCOIN_WALLET_LEGACY_MIGRATION_H
#define BITCOIN_WALLET_LEGACY_MIGRATION_H

#include <wallet/wallet.h>

namespace wallet {
namespace legacy_migration {

class LegacyWallet : public CWallet
{
public:
    LegacyWallet(const std::string& name, std::unique_ptr<WalletDatabase> database) : CWallet::CWallet(/*chain=*/nullptr, name, std::move(database)) {}
};

struct MigrationResult {
    std::string wallet_name;
    std::optional<std::string> watchonly_wallet_name;
    std::optional<std::string> solvables_wallet_name;
    std::shared_ptr<CWallet> wallet;
    std::shared_ptr<CWallet> watchonly_wallet;
    std::shared_ptr<CWallet> solvables_wallet;
    fs::path backup_path;
};

//! Do all steps to migrate a legacy wallet to a descriptor wallet
[[nodiscard]] util::Result<MigrationResult> MigrateLegacyToDescriptor(const std::string& wallet_name, const SecureString& passphrase, WalletContext& context, bool load_wallet = true);
//! Requirement: The wallet provided to this function must be isolated, with no attachment to the node's context.
[[nodiscard]] util::Result<MigrationResult> MigrateLegacyToDescriptor(std::shared_ptr<CWallet> local_wallet, const SecureString& passphrase, WalletContext& context, bool load_wallet = true);

} // namespace legacy_migration
} // namespace wallet

#endif // BITCOIN_WALLET_LEGACY_MIGRATION_H
