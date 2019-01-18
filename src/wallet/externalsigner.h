// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_EXTERNALSIGNER_H
#define BITCOIN_WALLET_EXTERNALSIGNER_H

#include <stdexcept>
#include <string>
#include <univalue.h>

class ExternalSignerException : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class ExternalSigner
{
private:
    std::string m_command;

public:
    ExternalSigner(const std::string& command, const std::string& fingerprint, bool mainnet);

    std::string m_fingerprint;
    bool m_mainnet;

    friend inline bool operator==( const ExternalSigner &a, const ExternalSigner &b )
    {
         return a.m_fingerprint == b.m_fingerprint;
    }

    static UniValue Enumerate(const std::string& command, std::vector<ExternalSigner>& signers, bool mainnet = true);

    UniValue getKeys(const std::string& descriptor);
};

#endif // BITCOIN_WALLET_EXTERNALSIGNER_H
