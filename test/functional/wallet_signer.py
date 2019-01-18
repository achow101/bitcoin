#!/usr/bin/env python3
# Copyright (c) 2017-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test external signer.

Verify that a bitcoind node can use an external signer command
"""
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class SignerTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        mock_signer_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mocks/signer.py')
        self.extra_args = [
            [],
            ['-signer="%s"' % mock_signer_path , '-addresstype=bech32', '-keypool=10'],
            ['-signer="%s"' % mock_signer_path, '-addresstype=p2sh-segwit', '-keypool=10'],
            ['-signer="%s"' % mock_signer_path, '-addresstype=legacy', '-keypool=10']
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        mock_signer_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mocks/signer.py')
        self.log.info('-signer="%s"' % mock_signer_path)
        assert_equal(self.nodes[0].getbalance(), 1250)
        assert_equal(self.nodes[1].getbalance(), 1250)
        assert_raises_rpc_error(-4, 'Error: restart bitcoind with -signer=<cmd>',
            self.nodes[0].enumeratesigners
        )
        result = self.nodes[1].enumeratesigners()
        assert_equal(len(result['signers']), 3)

        # Create new wallets with private keys disabled:
        self.nodes[1].createwallet('hww1', True)
        hww1 = self.nodes[1].get_wallet_rpc('hww1')
        self.nodes[2].createwallet('hww2', True)
        hww2 = self.nodes[2].get_wallet_rpc('hww2')
        self.nodes[3].createwallet('hww3', True)
        hww3 = self.nodes[3].get_wallet_rpc('hww3')

        hww1.enumeratesigners()
        hww2.enumeratesigners()
        # Delay enumerate on third wallet to test error handling
        # hww3.enumeratesigners()

        self.log.info('Test signerfetchkeys with bech32, p2sh-segwit and legacy')

        result = hww1.signerfetchkeys("00000001")
        assert_equal(result, [{'success': True}, {'success': True}])
        assert_equal(hww1.getwalletinfo()["keypoolsize"], 10)

        address1 = hww1.getnewaddress()
        assert_equal(address1, "bcrt1qm90ugl4d48jv8n6e5t9ln6t9zlpm5th68x4f8g")
        address_info = hww1.getaddressinfo(address1)
        assert_equal(address_info['solvable'], True)
        assert_equal(address_info['ismine'], False)
        assert_equal(address_info['hdkeypath'], "m/84'/1'/0'/0/0")

        assert_raises_rpc_error(-4, "First call enumeratesigners", hww3.signerfetchkeys)
        hww3.enumeratesigners()

        result = hww2.signerfetchkeys("00000001")
        assert_equal(result, [{'success': True}, {'success': True}])
        assert_equal(hww2.getwalletinfo()["keypoolsize"], 10)

        address2 = hww2.getnewaddress()
        assert_equal(address2, "2N2gQKzjUe47gM8p1JZxaAkTcoHPXV6YyVp")
        address_info = hww2.getaddressinfo(address2)
        assert_equal(address_info['solvable'], True)
        assert_equal(address_info['ismine'], False)
        assert_equal(address_info['hdkeypath'], "m/49'/1'/0'/0/0")

        assert_raises_rpc_error(-4, "Multiple signers found, please specify which to use", hww3.signerfetchkeys)
        hww3.signerdissociate("00000002")
        hww3.signerdissociate("d95fc47e")
        hww3.signerfetchkeys()

        assert_equal(result, [{'success': True}, {'success': True}])
        assert_equal(hww3.getwalletinfo()["keypoolsize"], 10)

        address3 = hww3.getnewaddress("00000001")
        assert_equal(address3, "n1LKejAadN6hg2FrBXoU1KrwX4uK16mco9")
        address_info = hww3.getaddressinfo(address3)
        assert_equal(address_info['solvable'], True)
        assert_equal(address_info['ismine'], False)
        assert_equal(address_info['hdkeypath'], "m/44'/1'/0'/0/0")

        self.log.info('Test signerdisplayaddress')
        hww1.signerdisplayaddress(address1, "00000001")
        hww3.signerdisplayaddress(address3)

        self.log.info('Test sign PSBT')
        self.nodes[0].sendtoaddress(address1, 1)
        self.nodes[0].generate(1)
        self.sync_all()

        # Load private key into wallet to generate a signed PSBT for the mock
        # self.nodes[1].createwallet("mock")
        # mock_wallet = self.nodes[1].get_wallet_rpc("mock")
        # TODO: we need support for creating an empty wallet and then importing private keys, following won't work:
        # mock_wallet.importmulti([{
        #     "desc": "wpkh([00000000/84h/1h/0h]tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0/0)",
        #     "timestamp": 0,
        #     "keypool": True
        # }])
        # print(mock_wallet.getaddressinfo(address1))
        # mock_psbt = mock_wallet.walletcreatefundedpsbt([], {self.nodes[0].getnewaddress():0.5}, 0, {"includeWatching": True}, True)['psbt']
        # mock_psbt_signed = mock_wallet.walletprocesspsbt(psbt=mock_psbt, bip32derivs=True)
        # print(mock_psbt_signed)

        psbt_orig = hww1.walletcreatefundedpsbt([], {self.nodes[0].getnewaddress():0.5}, 0, {"includeWatching": True}, True)['psbt']
        psbt_processed = hww1.signerprocesspsbt(psbt_orig, "00000001")
        assert_equal(psbt_processed['complete'], False) # TODO: should be true with a proper test PSBT

        self.log.info('Test signersend')
        dest = self.nodes[0].getnewaddress()
        res = hww1.signersend([], {dest:0.5}, 0, None, "00000001")
        # TODO once we have a proper test PSBT, complete should be true and then transaction should be broadcast:
        assert_equal(res['complete'], False)

        # self.nodes[0].generate(1)
        # self.sync_all()
        # assert_equal(self.nodes[0].getreceivedbyaddress(dest), 0.5)

        hww1.signerdissociate("00000002")
        hww1.signerdissociate("d95fc47e")
        hww1.signersend([], {dest:0.01}, 0, None)

if __name__ == '__main__':
    SignerTest().main()
