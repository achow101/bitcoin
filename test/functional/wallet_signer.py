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
            ['-signer="%s"' % mock_signer_path , '-addresstype=bech32'],
            ['-signer="%s"' % mock_signer_path, '-addresstype=p2sh-segwit'],
            ['-signer="%s"' % mock_signer_path, '-addresstype=legacy']
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        mock_signer_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'mocks/signer.py')
        self.log.info('-signer="%s"' % mock_signer_path)
        assert_equal(self.nodes[0].getbalance(), 1250)
        assert_equal(self.nodes[1].getbalance(), 1250)

if __name__ == '__main__':
    SignerTest().main()
