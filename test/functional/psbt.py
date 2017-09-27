#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the Partially Signed Transaction RPCs.

Test the following RPCs:
   - walletcreatepsbt
   - walletupdatepsbt
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

# Create one-input, one-output, no-fee transaction:
class PSBTTest(BitcoinTestFramework):

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3

    def run_test(self):

        # Get some money and activate segwit
        self.nodes[0].generate(500)

        # Create and fund a raw tx for sending 10 BTC
        rawtx = self.nodes[0].createrawtransaction([], {self.nodes[1].getnewaddress():10})
        rawtx = self.nodes[0].fundrawtransaction(rawtx)['hex']

        # Node 1 should not be able to sign it but still return the psbtx same as before
        psbtx1 = self.nodes[0].walletcreatepsbt(rawtx)
        psbtx = self.nodes[1].walletupdatepsbt(psbtx1)['hex']
        assert_equal(psbtx1, psbtx)

        # Sign the transaction and send
        signed_tx = self.nodes[0].walletupdatepsbt(psbtx)['hex']
        self.nodes[0].sendrawtransaction(signed_tx)

        # Create p2sh, p2wpkh, and p2wsh addresses
        pubkey0 = self.nodes[0].validateaddress(self.nodes[0].getnewaddress())['pubkey']
        pubkey1 = self.nodes[1].validateaddress(self.nodes[1].getnewaddress())['pubkey']
        pubkey2 = self.nodes[2].validateaddress(self.nodes[2].getnewaddress())['pubkey']
        p2sh = self.nodes[1].addmultisigaddress(2, [pubkey0, pubkey1, pubkey2])
        p2wsh = self.nodes[1].addwitnessaddress(p2sh)
        p2wpkh = self.nodes[1].addwitnessaddress(self.nodes[1].getnewaddress())

        # fund those addresses
        rawtx = self.nodes[0].createrawtransaction([], {p2sh:10, p2wsh:10, p2wpkh:10})
        rawtx = self.nodes[0].fundrawtransaction(rawtx, {"changePosition":3})
        signed_tx = self.nodes[0].signrawtransaction(rawtx['hex'])['hex']
        txid = self.nodes[0].sendrawtransaction(signed_tx)
        self.nodes[0].generate(6)
        self.sync_all()

        # Find the output pos
        p2sh_pos = -1
        p2wsh_pos = -1
        p2wpkh_pos = -1
        decoded = self.nodes[0].decoderawtransaction(signed_tx)
        for out in decoded['vout']:
            if out['scriptPubKey']['addresses'][0] == p2sh:
                p2sh_pos = out['n']
            elif out['scriptPubKey']['addresses'][0] == p2wsh:
                p2wsh_pos = out['n']
            elif out['scriptPubKey']['addresses'][0] == p2wpkh:
                p2wpkh_pos = out['n']

        # spend p2wpkh from node 1
        rawtx = self.nodes[1].createrawtransaction([{"txid":txid,"vout":p2wpkh_pos}], {self.nodes[1].getnewaddress():9.99})
        psbtx = self.nodes[1].walletcreatepsbt(rawtx)
        walletupdatepsbt_out = self.nodes[1].walletupdatepsbt(psbtx)
        assert_equal(walletupdatepsbt_out['complete'], True)
        self.nodes[1].sendrawtransaction(walletupdatepsbt_out['hex'])

        # partially sign p2sh and p2wsh with node 1
        rawtx = self.nodes[1].createrawtransaction([{"txid":txid,"vout":p2wsh_pos},{"txid":txid,"vout":p2sh_pos}], {self.nodes[1].getnewaddress():19.99})
        psbtx = self.nodes[1].walletcreatepsbt(rawtx)
        walletupdatepsbt_out = self.nodes[1].walletupdatepsbt(psbtx)
        psbtx = walletupdatepsbt_out['hex']
        assert_equal(walletupdatepsbt_out['complete'], False)

        # partially sign with node 2. This should be complete and sendable
        walletupdatepsbt_out = self.nodes[2].walletupdatepsbt(psbtx)
        assert_equal(walletupdatepsbt_out['complete'], True)
        self.nodes[2].sendrawtransaction(walletupdatepsbt_out['hex'])

        # check that walletupdatepsbt fails to decode a non-psbt
        assert_raises_rpc_error(-22, "TX decode failed", self.nodes[1].walletupdatepsbt, rawtx)

        # check that walletcreatepsbt fails to decode a psbt
        walletupdatepsbt_out = self.nodes[2].walletupdatepsbt(psbtx, "ALL", True)
        psbtx = walletupdatepsbt_out['hex']
        assert_raises_rpc_error(-22, "TX decode failed", self.nodes[1].walletcreatepsbt, psbtx)

        # Check that unknown values are just passed through
        unknown_psbt = "70736274ff0a080102030405060708090f0102030405060708090a0b0c0d0e0f00"
        unknown_out = self.nodes[0].walletupdatepsbt(unknown_psbt, "ALL", True)['hex']
        assert_equal(unknown_psbt, unknown_out)

if __name__ == '__main__':
    PSBTTest().main()
