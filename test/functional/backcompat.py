#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Backwards compatibility functional test

Test various backwards compatibility scenarios. Requires previous releases binaries,
see test/README.md.

Due to RPC changes introduced in various versions the below tests
won't work for older versions without some patches or workarounds.

Use only the latest patch version of each release, unless a test specifically
needs an older patch version.
"""

import os
import shutil
import pprint
import tempfile
import re

from test_framework.blocktools import create_block, create_coinbase
from test_framework.descriptors import descsum_create
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework

from test_framework.address import (
    script_to_p2sh,
)
from test_framework.script import (
    CScript,
    OP_1,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKLOCKTIMEVERIFY,
)
from test_framework.messages import(
    tx_from_hex,
)
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
    find_vout_for_address,
    rpc_port,
    p2p_port,
)
from test_framework.test_node import TestNode


class BackwardsCompatibilityTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        # Add new version after each release:
        self.wallet_names = [self.default_wallet_name]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_previous_releases()

    def get_bin_from_version(self, version, bin_name):
        if version > 219999:
            # Starting at client version 220000 the first two digits represent
            # the major version, e.g. v22.0 instead of v0.22.0.
            version *= 100
        return os.path.join(
            self.options.previous_releases_path,
            re.sub(
                r'\.0$' if version <= 219999 else r'(\.0){1,2}$',
                '', # Remove trailing dot for point releases, after 22.0 also remove double trailing dot.
                'v{}.{}.{}.{}'.format(
                    (version % 100000000) // 1000000,
                    (version % 1000000) // 10000,
                    (version % 10000) // 100,
                    (version % 100) // 1,
                ),
            ),
            'bin',
            bin_name,
        )

    def connect_nodes(self, from_connection, to_connection):
        from_num_peers = 1 + len(from_connection.getpeerinfo())
        to_num_peers = 1 + len(to_connection.getpeerinfo())
        ip_port = "127.0.0.1:" + str(p2p_port(to_connection.index))
        from_connection.addnode(ip_port, "onetry")
        # poll until version handshake complete to avoid race conditions
        # with transaction relaying
        # See comments in net_processing:
        # * Must have a version message before anything else
        # * Must have a verack message before anything else
        self.wait_until(lambda: sum(peer['version'] != 0 for peer in from_connection.getpeerinfo()) == from_num_peers)
        self.wait_until(lambda: sum(peer['bytesrecv_per_msg'].pop('verack', 0) == 24 for peer in from_connection.getpeerinfo()) == from_num_peers)
        # The message bytes are counted before processing the message, so make
        # sure it was fully processed by waiting for a ping.
        self.wait_until(lambda: sum(peer["bytesrecv_per_msg"].pop("pong", 0) >= 32 for peer in from_connection.getpeerinfo()) == from_num_peers)

    def get_node_version(self, node):
        if node.version_is_at_least(100000):
            return node.getnetworkinfo()["version"]
        else:
            return node.getinfo()["version"]

    def run_test(self):
        VERSIONS = [
            90000,
            90100,
            90200,
            90201,
            90300,
            90500,
            100000,
            100100,
            100200,
            100300,
            100400,
            110000,
            110100,
            110200,
            120000,
            120100,
            130000,
            130100,
            130200,
            140000,
            140100,
            140200,
            140300,
            150000,
            150001,
            150100,
            150200,
            160000,
            160100,
            160200,
            160300,
            170000,
            170001,
            170100,
            180000,
            180100,
            190000,
            190001,
            190100,
            190200,
            200000,
            200100,
            200200,
            210000,
            210100,
            210200,
            220000,
            230000,
            230100,
            230200,
            240000,
            250000,
        ]

        # Activate soft forks for the versions that need it
        self.log.info("Mining")
        cb_spk = bytes.fromhex(self.nodes[0].validateaddress(self.nodes[0].getnewaddress())["scriptPubKey"])
        for _ in range(600):
            template = self.nodes[0].getblocktemplate({"rules": ["segwit"]})
            coinbase = create_coinbase(height=template["height"], script_pubkey=cb_spk)
            block = create_block(version=0x20000002, tmpl=template, coinbase=coinbase)
            while True:
                submit_res = self.nodes[0].submitblock(block.serialize().hex())
                if submit_res != "high-hash":
                    break
                block.nNonce += 1

        # Make addresses for all of the transactions
        p2sh_segwit_addr = self.nodes[0].getnewaddress("", "p2sh-segwit")
        p2wpkh_addr = self.nodes[0].getnewaddress("", "bech32")
        p2tr_addr = self.nodes[0].getnewaddress("", "bech32m")
        der_addr = self.nodes[0].getnewaddress("", "legacy")

        multi_desc = descsum_create("sh(multi(1,tprv8mGPkMVz5mZuJDnC2NjjAv7E9Zqa5LCgX4zawbZu5nzTtLb5kGhPwycX4H1gtW1f5ZdTKTNtQJ61hk71F2TdcQ93EFDTpUcPBr98QRji615))")
        self.nodes[0].importdescriptors([{"desc": multi_desc,"timestamp":"now"}])
        multi_addr = self.nodes[0].deriveaddresses(multi_desc)[0]

        csv_script = CScript([20, OP_CHECKSEQUENCEVERIFY])
        csv_addr = script_to_p2sh(csv_script)

        cltv_script = CScript([610, OP_CHECKLOCKTIMEVERIFY])
        cltv_addr = script_to_p2sh(cltv_script)

        # Fund
        fund_tx = self.nodes[0].send(
            [
                {p2sh_segwit_addr: 5},
                {p2wpkh_addr: 5},
                {p2tr_addr: 5},
                {multi_addr: 5},
                {csv_addr: 5},
                {cltv_addr: 5},
                {der_addr: 5},
            ]
        )

        p2sh_segwit_utxo = {"txid": fund_tx["txid"], "vout": find_vout_for_address(self.nodes[0], fund_tx["txid"], p2sh_segwit_addr)}
        p2wpkh_utxo = {"txid": fund_tx["txid"], "vout": find_vout_for_address(self.nodes[0], fund_tx["txid"], p2wpkh_addr)}
        p2tr_utxo = {"txid": fund_tx["txid"], "vout": find_vout_for_address(self.nodes[0], fund_tx["txid"], p2tr_addr)}
        multi_utxo = {"txid": fund_tx["txid"], "vout": find_vout_for_address(self.nodes[0], fund_tx["txid"], multi_addr)}
        csv_utxo = {"txid": fund_tx["txid"], "vout": find_vout_for_address(self.nodes[0], fund_tx["txid"], csv_addr), "sequence": 20}
        cltv_utxo = {"txid": fund_tx["txid"], "vout": find_vout_for_address(self.nodes[0], fund_tx["txid"], cltv_addr)}
        der_utxo = {"txid": fund_tx["txid"], "vout": find_vout_for_address(self.nodes[0], fund_tx["txid"], der_addr)}

        self.generate(self.nodes[0], 1)

        # Make p2sh-p2wpkh, p2wpkh, and p2tr invalid sig and witness stripped txs
        bad_txs = []
        for t, utxo in [("p2sh-segwit", p2sh_segwit_utxo), ("p2wpkh", p2wpkh_utxo), ("p2tr", p2tr_utxo)]:
            child = self.nodes[0].sendall(recipients=[self.nodes[0].getnewaddress("", "legacy")], add_to_wallet=False, inputs=[utxo])
            bad_tx = tx_from_hex(child["hex"])
            mut_item = bytearray(bad_tx.wit.vtxinwit[0].scriptWitness.stack[0])
            mut_item[10] += 1
            bad_tx.wit.vtxinwit[0].scriptWitness.stack[0] = bytes(mut_item)
            bad_tx.nVersion = 1

            bad_txs.append((t, bad_tx.serialize_with_witness().hex()))
            bad_txs.append((t + " witness stripped", bad_tx.serialize_without_witness().hex()))

        # Make multi non-null dummy tx
        multi_child = self.nodes[0].sendall(recipients=[self.nodes[0].getnewaddress("", "legacy")], add_to_wallet=False, inputs=[multi_utxo])
        bad_multi_tx = tx_from_hex(multi_child["hex"])
        mut_item = bytearray(bad_multi_tx.vin[0].scriptSig)
        mut_item[0] = OP_1
        bad_multi_tx.vin[0].scriptSig = bytes(mut_item)
        bad_multi_tx.nVersion = 1
        bad_txs.append(("nulldummy", bad_multi_tx.serialize().hex()))

        # make csv spend
        csv_child = tx_from_hex(self.nodes[0].createrawtransaction([csv_utxo], {self.nodes[0].getnewaddress("", "legacy"): 4.9999}))
        csv_child.vin[0].scriptSig = CScript([csv_script])
        bad_txs.append(("csv", csv_child.serialize().hex()))

        # make cltv spend
        cltv_child = tx_from_hex(self.nodes[0].createrawtransaction([cltv_utxo], {self.nodes[0].getnewaddress("", "legacy"): 4.9999}, 610))
        cltv_child.vin[0].scriptSig = CScript([cltv_script])
        cltv_child.nVersion = 1
        bad_txs.append(("cltv", cltv_child.serialize().hex()))

        # make non-canonical der sig
        der_child = tx_from_hex(self.nodes[0].sendall(recipients=[self.nodes[0].getnewaddress("", "legacy")], add_to_wallet=False, inputs=[der_utxo])["hex"])
        der_mut = bytearray(der_child.vin[0].scriptSig)
        der_mut[0] += 1
        der_mut[2] += 1
        der_mut[4] += 1
        der_mut.insert(5, 0)
        der_child.vin[0].scriptSig = bytes(der_mut)
        bad_txs.append(("der", der_child.serialize().hex()))

        # Check we reject
        for t, tx in bad_txs:
            assert_raises_rpc_error(-26, "", self.nodes[0].sendrawtransaction, tx)

        # Check previous versions reject
        for ver in VERSIONS:
            self.log.info(f"Starting {ver}")
            datadir=os.path.join(self.options.tmpdir, f"node_{ver}")
            os.mkdir(datadir)
            os.mkdir(os.path.join(datadir, "stderr"))
            os.mkdir(os.path.join(datadir, "stdout"))
            extra_conf = []
            if ver >= 130000 and ver < 160000:
                # Set segwit and csv params so that they activate
                extra_conf = ["vbparams=csv:0:9999999999", "vbparams=segwit:0:9999999999", "bip9params=csv:0:9999999999", "bip9params=segwit:0:9999999999"]
            node = TestNode(
                i=1,
                datadir=datadir,
                chain=self.chain,
                rpchost=None,
                timewait=self.rpc_timeout,
                timeout_factor=self.options.timeout_factor,
                bitcoind=self.get_bin_from_version(ver, "bitcoind"),
                bitcoin_cli=self.get_bin_from_version(ver, "bitcoin-cli"),
                version=ver,
                coverage_dir=self.options.coveragedir,
                cwd=self.options.tmpdir,
                extra_conf=["rpcuser=user", "rpcpassword=pass", "acceptnonstdtxn=0"] + extra_conf,
                extra_args=["-regtest", f"-rpcport={rpc_port(1)}", f"-port={p2p_port(1)}"],
                use_cli=self.options.usecli,
                start_perf=self.options.perf,
                use_valgrind=self.options.valgrind,
                descriptors=self.options.descriptors,
            )
            node.start()
            self.log.info(f"  Waiting for {ver} rpc")
            node.wait_for_rpc_connection()
            assert_equal(self.get_node_version(node), ver)
            self.log.info(f"  Waiting for {ver} connection")
            self.connect_nodes(self.nodes[0], node)
            self.sync_blocks([self.nodes[0], node])
            self.log.info(f"  Testing {ver}")
            for t, tx in bad_txs:
                try:
                    node.sendrawtransaction(tx)
                    #pprint.pprint(self.nodes[0].decoderawtransaction(tx))
                    print(f"FAILED: {t} was accepted")
                except JSONRPCException as e:
                    print(f"Success: {t} was rejected with '{e}'")

            self.log.info(f"  Stopping {ver}")
            node.stop_node(wait_until_stopped=False)

if __name__ == '__main__':
    BackwardsCompatibilityTest().main()
