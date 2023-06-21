#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test running bitcoind with -reindex from a read-only blockstore
- Start two nodes, generate blocks, then restart with -reindex after setting blk files to read-only
"""

import subprocess
import stat
from test_framework.test_framework import BitcoinTestFramework

class BlockstoreReindexTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-fastprune"]]

    def reindex_readonly(self):
        self.log.debug("Generate block big enough to start second block file")
        fastprune_blockfile_size = 0x10000
        opreturn = "6a"
        nulldata = fastprune_blockfile_size * "ff"
        self.generateblock(self.nodes[0], output=f"raw({opreturn}{nulldata})", transactions=[])
        self.stop_node(0)

        assert (self.nodes[0].chain_path / "blocks" / "blk00000.dat").exists()
        assert (self.nodes[0].chain_path / "blocks" / "blk00001.dat").exists()

        self.log.debug("Make the first block file read-only")

        filename = self.nodes[0].chain_path / "blocks" / "blk00000.dat"
        try:
            subprocess.run(['chattr', '+i', filename])
        except Exception as e:
            self.log.warning(f"Can not make file immutable ({e}), trying read-only instead")
            (self.nodes[0].chain_path / "blocks" / "blk00000.dat").chmod(stat.S_IREAD)

        self.log.debug("Attempt to restart and reindex the node with the unwritable block file")
        with self.nodes[0].assert_debug_log(expected_msgs=['FlushStateToDisk', 'failed to open file'], unexpected_msgs=[]):
            self.nodes[0].assert_start_raises_init_error(extra_args=['-reindex', '-fastprune'],
                expected_msg="Error: A fatal internal error occurred, see debug.log for details")


    def run_test(self):
        self.reindex_readonly()

if __name__ == '__main__':
    BlockstoreReindexTest().main()
