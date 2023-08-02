#!/usr/bin/env python3

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


class SilentPaymentsReceivingTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, legacy=False)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_sqlite()

    def test_createwallet(self):
        self.log.info("Check createwallet silent payments option")

        self.nodes[0].createwallet(wallet_name="sp", silent_payment=True)
        wallet = self.nodes[0].get_wallet_rpc("sp")
        addr = wallet.getnewaddress(address_type="silent-payment")
        assert addr.startswith("sp")
        addr_again = wallet.getnewaddress(address_type="silent-payment")
        assert_equal(addr, addr_again)

        self.nodes[0].createwallet(wallet_name="non_sp", silent_payment=False)
        wallet = self.nodes[0].get_wallet_rpc("non_sp")
        assert_raises_rpc_error(-12, "Error: No silent-payment addresses available", wallet.getnewaddress, address_type="silent-payment")

        if self.is_bdb_compiled():
            assert_raises_rpc_error(-4, "Wallet with silent payments must also be a descriptor wallet", self.nodes[0].createwallet, wallet_name="legacy_sp", descriptors=False, silent_payment=True)

            self.nodes[0].createwallet(wallet_name="legacy_sp", descriptors=False)
            wallet = self.nodes[0].get_wallet_rpc("legacy_sp")
            assert_raises_rpc_error(-12, "Error: No silent-payment addresses available", wallet.getnewaddress, address_type="silent-payment")

    def run_test(self):
        self.test_createwallet()


if __name__ == '__main__':
    SilentPaymentsReceivingTest().main()
