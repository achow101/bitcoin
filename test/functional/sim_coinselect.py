#! /usr/bin/env python3
from test_framework.authproxy import JSONRPCException
from test_framework.messages import ser_compact_size
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from statistics import mean, stdev
from decimal import Decimal, getcontext

import logging


class CoinSelectionSimulation(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-dustrelayfee=0", "-maxtxfee=1"]]

    def log_sim_results(self, res_file):
        getcontext().prec = 12
        # Find change stats
        change_vals = sorted(self.change_vals)
        min_change = Decimal(change_vals[0]) if len(self.change_vals) > 0 else 0
        max_change = Decimal(change_vals[-1]) if len(self.change_vals) > 0 else 0
        mean_change = Decimal(mean(change_vals)) * Decimal(1) if len(self.change_vals) > 0 else 0
        stdev_change = Decimal(stdev(change_vals)) * Decimal(1) if len(self.change_vals) > 0 else 0

        # Remaining utxos and fee stats
        remaining_utxos = self.tester.listunspent()
        cost_to_empty = Decimal(-1) * Decimal(len(remaining_utxos)) * Decimal(68) * Decimal(0.00001) / Decimal(1000)
        total_cost = self.total_fees + cost_to_empty
        mean_fees = Decimal(self.total_fees) / Decimal(self.withdraws) if self.withdraws > 0 else 0

        # input stats
        input_sizes = sorted(self.input_sizes)
        min_input_size = Decimal(input_sizes[0]) if len(self.input_sizes) > 0 else 0
        max_input_size = Decimal(input_sizes[-1]) if len(self.input_sizes) > 0 else 0
        mean_input_size = (Decimal(mean(input_sizes)) * Decimal(1)) if len(self.input_sizes) > 0 else 0
        stdev_input_size = (Decimal(stdev(input_sizes)) * Decimal(1)) if len(self.input_sizes) > 0 else 0

        # UTXO stats
        mean_utxo_set_size = (Decimal(mean(self.utxo_set_sizes)) * Decimal(1)) if len(self.utxo_set_sizes) > 0 else 0

        csinfo = self.tester.coinselectioninfo()

        result_str = f"| {self.scenario} | {self.tester.getbalance()} | {mean_utxo_set_size} | {len(remaining_utxos)} | {self.count_received} | {self.count_sent} | {self.withdraws} | {self.unec_utxos} | {len(self.change_vals)} | {self.no_change} | {min_change} | {max_change} | {mean_change} | {stdev_change} | {self.total_fees} | {mean_fees} | {cost_to_empty} | {total_cost} | {min_input_size} | {max_input_size} | {mean_input_size} | {stdev_input_size} | {csinfo['bnb_usage']} | {csinfo['srd_usage']} | {csinfo['knapsack_usage']} | {self.bnb_no_change} | {self.srd_no_change} | {self.knapsack_no_change} |"
        res_file.write(f"{result_str}\n")
        res_file.flush()
        self.log.debug(result_str)
        return result_str

    def run_test(self):
        # Setup debug logging
        debug_log_handler = logging.FileHandler("sim_debug.log")
        debug_log_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)03d000Z %(name)s (%(levelname)s): %(message)s', datefmt='%Y-%m-%dT%H:%M:%S')
        debug_log_handler.setFormatter(formatter)
        self.log.addHandler(debug_log_handler)

        # Decimal precision
        getcontext().prec = 12

        # Make two wallets
        self.nodes[0].createwallet('funder')
        self.nodes[0].createwallet('tester')
        self.funder = self.nodes[0].get_wallet_rpc('funder')
        self.tester = self.nodes[0].get_wallet_rpc('tester')

        # Check that there's no UTXO on the wallets
        assert_equal(len(self.funder.listunspent()), 0)
        assert_equal(len(self.tester.listunspent()), 0)

        self.log.info("Mining blocks for node0 to be able to send enough coins")

        gen_addr = self.funder.getnewaddress()
        self.funder.generatetoaddress(600, gen_addr)  # > 14,000 BTC
        withdraw_address = self.funder.getnewaddress()
        deposit_address = self.tester.getnewaddress()

        self.scenario = 'sim_data.csv'

        header = "| Scenario File | Current Balance | Mean #UTXO | Current #UTXO | #Deposits | #Inputs Spent | #Withdraws | #Uneconomical outputs spent | #Change Created | #Changeless | Min Change Value | Max Change Value | Mean Change Value | Std. Dev. of Change Value | Total Fees | Mean Fees per Withdraw | Cost to Empty | Total Cost | Min Input Size | Max Input Size | Mean Input Size | Std. Dev. of Input Size | BnB Usage | SRD Usage | Knapsack Usage | #BnB no change | #SRD no change | #Knapsack no change |"

        self.log.info(f"Simulating using scenario: {self.scenario}")
        self.total_fees = Decimal()
        self.ops = 0
        self.count_sent = 0
        self.change_vals = []
        self.no_change = 0
        self.withdraws = 0
        self.input_sizes = []
        self.utxo_set_sizes = []
        self.count_change = 0
        self.count_received = 0
        self.unec_utxos = 0
        self.bnb_no_change = 0
        self.srd_no_change = 0
        self.knapsack_no_change = 0
        self.last_cs_info = {"bnb_usage": 0, "srd_usage": 0, "knapsack_usage": 0}
        with open('sim_results.txt', 'a+') as res:
            res.write(f'----BEGIN SIMULATION RESULTS----\nScenario: {self.scenario}\n{header}\n')
            res.flush()
            with open(self.scenario) as f:
                for line in f:
                    if self.ops % 500 == 0:
                        self.log.info(f"{self.ops} operations performed so far")
                        self.log_sim_results(res)

                    # Make deposit or withdrawal
                    val_str, fee_str = line.rstrip().lstrip().split(',')
                    value = Decimal(val_str)
                    feerate = Decimal(fee_str)
                    if value > 0:
                        try:
                            # deposit
                            self.funder.sendtoaddress(deposit_address, value)
                            self.count_received += 1
                            self.log.debug(f"Op {self.ops} Received {self.count_received}th deposit of {value} BTC")
                        except JSONRPCException as e:
                            self.log.warn(f"Failure on op {self.ops} with funder sending {value} with error {str(e)}")
                    if value < 0:
                        try:
                            # Prepare withdraw
                            value = value * -1
                            psbt = self.tester.walletcreatefundedpsbt(outputs=[{withdraw_address: value}], options={"feeRate": feerate})["psbt"]
                            psbt = self.tester.walletprocesspsbt(psbt)["psbt"]
                            # Send the tx
                            psbt = self.tester.finalizepsbt(psbt, False)["psbt"]
                            tx = self.tester.finalizepsbt(psbt)["hex"]
                            self.tester.sendrawtransaction(tx)
                            self.withdraws += 1
                            # Figure out which algo
                            algo = None
                            cs_info = self.tester.coinselectioninfo()
                            for a in ["bnb", "srd", "knapsack"]:
                                key = f"{a}_usage"
                                if cs_info[key] > self.last_cs_info[key]:
                                    algo = a
                                    assert cs_info[key] == self.last_cs_info[key] + 1
                                    break
                            self.last_cs_info = cs_info
                            # Get negative EV UTXOs
                            dec = self.tester.decodepsbt(psbt)
                            for inp in dec["inputs"]:
                                inp_size = 4 + 36 + 4 # prev txid, output index, sequence are all fixed size
                                if "final_scriptSig" in inp:
                                    scriptsig_len = len(inp["final_scriptSig"])
                                    inp_size += scriptsig_len + len(ser_compact_size(scriptsig_len))
                                else:
                                    inp_size += 1
                                if "final_scriptWitness" in inp:
                                    witness_len = len(inp["final_scriptWitness"])
                                    inp_size += witness_len / 4
                                inp_fee = feerate * (Decimal(inp_size) / Decimal(1000.0))
                                ev = inp["witness_utxo"]["amount"] - inp_fee
                                if ev <= 0:
                                    self.unec_utxos += 1
                            # Get fee info
                            fee = dec["fee"]
                            self.total_fees += fee
                            # Spent utxo counts and input info
                            num_in = len(dec["inputs"])
                            self.count_sent += num_in
                            self.input_sizes.append(num_in)
                            # Change info
                            has_change = False
                            if len(dec["tx"]["vout"]) > 1:
                                for out in dec["tx"]["vout"]:
                                    if out['scriptPubKey']['address'] != withdraw_address:
                                        self.change_vals.append(out['value'])
                                        self.count_change += 1
                                        has_change = True
                            if not has_change:
                                self.no_change += 1
                                assert algo is not None
                                if algo == "bnb":
                                    self.bnb_no_change += 1
                                elif algo == "srd":
                                    self.srd_no_change += 1
                                elif algo == "knapsack":
                                    self.knapsack_no_change += 1
                            self.log.debug(f"Op {self.ops} Sent {self.withdraws}th withdraw of {value} BTC using {num_in} inputs with fee {fee} ({feerate} BTC/kvB)")
                        except JSONRPCException as e:
                            self.log.warn(f"Failure on op {self.ops} with tester sending {value} with error {str(e)}")
                    self.utxo_set_sizes.append(len(self.tester.listunspent(0)))
                    self.funder.generatetoaddress(1, gen_addr)
                    self.ops += 1

            final_result = self.log_sim_results(res)
            res.write('----END SIMULATION RESULTS----\n\n\n')
            res.flush()
            self.log.info(header)
            self.log.info(final_result)


if __name__ == '__main__':
    CoinSelectionSimulation().main()
