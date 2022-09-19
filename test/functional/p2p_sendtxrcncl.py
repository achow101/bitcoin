#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test SENDTXRCNCL message
"""

from test_framework.messages import (
    msg_sendtxrcncl,
    msg_verack,
    msg_version,
    msg_wtxidrelay,
)
from test_framework.p2p import (
    P2PInterface,
    P2P_SERVICES,
    P2P_SUBVERSION,
    P2P_VERSION,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class PeerNoVerack(P2PInterface):
    def __init__(self, wtxidrelay=True):
        super().__init__(wtxidrelay=wtxidrelay)

    def on_version(self, message):
        # Avoid sending verack in response to version.
        # When calling add_p2p_connection, wait_for_verack=False must be set (see
        # comment in add_p2p_connection).
        if message.nVersion >= 70016 and self.wtxidrelay:
            self.send_message(msg_wtxidrelay())

class SendTxrcnclReceiver(P2PInterface):
    def __init__(self):
        super().__init__()
        self.sendtxrcncl_msg_received = None

    def on_sendtxrcncl(self, message):
        self.sendtxrcncl_msg_received = message

class PeerTrackMsgOrder(P2PInterface):
    def __init__(self):
        super().__init__()
        self.messages = []

    def on_message(self, message):
        super().on_message(message)
        self.messages.append(message)

def create_sendtxrcncl_msg(initiator=True):
    sendtxrcncl_msg = msg_sendtxrcncl()
    sendtxrcncl_msg.initiator = initiator
    sendtxrcncl_msg.responder = not initiator
    sendtxrcncl_msg.version = 1
    sendtxrcncl_msg.salt = 2
    return sendtxrcncl_msg

class SendTxRcnclTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-txreconciliation']]

    def run_test(self):
        self.log.info('SENDTXRCNCL sent to an inbound')
        peer = self.nodes[0].add_p2p_connection(SendTxrcnclReceiver(), send_version=True, wait_for_verack=True)
        assert peer.sendtxrcncl_msg_received
        assert not peer.sendtxrcncl_msg_received.initiator
        assert peer.sendtxrcncl_msg_received.responder
        assert_equal(peer.sendtxrcncl_msg_received.version, 1)
        peer.peer_disconnect()

        self.log.info('SENDTXRCNCL should be sent before VERACK')
        peer = self.nodes[0].add_p2p_connection(PeerTrackMsgOrder(), send_version=True, wait_for_verack=True)
        peer.wait_for_verack()
        verack_index = [i for i, msg in enumerate(peer.messages) if msg.msgtype == b'verack'][0]
        sendtxrcncl_index = [i for i, msg in enumerate(peer.messages) if msg.msgtype == b'sendtxrcncl'][0]
        assert(sendtxrcncl_index < verack_index)
        peer.peer_disconnect()

        self.log.info('SENDTXRCNCL on pre-WTXID version should not be sent')
        peer = self.nodes[0].add_p2p_connection(SendTxrcnclReceiver(), send_version=False, wait_for_verack=False)
        pre_wtxid_version_msg = msg_version()
        pre_wtxid_version_msg.nVersion = 70015
        pre_wtxid_version_msg.strSubVer = P2P_SUBVERSION
        pre_wtxid_version_msg.nServices = P2P_SERVICES
        pre_wtxid_version_msg.relay = 1
        peer.send_message(pre_wtxid_version_msg)
        peer.wait_for_verack()
        assert not peer.sendtxrcncl_msg_received
        peer.peer_disconnect()

        self.log.info('SENDTXRCNCL for fRelay=false should not be sent')
        peer = self.nodes[0].add_p2p_connection(SendTxrcnclReceiver(), send_version=False, wait_for_verack=False)
        no_txrelay_version_msg = msg_version()
        no_txrelay_version_msg.nVersion = P2P_VERSION
        no_txrelay_version_msg.strSubVer = P2P_SUBVERSION
        no_txrelay_version_msg.nServices = P2P_SERVICES
        no_txrelay_version_msg.relay = 0
        peer.send_message(no_txrelay_version_msg)
        peer.wait_for_verack()
        assert not peer.sendtxrcncl_msg_received
        peer.peer_disconnect()

        self.log.info('valid SENDTXRCNCL received')
        peer = self.nodes[0].add_p2p_connection(PeerNoVerack(), send_version=True, wait_for_verack=False)
        peer.send_message(create_sendtxrcncl_msg())
        self.wait_until(lambda : "sendtxrcncl" in self.nodes[0].getpeerinfo()[-1]["bytesrecv_per_msg"])
        self.log.info('second SENDTXRCNCL triggers a disconnect')
        peer.send_message(create_sendtxrcncl_msg())
        peer.wait_for_disconnect()

        self.log.info('SENDTXRCNCL with initiator=responder=0 triggers a disconnect')
        sendtxrcncl_no_role = create_sendtxrcncl_msg()
        sendtxrcncl_no_role.initiator = False
        sendtxrcncl_no_role.responder = False
        peer = self.nodes[0].add_p2p_connection(PeerNoVerack(), send_version=True, wait_for_verack=False)
        peer.send_message(sendtxrcncl_no_role)
        peer.wait_for_disconnect()

        self.log.info('SENDTXRCNCL with initiator=0 and responder=1 from inbound triggers a disconnect')
        sendtxrcncl_wrong_role = create_sendtxrcncl_msg(initiator=False)
        peer = self.nodes[0].add_p2p_connection(PeerNoVerack(), send_version=True, wait_for_verack=False)
        peer.send_message(sendtxrcncl_wrong_role)
        peer.wait_for_disconnect()

        self.log.info('SENDTXRCNCL with version=0 triggers a disconnect')
        sendtxrcncl_low_version = create_sendtxrcncl_msg()
        sendtxrcncl_low_version.version = 0
        peer = self.nodes[0].add_p2p_connection(PeerNoVerack(), send_version=True, wait_for_verack=False)
        peer.send_message(sendtxrcncl_low_version)
        peer.wait_for_disconnect()

        self.log.info('sending SENDTXRCNCL after sending VERACK triggers a disconnect')
        # We use PeerNoVerack even though verack is sent right after, to make sure it was actually
        # sent before sendtxrcncl is sent.
        peer = self.nodes[0].add_p2p_connection(PeerNoVerack(), send_version=True, wait_for_verack=False)
        peer.send_and_ping(msg_verack())
        peer.send_message(create_sendtxrcncl_msg())
        peer.wait_for_disconnect()

        self.log.info('SENDTXRCNCL without WTXIDRELAY is ignored (recon state is erased after VERACK)')
        peer = self.nodes[0].add_p2p_connection(PeerNoVerack(wtxidrelay=False), send_version=True, wait_for_verack=False)
        with self.nodes[0].assert_debug_log(['Forget txreconciliation state of peer']):
            peer.send_message(create_sendtxrcncl_msg())
            peer.send_message(msg_verack())
        peer.peer_disconnect()

        self.log.info('SENDTXRCNCL sent to an outbound')
        peer = self.nodes[0].add_outbound_p2p_connection(
            SendTxrcnclReceiver(), wait_for_verack=True, p2p_idx=1, connection_type="outbound-full-relay")
        assert peer.sendtxrcncl_msg_received
        assert peer.sendtxrcncl_msg_received.initiator
        assert not peer.sendtxrcncl_msg_received.responder
        assert_equal(peer.sendtxrcncl_msg_received.version, 1)
        peer.peer_disconnect()

        self.log.info('SENDTXRCNCL should not be sent if block-relay-only')
        peer = self.nodes[0].add_outbound_p2p_connection(
            SendTxrcnclReceiver(), wait_for_verack=True, p2p_idx=2, connection_type="block-relay-only")
        assert not peer.sendtxrcncl_msg_received
        peer.peer_disconnect()

        self.log.info('SENDTXRCNCL if block-relay-only triggers a disconnect')
        peer = self.nodes[0].add_outbound_p2p_connection(
            PeerNoVerack(), wait_for_verack=False, p2p_idx=3, connection_type="block-relay-only")
        peer.send_message(create_sendtxrcncl_msg(initiator=False))
        peer.wait_for_disconnect()

        self.log.info('SENDTXRCNCL with initiator=1 and responder=0 from outbound triggers a disconnect')
        sendtxrcncl_wrong_role = create_sendtxrcncl_msg(initiator=True)
        peer = self.nodes[0].add_outbound_p2p_connection(
            P2PInterface(), wait_for_verack=False, p2p_idx=4, connection_type="outbound-full-relay")
        peer.send_message(sendtxrcncl_wrong_role)
        peer.wait_for_disconnect()

        self.log.info('SENDTXRCNCL not sent if -txreconciliation flag is not set')
        self.restart_node(0, [])
        peer = self.nodes[0].add_p2p_connection(SendTxrcnclReceiver(), send_version=True, wait_for_verack=True)
        assert not peer.sendtxrcncl_msg_received
        peer.peer_disconnect()

        self.log.info('SENDTXRCNCL not sent if blocksonly is set')
        self.restart_node(0, ["-txreconciliation", "-blocksonly"])
        peer = self.nodes[0].add_p2p_connection(SendTxrcnclReceiver(), send_version=True, wait_for_verack=True)
        assert not peer.sendtxrcncl_msg_received
        peer.peer_disconnect()


if __name__ == '__main__':
    SendTxRcnclTest().main()
