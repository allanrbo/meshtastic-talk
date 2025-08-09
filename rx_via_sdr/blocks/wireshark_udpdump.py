#!/usr/bin/env python3
"""
Generic GNU Radio → Wireshark UDP forwarder.

Sends each incoming PMT u8vector as one PCAP record inside a UDP datagram.
"""
import socket
import struct
import time
import pmt
from gnuradio import gr


class wireshark_udpdump(gr.basic_block):
    def __init__(self, prefix_bytes=b""):
        super().__init__(name="wireshark_udpdump", in_sig=None, out_sig=None)
        self._prefix_bytes = prefix_bytes
        self._addr = ("127.0.0.1", 5555)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Register message handler
        self.message_port_register_in(pmt.intern("msg"))
        self.set_msg_handler(pmt.intern("msg"), self._handle_msg)

    def _handle_msg(self, msg_pmt):
        if pmt.is_null(msg_pmt):
            return

        pkt = bytes(pmt.to_python(msg_pmt))

        self._sock.sendto(self._prefix_bytes + pkt, self._addr)
