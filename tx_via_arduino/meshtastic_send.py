#!/usr/bin/env python3
# Minimal Meshtastic sender using a LoRa relay Arduino
#
# - Configures modem (ShortTurbo), builds meshtastic.Data via mesh_pb2,
#   AES‑CTR encrypts it, prepends L1 header and sends via "DATA <hex>".

import os, sys, time, serial, secrets, struct, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from time import sleep

# I have my protoc output in this path, so if you have properly
# installed it or have it in a different path, you wont need this path hack...
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'rx_via_sdr', 'lib', 'meshtastic_protobufs_installed'))
from meshtastic import mesh_pb2
from meshtastic import portnums_pb2

if len(sys.argv) != 2:
    print("usage: meshtastic_send.py \"your message\""); raise SystemExit(1)
msg_txt = sys.argv[1]

PORT = '/dev/ttyACM0'

DEST = 0xFFFFFFFF
SENDER = 0xCAFED00D
HOP_LIMIT = 1

CHAN_NAME = "equalbeat"
PSK = base64.b64decode("06lGUq+WhpsOt/weuKcesGzFVZ6HQx3rwWyS8liJhzY=")
# CHAN_NAME = "DEFCONnect"
# PSK = base64.b64decode("OEu8wB3AItGBvza4YSHh+5a3LlW/dCJ+nWr7SNZMsaE=")
# CHAN_NAME = "HackerComms"
# PSK = base64.b64decode("6IzsaoVhx1ETWeWuu0dUWMLqItvYJLbRzwgTAKCfvtY=")
# CHAN_NAME = "NodeChat"
# PSK = base64.b64decode("TiIdi8MJG+IRnIkS8iUZXRU+MHuGtuzEasOWXp4QndU=")


def xor_hash(bs:bytes)->int:
    h = 0
    for b in bs:
        h ^= b
    return h

def channel_hash(name:str, key:bytes)->int:
    # Like in firmware/src/mesh/Channels.cpp
    return (xor_hash(name.encode()) ^ xor_hash(key)) & 0xFF

def aes_ctr_encrypt(key:bytes, sender:int, pkt_id:int, plain:bytes)->bytes:
    if len(key) not in (16,32):
        raise ValueError('PSK must be 16 or 32 bytes')
    ctr = pkt_id.to_bytes(8,'little') + sender.to_bytes(4,'little') + b"\x00"*4
    enc = Cipher(algorithms.AES(key), modes.CTR(ctr)).encryptor()
    return enc.update(plain) + enc.finalize()

# Build packet
msg_txt = sys.argv[1] if len(sys.argv) > 1 else 'hello world'
pkt = mesh_pb2.Data(
    portnum=portnums_pb2.PortNum.TEXT_MESSAGE_APP,
    payload=msg_txt.encode('utf-8'),
)
data_plain = pkt.SerializeToString()
packet_id = secrets.randbits(32)
ch = channel_hash(CHAN_NAME, PSK)
hop_start = HOP_LIMIT
flags = (HOP_LIMIT & 0x07) | ((hop_start & 0x07) << 5)
data_enc = aes_ctr_encrypt(PSK, SENDER, packet_id, data_plain)
# Layer-1 header format described in https://meshtastic.org/docs/overview/mesh-algo/
hdr = struct.pack('<IIIBBBB', DEST, SENDER, packet_id, flags, ch, 0, 0)
packet = hdr + data_enc

# Send to Arduino
ser = serial.Serial(PORT, 9600, timeout=0.2)
if not ser.is_open:
    ser.open()

def send(line:str):
    ser.write((line + '\n').encode())
    time.sleep(0.05)

# Meshtastic ShortTurbo
send('FREQ 917250000')
send('BW 500000')
send('SF 7')
send('CR 4/5')
send('TXPOWER 1')
send('SYNCWORD 2B')
send('PREAMBLE 16')
send('CRC ON')

send('DATA ' + packet.hex().upper())
