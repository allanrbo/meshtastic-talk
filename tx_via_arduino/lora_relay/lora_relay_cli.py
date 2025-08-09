#!/usr/bin/env python3
"""Simple interactive CLI for the LoRaRelay protocol.

Usage:  lora_cli.py [-p PORT] [-b BAUD] [command ...]
If commands are given on the CLI they are sent and the program exits.
Otherwise an interactive shell starts where you can type protocol lines.
Incoming DATA lines are decoded/pretty‑printed automatically.
"""
import argparse, serial, threading, binascii, shlex, sys, time, re
from datetime import datetime

DATA_RE  = re.compile(r"^DATA\s+([0-9A-Fa-f]+)\s+RSSI=([-0-9.]+)\s+SNR=([-0-9.]+)")

###########################################################################
# Serial helpers
###########################################################################

def open_serial(port:str, baud:int)->serial.Serial:
    ser = serial.Serial(port=port, baudrate=baud, timeout=0.1)
    if not ser.is_open:
        ser.open()
    return ser

def hexdump(data:bytes, width:int=16):
    for off in range(0,len(data),width):
        chunk = data[off:off+width]
        hexpart = ' '.join(f"{b:02X}" for b in chunk)
        asc = ''.join(chr(b) if 32<=b<=126 else '.' for b in chunk)
        print(f"{off:04X}  {hexpart:<{width*3}}  {asc}")

###########################################################################
# Receiving thread
###########################################################################

def recv_loop(ser:serial.Serial):
    buf = b''
    while True:
        try:
            buf += ser.read(ser.in_waiting or 1)
            if b'\n' not in buf:
                time.sleep(0.01); continue
            line, buf = buf.split(b'\n',1)
            txt = line.decode(errors='replace').strip()
            m = DATA_RE.match(txt)
            if m:
                raw = bytes.fromhex(m.group(1))
                rssi, snr = m.group(2), m.group(3)
                ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
                print(f"\n{ts}  RSSI={rssi}  SNR={snr}")
                hexdump(raw)
                print()
            else:
                print(txt)
        except serial.SerialException:
            break

###########################################################################
# Main
###########################################################################

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-p','--port',default='/dev/ttyACM0')
    ap.add_argument('-b','--baud',type=int,default=9600)
    ap.add_argument('cmd',nargs=argparse.REMAINDER,help='optional command(s) to send')
    args = ap.parse_args()

    ser = open_serial(args.port,args.baud)

    th = threading.Thread(target=recv_loop,args=(ser,),daemon=True)
    th.start()

    def send(line:str):
        ser.write((line+'\n').encode())
    
    # If commands were passed on cmdline, send & quit
    if args.cmd:
        send(' '.join(args.cmd))
        time.sleep(0.2)
        return

    print("Type protocol lines (ctrl+c to quit). Incoming DATA are decoded.")
    try:
        while True:
            line = input('> ').strip()
            if not line:
                line = "status"
            send(line)
    except (EOFError, KeyboardInterrupt):
        pass

if __name__ == '__main__':
    main()
