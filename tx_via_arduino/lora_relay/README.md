Allan Boll and ChatGPT o3
2025-04-28

Small Arduino program to send and receive LoRa data, and set LoRa modem setting.

Protocol:
```
FREQ <Hz>
BW <Hz>
SF <7-12>
CR <4/5|4/6|4/7|4/8>
TXPOWER <dBm>
SYNCWORD <0-FF>
PREAMBLE <symbols>
CRC <ON|OFF>
DATA <hex-payload>
STATUS
RESET
```

Paste this to set up for Meshtastic MediumSlow:
```
FREQ 914875000
BW 250000
SF 10
CR 4/5
TXPOWER 1
SYNCWORD 2B
PREAMBLE 16
CRC ON
```

Paste this to set up for Meshtastic ShortTurbo:
```
FREQ 917250000
BW 500000
SF 7
CR 4/5
TXPOWER 1
SYNCWORD 2B
PREAMBLE 16
CRC ON
```

