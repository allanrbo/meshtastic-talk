#include <LoRa.h>

// ─────────────────────────── Hardware pinout (LoR32u4II) ──────────────────────────
#define SCK   15
#define MISO  14
#define MOSI  16
#define NSS    8
#define RST    4
#define DIO0   7
#define PABOOST true

// ─────────────────────────── Default settings ─────────────────────────────────────
uint32_t  g_freq     = 915000000UL;   // Hz
uint32_t  g_bw       = 125000UL;      // Hz
uint8_t   g_sf       = 7;             // 7‑12
uint8_t   g_cr_denom = 5;             // coding‑rate 4/5 ... 4/8
uint8_t   g_txpower  = 17;            // dBm (‑4 ... 20 depending on module)
uint8_t   g_syncword = 0x12;          // hex byte
uint16_t  g_preamble = 8;             // symbols
bool      g_crc_en   = false;

// ─────────────────────────── Helpers ───────────────────────────────────────────────
void sendOK()               { Serial.println(F("OK")); }
void sendERR(const char* m) { Serial.print(F("ERR ")); Serial.println(m); }

void applySettings() {
  LoRa.setFrequency(g_freq);
  LoRa.setSignalBandwidth(g_bw);
  LoRa.setSpreadingFactor(g_sf);
  LoRa.setCodingRate4(g_cr_denom);
  LoRa.setTxPower(g_txpower);
  LoRa.setSyncWord(g_syncword);
  g_crc_en ? LoRa.enableCrc() : LoRa.disableCrc();
  LoRa.setPreambleLength(g_preamble);
}

void dumpStatus() {
  Serial.print(F("STATUS "));
  Serial.print(F("FREQ="));     Serial.print(g_freq);
  Serial.print(F(" BW="));       Serial.print(g_bw);
  Serial.print(F(" SF="));       Serial.print(g_sf);
  Serial.print(F(" CR=4/"));     Serial.print(g_cr_denom);
  Serial.print(F(" TXPOWER="));  Serial.print(g_txpower);
  Serial.print(F(" SYNCWORD=")); Serial.print(g_syncword, HEX);
  Serial.print(F(" PREAMBLE=")); Serial.print(g_preamble);
  Serial.print(F(" CRC="));      Serial.println(g_crc_en ? F("ON") : F("OFF"));
}

// returns -1 on error, 0‑255 on success
int16_t hexByte(char hi, char lo) {
    auto nib = [](char c)->int8_t {
        if ('0'<=c && c<='9') return c-'0';
        if ('a'<=c && c<='f') return c-'a'+10;
        if ('A'<=c && c<='F') return c-'A'+10;
        return -1;
    };
    int8_t n1 = nib(hi), n2 = nib(lo);
    if (n1<0 || n2<0) return -1;
    return (n1<<4) | n2;
}

void sendLoraPacket(const String& hex) {
    if (hex.length() & 1) { sendERR("odd DATA length"); return; }

    LoRa.beginPacket();
    for (size_t i = 0; i < hex.length(); i += 2) {
        int16_t v = hexByte(hex[i], hex[i+1]);
        if (v < 0) { LoRa.endPacket(); sendERR("bad hex"); return; }
        LoRa.write((uint8_t)v);
    }
    LoRa.endPacket();
    sendOK();
    LoRa.receive();
}


void parseLine(String line) {
  line.trim();
  if (!line.length() || line[0]=='#') return;   // ignore empty & comments

  int sp = line.indexOf(' ');
  String cmd = (sp==-1) ? line : line.substring(0,sp);
  String arg = (sp==-1) ? ""  : line.substring(sp+1);
  cmd.toUpperCase();

  if (cmd == "HELLO") { Serial.println(F("HELLO LoRaRelay 1.0 SX1276")); return; }
  else if (cmd == "FREQ") {
    g_freq = arg.toInt(); applySettings(); sendOK();
  } else if (cmd == "BW") {
    g_bw = arg.toInt(); applySettings(); sendOK();
  } else if (cmd == "SF") {
    uint8_t v = arg.toInt(); if (v<7||v>12) { sendERR("SF range"); return; }
    g_sf=v; applySettings(); sendOK();
  } else if (cmd == "CR") {
    if (!arg.startsWith("4/")) { sendERR("CR format"); return; }
    uint8_t d = arg.substring(2).toInt(); if (d<5||d>8) { sendERR("CR denom"); return; }
    g_cr_denom=d; applySettings(); sendOK();
  } else if (cmd == "TXPOWER") {
    g_txpower = arg.toInt(); applySettings(); sendOK();
  } else if (cmd == "SYNCWORD") {
    g_syncword = strtol(arg.c_str(), nullptr, 16); applySettings(); sendOK();
  } else if (cmd == "PREAMBLE") {
    g_preamble = arg.toInt(); applySettings(); sendOK();
  } else if (cmd == "CRC") {
    arg.toUpperCase();
    if (arg=="ON")  g_crc_en=true;
    else if (arg=="OFF") g_crc_en=false;
    else { sendERR("CRC arg"); return; }
    applySettings(); sendOK();
  } else if (cmd == "DATA") {
    sendLoraPacket(arg);
  } else if (cmd == "STATUS") { dumpStatus(); }
  else if (cmd == "RESET")  { applySettings(); sendOK(); }
  else { sendERR("unknown cmd"); }
}

// ─────────────────────────── Arduino setup / loop ─────────────────────────────────
void setup() {
  pinMode(LED_BUILTIN, OUTPUT);
  Serial.begin(9600);
  while(!Serial);

  LoRa.setPins(NSS,RST,DIO0);
  if (!LoRa.begin(g_freq,PABOOST)) {
    Serial.println(F("ERR LoRa init")); while(true);
  }
  applySettings();
  Serial.println(F("HELLO LoRaRelay 1.0 SX1276"));
  dumpStatus();
  LoRa.onReceive(onReceiveLora);
  LoRa.receive();
}

void loop() {
  if (Serial.available()) {
    String line = Serial.readStringUntil('\n');
    parseLine(line);
  }
}

// ─────────────────────────── Receive callback ────────────────────────────────────
void onReceiveLora(int packetSize) {
  if (packetSize <= 0) return;   // defensive: RX done fired but zero bytes

  String out = "DATA ";
  for (int i = 0; i < packetSize; ++i) {
    uint8_t b = LoRa.read();
    char buf[3];
    sprintf(buf, "%02x", b);
    out += buf;
  }
  out += " RSSI=" + String(LoRa.packetRssi());
  out += " SNR="  + String(LoRa.packetSnr());
  Serial.println(out);
}
