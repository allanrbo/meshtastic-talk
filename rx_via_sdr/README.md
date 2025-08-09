## Getting started

```
apt install build-essential cmake gnuradio-dev protobuf-compiler python3-protobuf
./run_grc.sh

# In another terminal window
./run_wireshark.sh

```


If you don't have the above mentioned Protobuf search paths configured correctly, all packets will show up as UNKNOWN_APP, and Protobuf decoding will generally not function correctly.

If emojis aren't showing up correctly in Wireshark, try this:
```
mkdir -p ~/.config/fontconfig/conf.d/
cat > ~/.config/fontconfig/conf.d/40-emoji.conf <<"EOF"
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
  <alias>
    <family>monospace</family>
    <prefer>
      <family>Noto Color Emoji</family>
      <family>Noto Mono</family>
    </prefer>
  </alias>
</fontconfig>
EOF

fc-cache -f

# In Wireshark: Edit -> Preferences -> Appearance -> Font and Colors -> Main window font -> monospace
```
