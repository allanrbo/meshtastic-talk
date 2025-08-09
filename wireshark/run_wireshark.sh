SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"

mkdir -p $HOME/.local/lib/wireshark/plugins/
ln -s $SCRIPT_DIR/meshtastic_wireshark.lua $HOME/.local/lib/wireshark/plugins/meshtastic_wireshark.lua

MESHTASTIC_PROTO_DIR="$(realpath $SCRIPT_DIR/../rx_via_sdr/lib/meshtastic_protobufs)"
echo $MESHTASTIC_PROTO_DIR
wireshark \
  -i udpdump \
  -k \
  -o "uat:protobuf_search_paths:\"/usr/include/\",\"FALSE\"" \
  -o "uat:protobuf_search_paths:\"$MESHTASTIC_PROTO_DIR\",\"TRUE\"" \
  -o 'gui.column.format:"No.","%m","Time","%t","Info","%i"'

# Clean up symlink after we are done
rm $HOME/.local/lib/wireshark/plugins/meshtastic_wireshark.lua
