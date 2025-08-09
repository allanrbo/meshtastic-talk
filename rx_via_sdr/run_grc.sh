set -euo pipefail

git submodule update --init

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"


if ! command -v protoc >/dev/null 2>&1; then
    echo "protoc not available. Install it with e.g. apt install protobuf-compiler python3-protobuf"
    exit 1
fi
if ! command -v cmake >/dev/null 2>&1; then
    echo "cmake not available. Install it with e.g. apt install cmake"
    exit 1
fi
if ! command -v make >/dev/null 2>&1; then
    echo "make not available. Install it with e.g. apt install build-essential"
    exit 1
fi
if ! command -v gnuradio-companion >/dev/null 2>&1; then
    echo "gnuradio-companion not available. Install it with e.g. apt install gnuradio"
    exit 1
fi

if [[ -z ${VIRTUAL_ENV-} ]]; then
    echo "Please first activate the Python virtual env with the Python deps"
    exit 1
fi

cd $SCRIPT_DIR
mkdir -p lib
git submodule update --init

# Build and install LoRa module to a subdir to avoid needing root.
#   This was previously run: git submodule add https://github.com/tapparelj/gr-lora_sdr.git lib/gr-lora_sdr
cd $SCRIPT_DIR
mkdir -p lib/gr-lora_sdr_installed
cd lib/gr-lora_sdr
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=../../gr-lora_sdr_installed -DCMAKE_BUILD_TYPE=Release
make -j8
make install

# Generate protobuf Python modules.
#   This was previously run: git submodule add https://github.com/meshtastic/protobufs.git lib/meshtastic_protobufs
cd $SCRIPT_DIR
mkdir -p lib/meshtastic_protobufs_installed
cd lib/meshtastic_protobufs
protoc --proto_path . --python_out=../meshtastic_protobufs_installed/ meshtastic/*.proto

# Launch Gnu Radio Companion with correct paths.
PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
export PYTHONPATH="$SCRIPT_DIR/../venv/lib/python$PY_VERSION/site-packages:$SCRIPT_DIR/blocks:$SCRIPT_DIR/lib/meshtastic_protobufs_installed:$SCRIPT_DIR/lib/gr-lora_sdr_installed/lib/python$PY_VERSION/site-packages${PYTHONPATH:+:$PYTHONPATH}"
export LD_LIBRARY_PATH="$SCRIPT_DIR/lib/gr-lora_sdr_installed/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export GRC_BLOCKS_PATH="$SCRIPT_DIR/blocks:$SCRIPT_DIR/lib/gr-lora_sdr_installed/share/gnuradio/grc/blocks:${GRC_BLOCKS_PATH:+:$GRC_BLOCKS_PATH}"
gnuradio-companion
