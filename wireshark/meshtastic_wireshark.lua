local meshtastic = Proto("meshtastic", "meshtastic")
local pb = Dissector.get("protobuf")

-- compatibility for Lua versions without bit32 (e.g. Lua 5.3 removed bit32)
if bit32 == nil and bit ~= nil then
    bit32 = { band = bit.band, rshift = bit.rshift }
end

-- Meshtastic layer-1 header fields
local pf_dest         = ProtoField.uint32("meshtastic.dest",       "Destination", base.HEX)
local pf_sender       = ProtoField.uint32("meshtastic.sender",     "Sender",      base.HEX)
local pf_packet_id    = ProtoField.uint32("meshtastic.packet_id",  "Packet ID",   base.HEX)
local pf_flags_raw    = ProtoField.uint8 ("meshtastic.flags_raw",  "Flags",       base.HEX)
local pf_channel_hash = ProtoField.uint8 ("meshtastic.channel_hash","Channel Hash")
local pf_next_hop     = ProtoField.uint8 ("meshtastic.next_hop",   "Next Hop")
local pf_relay        = ProtoField.uint8 ("meshtastic.relay",      "Relay")
local pf_payload      = ProtoField.bytes ("meshtastic.payload",    "Payload")

-- Bitfields for flags (HopLimit: bits 0-2, WantAck: bit 3, ViaMQTT: bit 4, HopStart: bits 5-7)
local pf_hop_limit   = ProtoField.uint8 ("meshtastic.hop_limit",   "Hop Limit", base.DEC, nil, 0x07)
local pf_want_ack    = ProtoField.bool  ("meshtastic.want_ack",    "Want Ack",  8,    nil, 0x08)
local pf_via_mqtt    = ProtoField.bool  ("meshtastic.via_mqtt",    "Via MQTT",  8,    nil, 0x10)
local pf_hop_start   = ProtoField.uint8 ("meshtastic.hop_start",   "Hop Start", base.DEC, nil, 0xE0)

meshtastic.fields = {
  pf_dest, pf_sender, pf_packet_id, pf_flags_raw, pf_hop_limit, pf_want_ack, pf_via_mqtt, pf_hop_start,
  pf_channel_hash, pf_next_hop, pf_relay, pf_payload
}

local exported_pdu = Dissector.get("exported_pdu")
local data_field = Field.new("data.data")

-- Because we're using the generic "udpdump" input of Wireshark, we will prefix
-- the relevant packets with this magic string so we can fall back to the
-- default dissector for the rest.
local magic     = "_meshtastic_____"

local latest_observed_portnum
local latest_observed_text_msg
local latest_observed_short_name
local latest_observed_long_name

function meshtastic.dissector(tvb, pinfo, tree)
    -- Fall back to the default dissector on wtap.WIRESHARK_UPPER_PDU.
    exported_pdu:call(tvb, pinfo, tree)

    -- Is there a data field, and does it start with our magic string?
    if data_field() == nil then
        return
    end
    tvb = data_field().value:tvb()
    if tvb(0,#magic):raw() ~= magic then
        return
    end

    -- Skip past the magic string.
    tvb = tvb(#magic)

    latest_observed_portnum = "UNKNOWN_APP"
    latest_observed_text_msg = nil
    latest_observed_short_name = nil
    latest_observed_long_name = nil

    pinfo.cols.protocol = meshtastic.name
    local subtree = tree:add(meshtastic, tvb, "Meshtastic packet")
    -- Layer-1 header (16 bytes)
    subtree:add_le(pf_dest,      tvb(0,4))
    subtree:add_le(pf_sender,    tvb(4,4))
    subtree:add_le(pf_packet_id, tvb(8,4))
    local flags_item = subtree:add(pf_flags_raw, tvb(12,1))
    flags_item:add(pf_hop_limit, tvb(12,1))
    flags_item:add(pf_want_ack,  tvb(12,1))
    flags_item:add(pf_via_mqtt,  tvb(12,1))
    flags_item:add(pf_hop_start, tvb(12,1))
    -- override flags summary to include raw value and names of set flag bits
    do
        local flags_val = tvb(12,1):uint()
        local flags_desc = {}
        -- Hop Limit (bits 0-2)
        local hop_limit = bit32.band(flags_val, 0x07)
        table.insert(flags_desc, string.format("Hop Limit=%d", hop_limit))
        -- Want Ack (bit 3)
        if bit32.band(flags_val, 0x08) ~= 0 then table.insert(flags_desc, "Want Ack") end
        -- Via MQTT (bit 4)
        if bit32.band(flags_val, 0x10) ~= 0 then table.insert(flags_desc, "Via MQTT") end
        -- Hop Start (bits 5-7)
        local hop_start = bit32.rshift(bit32.band(flags_val, 0xE0), 5)
        table.insert(flags_desc, string.format("Hop Start=%d", hop_start))
        local txt = string.format("Flags: 0x%03X", flags_val)
        if #flags_desc > 0 then txt = txt .. " (" .. table.concat(flags_desc, ", ") .. ")" end
        flags_item:set_text(txt)
    end
    subtree:add(pf_channel_hash, tvb(13,1))
    subtree:add(pf_next_hop,     tvb(14,1))
    subtree:add(pf_relay,        tvb(15,1))
    subtree:add(pf_payload,      tvb(16))  -- Rest of packet.

    pinfo.private["pb_msg_type"] = "message,meshtastic.Data"
    pb:call(tvb(16):tvb(), pinfo, subtree)

    local optional_info = ""
    if latest_observed_text_msg ~= nil then
        optional_info = optional_info .. " text_message=\"" .. latest_observed_text_msg .. "\""
    end
    if latest_observed_short_name ~= nil then
        optional_info = optional_info .. " short_name=\"" .. latest_observed_short_name .. "\""
    end
    if latest_observed_long_name ~= nil then
        optional_info = optional_info .. " long_name=\"" .. latest_observed_long_name .. "\""
    end
    pinfo.cols.info:set(
        string.format(
            "Meshtastic frame, len=%d, dest=%08x, sender=%08x, portnum=%s",
            tvb:len(),
            tvb(0,4):le_uint(),
            tvb(4,4):le_uint(),
            latest_observed_portnum
        ) .. optional_info
    )
end

DissectorTable.get("wtap_encap"):add(wtap.WIRESHARK_UPPER_PDU, meshtastic)

do
    local protobuf_field = DissectorTable.get("protobuf_field")

    -- Store the latest observed portnum from meshtastic.Data.
    -- The hope is that, because portnum is a lower tag number than payload, it
    -- will always get hit before payload.
    local portnum_names = {
        [0] = "UNKNOWN_APP",
        [1] = "TEXT_MESSAGE_APP",
        [2] = "REMOTE_HARDWARE_APP",
        [3] = "POSITION_APP",
        [4] = "NODEINFO_APP",
        [5] = "ROUTING_APP",
        [6] = "ADMIN_APP",
        [7] = "TEXT_MESSAGE_COMPRESSED_APP",
        [8] = "WAYPOINT_APP",
        [9] = "AUDIO_APP",
        [10] = "DETECTION_SENSOR_APP",
        [11] = "ALERT_APP",
        [12] = "KEY_VERIFICATION_APP",
        [32] = "REPLY_APP",
        [33] = "IP_TUNNEL_APP",
        [34] = "PAXCOUNTER_APP",
        [64] = "SERIAL_APP",
        [65] = "STORE_FORWARD_APP",
        [66] = "RANGE_TEST_APP",
        [67] = "TELEMETRY_APP",
        [68] = "ZPS_APP",
        [69] = "SIMULATOR_APP",
        [70] = "TRACEROUTE_APP",
        [71] = "NEIGHBORINFO_APP",
        [72] = "ATAK_PLUGIN",
        [73] = "MAP_REPORT_APP",
        [74] = "POWERSTRESS_APP",
        [76] = "RETICULUM_TUNNEL_APP",
        [77] = "CAYENNE_APP",
        [256] = "PRIVATE_APP",
        [257] = "ATAK_FORWARDER",
    }
    local portnum_proto = Proto("meshtastic.Data.portnum", "meshtastic.Data.portnum")
    function portnum_proto.dissector(tvb, pinfo, tree)
        latest_observed_portnum = portnum_names[tvb():uint()] or "UNKNOWN_APP"
    end
    protobuf_field:add("meshtastic.Data.portnum", portnum_proto)

    local short_name_proto = Proto("meshtastic.User.short_name", "meshtastic.User.short_name")
    function short_name_proto.dissector(tvb, pinfo, tree)
        latest_observed_short_name = tvb():string(ENC_UTF_8)
    end
    protobuf_field:add("meshtastic.User.short_name", short_name_proto)

    local long_name_proto = Proto("meshtastic.User.long_name", "meshtastic.User.long_name")
    function long_name_proto.dissector(tvb, pinfo, tree)
        latest_observed_long_name = tvb():string(ENC_UTF_8)
    end
    protobuf_field:add("meshtastic.User.long_name", long_name_proto)

    -- Hook on when we meet a meshtastic.Data.payload, and switch between the
    -- different protobuf message types that we have definitions for, based on
    -- the latest observed port number.
    local payload_proto = Proto("meshtastic.Data.payload", "meshtastic.Data.payload")
    function payload_proto.dissector(tvb, pinfo, tree)
        -- Text-like payloads
        if latest_observed_portnum == "TEXT_MESSAGE_APP"
           or latest_observed_portnum == "DETECTION_SENSOR_APP"
           or latest_observed_portnum == "ALERT_APP"
           or latest_observed_portnum == "RANGE_TEST_APP"
           or latest_observed_portnum == "REPLY_APP" then
            local payload_range = tvb:range()
            local payload_text = payload_range:string(ENC_UTF_8)
            tree:add(payload_range, "Text message: " .. payload_text)
            latest_observed_text_msg = payload_text
        end

        if latest_observed_portnum == "REMOTE_HARDWARE_APP" then
            pinfo.private["pb_msg_type"] = "message,meshtastic.HardwareMessage"
            pb:call(tvb, pinfo, tree)
        end

        if latest_observed_portnum == "POSITION_APP" then
            pinfo.private["pb_msg_type"] = "message,meshtastic.Position"
            pb:call(tvb, pinfo, tree)
        end

        if latest_observed_portnum == "NODEINFO_APP" then
            pinfo.private["pb_msg_type"] = "message,meshtastic.User"
            pb:call(tvb, pinfo, tree)
        end

        if latest_observed_portnum == "ROUTING_APP" then
            pinfo.private["pb_msg_type"] = "message,meshtastic.Routing"
            pb:call(tvb, pinfo, tree)
        end

        if latest_observed_portnum == "ADMIN_APP" then
            pinfo.private["pb_msg_type"] = "message,meshtastic.AdminMessage"
            pb:call(tvb, pinfo, tree)
        end

        if latest_observed_portnum == "WAYPOINT_APP" then
            pinfo.private["pb_msg_type"] = "message,meshtastic.Waypoint"
            pb:call(tvb, pinfo, tree)
        end

        if latest_observed_portnum == "KEY_VERIFICATION_APP" then
            pinfo.private["pb_msg_type"] = "message,meshtastic.KeyVerification"
            pb:call(tvb, pinfo, tree)
        end

        if latest_observed_portnum == "PAXCOUNTER_APP" then
            pinfo.private["pb_msg_type"] = "message,meshtastic.Paxcount"
            pb:call(tvb, pinfo, tree)
        end

        if latest_observed_portnum == "STORE_FORWARD_APP" then
            pinfo.private["pb_msg_type"] = "message,meshtastic.StoreAndForward"
            pb:call(tvb, pinfo, tree)
        end

        if latest_observed_portnum == "TELEMETRY_APP" then
            pinfo.private["pb_msg_type"] = "message,meshtastic.Telemetry"
            pb:call(tvb, pinfo, tree)
        end

        if latest_observed_portnum == "TRACEROUTE_APP" then
            pinfo.private["pb_msg_type"] = "message,meshtastic.RouteDiscovery"
            pb:call(tvb, pinfo, tree)
        end

        if latest_observed_portnum == "NEIGHBORINFO_APP" then
            pinfo.private["pb_msg_type"] = "message,meshtastic.NeighborInfo"
            pb:call(tvb, pinfo, tree)
        end

        if latest_observed_portnum == "ATAK_PLUGIN" then
            pinfo.private["pb_msg_type"] = "message,meshtastic.TAKPacket"
            pb:call(tvb, pinfo, tree)
        end

        if latest_observed_portnum == "MAP_REPORT_APP" then
            pinfo.private["pb_msg_type"] = "message,meshtastic.MapReport"
            pb:call(tvb, pinfo, tree)
        end

        if latest_observed_portnum == "POWERSTRESS_APP" then
            pinfo.private["pb_msg_type"] = "message,meshtastic.PowerStressMessage"
            pb:call(tvb, pinfo, tree)
        end
    end
    protobuf_field:add("meshtastic.Data.payload", payload_proto)
end
