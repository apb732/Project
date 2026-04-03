import json
from scapy.all import *

def parse_bssload_bytes(hex_string):
    raw = bytes.fromhex(hex_string)
    if len(raw) != 5:
        print(f"Unexpected BSS Load length: {len(raw)} bytes")
        return None
    station_count = int.from_bytes(raw[0:2], 'little')
    channel_utilization = raw[2]
    admission_capacity = int.from_bytes(raw[3:5], 'little')
    utilization_percent = round(channel_utilization * 100 / 255, 1)
    return {
        "Station Count": station_count,
        "Channel Utilization": channel_utilization,
        "Channel Utilization (%)": utilization_percent,
        "Available Admission Capacity": admission_capacity
    }

def extract_bssload_hex(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 11 and elt.info:
            return elt.info.hex()
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def get_ssid(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0:
            return elt.info.decode(errors='ignore')
        elt = elt.payload.getlayer(Dot11Elt)
    return None

def get_channel(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3 and elt.info:
            return elt.info[0]
        if elt.ID == 61 and elt.info:
            return elt.info[0]
        if elt.ID == 192 and elt.info:
            return elt.info[0]
        elt = elt.payload.getlayer(Dot11Elt)
    return None

def channel_to_band(ch, freq=None):
    if freq and 5925 <= freq <= 7125:
        return "6 GHz"
    if ch is None:
        return None
    if 1 <= ch <= 14:
        return "2.4 GHz"
    if 36 <= ch <= 165:
        return "5 GHz"
    return "Unknown"

def get_standard(pkt):
    has_ht = has_vht = has_he = has_eht = False
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 45: has_ht = True
        elif elt.ID == 191: has_vht = True
        elif elt.ID == 255 and elt.info and elt.info[0] == 35: has_he = True
        elif elt.ID == 255 and elt.info and elt.info[0] == 108: has_eht = True
        elt = elt.payload.getlayer(Dot11Elt)
    if has_eht: return "Wi-Fi 7 (802.11be)"
    if has_he: return "Wi-Fi 6 (802.11ax)"
    if has_vht: return "Wi-Fi 5 (802.11ac)"
    if has_ht: return "Wi-Fi 4 (802.11n)"
    return "Legacy"

def HT_capabilities_information_element_parser(ht_data):
    if not ht_data or len(ht_data) < 26:
        return None

    # --- Base field extraction ---
    ht_cap_info = int.from_bytes(ht_data[0:2], 'little')
    ampdu_params = ht_data[2]
    supported_mcs_set = ht_data[3:19]  # Bytes 3–18
    ht_ext_cap = int.from_bytes(ht_data[19:21], 'little')
    txbf_cap = int.from_bytes(ht_data[21:25], 'little')
    asel_cap = ht_data[25]

    # --- Decode bitfields from HT Capabilities Info (16 bits) ---
    ldpc                 = bool(ht_cap_info & (1 << 0))
    chan_width_40mhz     = bool(ht_cap_info & (1 << 1))
    sm_power_save        = (ht_cap_info >> 2) & 0b11
    greenfield           = bool(ht_cap_info & (1 << 4))
    short_gi_20          = bool(ht_cap_info & (1 << 5))
    short_gi_40          = bool(ht_cap_info & (1 << 6))
    tx_stbc              = bool(ht_cap_info & (1 << 7))
    rx_stbc              = (ht_cap_info >> 8) & 0b11
    reserved_b10         = bool(ht_cap_info & (1 << 10))
    max_amsdu_len        = 7935 if (ht_cap_info & (1 << 11)) else 3839
    dsss_cck_40          = bool(ht_cap_info & (1 << 12))
    reserved_b13         = bool(ht_cap_info & (1 << 13))
    forty_mhz_intolerant = bool(ht_cap_info & (1 << 14))
    reserved_b15         = bool(ht_cap_info & (1 << 15))

    smps_mode = {0: "Static", 1: "Dynamic", 3: "Disabled"}.get(sm_power_save, "Reserved")
    rx_stbc_desc = {0: "None", 1: "1 stream", 2: "1–2 streams", 3: "1–3 streams"}.get(rx_stbc, "Reserved")

    # Supported MCS Set
    # The first 4 bytes represent 8 MCS indexes each (0–31)
    rx_nss = 0
    for i in range(4):
        if supported_mcs_set[i] != 0:
            rx_nss = i + 1  # each nonzero byte = one supported RX stream

    # TX MCS Field (byte index 12) encodes TX stream info
    tx_mcs_field = supported_mcs_set[12] if len(supported_mcs_set) > 12 else 0
    tx_nss = None
    tx_nss_desc = "TX MCS not defined"

    if (tx_mcs_field & 0x01) == 0:
        tx_nss_desc = "TX MCS set not explicitly defined"
    elif (tx_mcs_field & 0x02) == 0:
        tx_nss = rx_nss
        tx_nss_desc = f"TX MCS = RX MCS ({rx_nss} stream{'s' if rx_nss != 1 else ''})"
    else:
        tx_nss_bits = (tx_mcs_field >> 2) & 0x03
        tx_nss = tx_nss_bits + 1
        tx_nss_desc = f"{tx_nss} TX spatial stream{'s' if tx_nss != 1 else ''}"

    return {
        "LDPC": ldpc,
        "40 MHz Support": chan_width_40mhz,
        "SM Power Save": smps_mode,
        "Greenfield": greenfield,
        "Short GI 20MHz": short_gi_20,
        "Short GI 40MHz": short_gi_40,
        "TX STBC": tx_stbc,
        "RX STBC": rx_stbc_desc,
        "Reserved (B10)": reserved_b10,
        "Max A-MSDU Length": max_amsdu_len,
        "DSSS/CCK 40MHz": dsss_cck_40,
        "Reserved (B13)": reserved_b13,
        "40MHz Intolerant": forty_mhz_intolerant,
        "Reserved (B15)": reserved_b15,
        "A-MPDU Params": f"0x{ampdu_params:02x}",

        "Supported MCS Set (hex)": supported_mcs_set.hex(),
        "RX NSS": rx_nss,
        "TX NSS": tx_nss,
        "TX NSS Description": tx_nss_desc,

        "HT Extended Capabilities": f"0x{ht_ext_cap:04x}",
        "TX Beamforming Capabilities": f"0x{txbf_cap:08x}",
        "Antenna Selection Capabilities": f"0x{asel_cap:02x}",
    }


def get_ht_capabilities(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 45:
            ht_data = elt.info
            return HT_capabilities_information_element_parser(ht_data)
        elt = elt.payload.getlayer(Dot11Elt)
    return None

def VHT_capabilities_information_element_parser(vht_data):
    if not vht_data or len(vht_data) < 12:
        return None

    vht_cap_info = int.from_bytes(vht_data[0:4], 'little')
    supported_mcs_set = vht_data[4:12]

    max_mpdu_len_code = (vht_cap_info >> 0) & 0b11
    supp_chan_width   = (vht_cap_info >> 2) & 0b11
    rx_ldpc           = bool(vht_cap_info & (1 << 4))
    short_gi_80       = bool(vht_cap_info & (1 << 5))
    short_gi_160      = bool(vht_cap_info & (1 << 6))
    tx_stbc           = bool(vht_cap_info & (1 << 7))
    rx_stbc           = (vht_cap_info >> 8) & 0b111
    su_beamformer     = bool(vht_cap_info & (1 << 11))
    su_beamformee     = bool(vht_cap_info & (1 << 12))

    beamformee_sts_raw = (vht_cap_info >> 13) & 0b111
    bf_sts_cap = beamformee_sts_raw + 1

    num_sounding_dims_raw = (vht_cap_info >> 16) & 0b111
    num_sounding_dim = num_sounding_dims_raw + 1

    mu_beamformer     = bool(vht_cap_info & (1 << 19))
    mu_beamformee     = bool(vht_cap_info & (1 << 20))
    vht_txop_ps       = bool(vht_cap_info & (1 << 21))
    htc_vht_capable   = bool(vht_cap_info & (1 << 22))

    exp = (vht_cap_info >> 23) & 0b111
    max_ampdu_exp = (1 << (13 + exp)) - 1


    vht_link_adapt = (vht_cap_info >> 26) & 0b11


    rx_ant_cons       = bool(vht_cap_info & (1 << 28))
    tx_ant_cons       = bool(vht_cap_info & (1 << 29))

    ext_nss_bw        = (vht_cap_info >> 30) & 0b11


    mpdu_len_map   = {0: "≤3895 B", 1: "≤7991 B", 2: "≤11454 B"}
    chan_width_map = {0: "Neither 160 nor 80+80 MHz", 1: "160 MHz", 2: "160 and 80+80 MHz"}
    ext_nss_bw_map = {0: "Not supported", 1: "Supported", 2: "Reserved", 3: "Reserved"}
    vht_link_adapt_map = {0: "No Feedback", 1: "Reserved", 2: "Unsolicited feedback", 3: "Both unsolicited and solicited feedback"}

    return {
        "Max MPDU Length": mpdu_len_map.get(max_mpdu_len_code, "Reserved"),
        "Supported Channel Width": chan_width_map.get(supp_chan_width, "Reserved"),
        "RX LDPC": rx_ldpc,
        "Short GI for 80 MHz": short_gi_80,
        "Short GI for 160 MHz": short_gi_160,
        "TX STBC": tx_stbc,
        "RX STBC": rx_stbc,
        "SU Beamformer Capable": su_beamformer,
        "SU Beamformee Capable": su_beamformee,
        "Beamformee STS Capability": bf_sts_cap,
        "Number of Sounding Dimensions": num_sounding_dim,
        "MU Beamformer Capable": mu_beamformer,
        "MU Beamformee Capable": mu_beamformee,
        "VHT TXOP Power Save": vht_txop_ps,
        "+HTC-VHT Capable": htc_vht_capable,
        "Max A-MPDU Length Exponent": max_ampdu_exp,
        "VHT Link Adaptation": vht_link_adapt_map.get(vht_link_adapt, "Reserved"),
        "RX Antenna Pattern Consistency": rx_ant_cons,
        "TX Antenna Pattern Consistency": tx_ant_cons,
        "Extended NSS BW Support": ext_nss_bw_map.get(ext_nss_bw, "Reserved"),
        "Supported MCS Set (hex)": supported_mcs_set.hex(),
    }

def get_vht_capabilities(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 191:
            vht_data = elt.info
            return VHT_capabilities_information_element_parser(vht_data)
        elt = elt.payload.getlayer(Dot11Elt)
    return None


if __name__ == "__main__":
    path = input("Enter pcap filename: ")
    packets = rdpcap(path)
    print(f"Number of frames: {len(packets)}")

    start = int(input("Enter start packet number: "))
    end = int(input("Enter end packet number: "))

    results = []
    bss_count = 0
    ht_count = 0
    vht_count = 0

    for i, pkt in enumerate(packets, start=1):
        if i < start or i > end:
            continue

        if pkt.haslayer(Dot11Beacon):
            info = {}
            info['Packet #'] = i
            info['BSSID'] = pkt[Dot11].addr3
            info['SSID'] = get_ssid(pkt)
            info['Channel'] = get_channel(pkt)
            info['Band'] = channel_to_band(info['Channel'])
            info['Standard'] = get_standard(pkt)

            raw_hex = extract_bssload_hex(pkt)
            if raw_hex:
                parsed_bss = parse_bssload_bytes(raw_hex)
                info['BSS Load Raw'] = raw_hex
                if parsed_bss:
                    info.update(parsed_bss)
                    bss_count += 1
                else:
                    info['BSS Load Error'] = f"Invalid BSS Load length ({len(bytes.fromhex(raw_hex))} bytes)"

            ht_caps = get_ht_capabilities(pkt)
            if ht_caps:
                info['HT Capabilities'] = ht_caps
                ht_count += 1
            else:
                info['HT Capabilities'] = None

            vht_caps = get_vht_capabilities(pkt)
            if vht_caps:
                info['VHT Capabilities'] = vht_caps
                vht_count += 1
            else:
                info['VHT Capabilities'] = None

            results.append(info)

    # --- Print results ---
    for res in results:
        print("\n--- Beacon Frame ---")
        for k, v in res.items():
            if isinstance(v, dict):
                print(f"{k}:")
                for subk, subv in v.items():
                    print(f"   {subk}: {subv}")
            else:
                print(f"{k}: {v}")

    print(f"\nTotal beacons with BSS Load: {bss_count}")
    print(f"Total beacons with HT Capabilities: {ht_count}")
    print(f"Total beacons with VHT Capabilities: {vht_count}")

    # --- Save results to JSON ---
    output_filename = "parsed_beacons.json"
    with open(output_filename, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\nJSON output saved to {output_filename}")
