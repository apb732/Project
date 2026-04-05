from scapy.all import *
import struct
import json

QBSS_LOAD_EID = 11
HT_CAP_EID = 45
VHT_CAP_EID = 191
EXT_TAG_EID = 255
HE_CAP_EXT_ID = 35
EHT_CAP_EXT_ID = 108


def parse_qbss_load(info):
    if len(info) != 5:
        return None

    station_count = int.from_bytes(info[0:2], "little")
    channel_util = info[2]
    adc = int.from_bytes(info[3:5], "little")

    return {
        "wlan.tag": {
            "wlan.tag.number": "11",
            "wlan.tag.length": "5",
            "wlan.qbss.scount": str(station_count),
            "wlan.qbss.cu": str(channel_util),
            "wlan.qbss.adc": str(adc)
        }
    }


def extract_qbss_from_beacon(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return None

    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == QBSS_LOAD_EID:
            return parse_qbss_load(elt.info)
        elt = elt.payload.getlayer(Dot11Elt)

    return None

def parse_ht_capabilities(eid, length, info):
    if len(info) < 26:
        return None

    pos = 0

    # ----------------------------
    # HT Capabilities Info (2B)
    # ----------------------------
    ht_cap_info = struct.unpack_from("<H", info, pos)[0]
    pos += 2

    ht_cap_tree = {
        "wlan.ht.capabilities.ldpccoding": str((ht_cap_info >> 0) & 0x1),
        "wlan.ht.capabilities.width": str((ht_cap_info >> 1) & 0x1),
        "wlan.ht.capabilities.sm": hex((ht_cap_info >> 2) & 0x3),
        "wlan.ht.capabilities.green": str((ht_cap_info >> 4) & 0x1),
        "wlan.ht.capabilities.short20": str((ht_cap_info >> 5) & 0x1),
        "wlan.ht.capabilities.short40": str((ht_cap_info >> 6) & 0x1),
        "wlan.ht.capabilities.txstbc": str((ht_cap_info >> 7) & 0x1),
        "wlan.ht.capabilities.rxstbc": hex((ht_cap_info >> 8) & 0x3),
        "wlan.ht.capabilities.info_reserved_b10": hex((ht_cap_info >> 10) & 0x1),
        "wlan.ht.capabilities.amsdu": str((ht_cap_info >> 11) & 0x1),
        "wlan.ht.capabilities.dsscck": str((ht_cap_info >> 12) & 0x1),
        "wlan.ht.capabilities.info_reserved_b13": hex((ht_cap_info >> 13) & 0x1),
        "wlan.ht.capabilities.40mhzintolerant": str((ht_cap_info >> 14) & 0x1),
        "wlan.ht.capabilities.info_reserved_b15": hex((ht_cap_info >> 15) & 0x1)
    }

    # ----------------------------
    # AMPDU Parameters (1B)
    # ----------------------------
    ampdu = info[pos]
    pos += 1

    ampdu_tree = {
        "wlan.ht.ampduparam.maxlength": hex(ampdu & 0x3),
        "wlan.ht.ampduparam.mpdu_start_spacing": hex((ampdu >> 2) & 0x7),
        "wlan.ht.ampduparam.reserved": hex((ampdu >> 5) & 0x7)
    }

    # ----------------------------
    # MCS Set (16B)
    # ----------------------------
    mcs = info[pos:pos+16]
    pos += 16

    rx_mask = mcs[:10]

    rxbitmask = {
        "wlan.ht.mcsset.rxbitmask.0to7": hex(rx_mask[0]),
        "wlan.ht.mcsset.rxbitmask.8to15": hex(rx_mask[1]),
        "wlan.ht.mcsset.rxbitmask.16to23": hex(rx_mask[2]),
        "wlan.ht.mcsset.rxbitmask.24to31": hex(rx_mask[3]),
        "wlan.ht.mcsset.rxbitmask.32": hex(rx_mask[4]),
        "wlan.ht.mcsset.rxbitmask.33to38": hex(rx_mask[5]),
        "wlan.ht.mcsset.rxbitmask.39to52": hex(rx_mask[6]),
        "wlan.ht.mcsset.rxbitmask.53to76": hex(rx_mask[7])
    }

    highest_rate = struct.unpack("<H", mcs[10:12])[0]

    tx_params = mcs[12]

    mcsset = {
        "wlan.ht.mcsset.rxbitmask": rxbitmask,
        "wlan.ht.mcsset.highestdatarate": hex(highest_rate),
        "wlan.ht.mcsset.txsetdefined": str((tx_params >> 0) & 0x1),
        "wlan.ht.mcsset.txrxmcsnotequal": str((tx_params >> 1) & 0x1),
        "wlan.ht.mcsset.txmaxss": hex((tx_params >> 2) & 0x3),
        "wlan.ht.mcsset.txunequalmod": str((tx_params >> 4) & 0x1)
    }

    # ----------------------------
    # HT Extended Capabilities (2B)
    # ----------------------------
    htex = struct.unpack_from("<H", info, pos)[0]
    pos += 2

    htex_tree = {
        "wlan.htex.capabilities.reserved_b0_b7": hex(htex & 0xff),
        "wlan.htex.capabilities.mcs": hex((htex >> 8) & 0x3),
        "wlan.htex.capabilities.htc": str((htex >> 10) & 0x1),
        "wlan.htex.capabilities.rdresponder": str((htex >> 11) & 0x1),
        "wlan.htex.capabilities.reserved_b12_b15": hex((htex >> 12) & 0xf)
    }

    # ----------------------------
    # TX Beamforming (4B)
    # ----------------------------
    txbf = struct.unpack_from("<I", info, pos)[0]
    pos += 4

    txbf_tree = {
        "wlan.txbf.txbf": str((txbf >> 0) & 0x1),
        "wlan.txbf.rxss": str((txbf >> 1) & 0x3),
        "wlan.txbf.txss": str((txbf >> 3) & 0x3),
        "wlan.txbf.rxndp": str((txbf >> 5) & 0x1),
        "wlan.txbf.txndp": str((txbf >> 6) & 0x1),
        "wlan.txbf.impltxbf": str((txbf >> 7) & 0x1),
        "wlan.txbf.calibration": hex((txbf >> 8) & 0x3),
        "wlan.txbf.csi": str((txbf >> 10) & 0x1),
        "wlan.txbf.fm.uncompressed.tbf": str((txbf >> 11) & 0x1),
        "wlan.txbf.fm.compressed.tbf": str((txbf >> 12) & 0x1),
        "wlan.txbf.rcsi": hex((txbf >> 13) & 0x7),
        "wlan.txbf.fm.uncompressed.rbf": hex((txbf >> 16) & 0x3),
        "wlan.txbf.fm.compressed.bf": hex((txbf >> 18) & 0x3),
        "wlan.txbf.mingroup": hex((txbf >> 20) & 0x3),
        "wlan.txbf.csinumant": hex((txbf >> 22) & 0x3),
        "wlan.txbf.fm.uncompressed.maxant": hex((txbf >> 24) & 0x3),
        "wlan.txbf.fm.compressed.maxant": hex((txbf >> 26) & 0x3),
        "wlan.txbf.csi.maxrows": hex((txbf >> 28) & 0x3),
        "wlan.txbf.channelest": hex((txbf >> 30) & 0x3),
        "wlan.txbf.reserved": "0x00000000"
    }

    # ----------------------------
    # ASEL Capabilities (1B)
    # ----------------------------
    asel = info[pos]

    asel_tree = {
        "wlan.asel.capable": str((asel >> 0) & 0x1),
        "wlan.asel.txcsi": str((asel >> 1) & 0x1),
        "wlan.asel.txif": str((asel >> 2) & 0x1),
        "wlan.asel.csi": str((asel >> 3) & 0x1),
        "wlan.asel.if": str((asel >> 4) & 0x1),
        "wlan.asel.rx": str((asel >> 5) & 0x1),
        "wlan.asel.sppdu": str((asel >> 6) & 0x1),
        "wlan.asel.reserved": hex((asel >> 7) & 0x1)
    }

    return {
        "wlan.tag": {
            "wlan.tag.number": str(eid),
            "wlan.tag.length": str(length),

            "wlan.ht.capabilities": hex(ht_cap_info),
            "wlan.ht.capabilities_tree": ht_cap_tree,

            "wlan.ht.ampduparam": hex(ampdu),
            "wlan.ht.ampduparam_tree": ampdu_tree,

            "wlan.ht.mcsset": mcsset,

            "wlan.htex.capabilities": hex(htex),
            "wlan.htex.capabilities_tree": htex_tree,

            "wlan.txbf": hex(txbf),
            "wlan.txbf_tree": txbf_tree,

            "wlan.asel": hex(asel),
            "wlan.asel_tree": asel_tree
        }
    }
def extract_ht_capabilities(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return None

    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == HT_CAP_EID:
            return parse_ht_capabilities(
                elt.ID,
                elt.len,
                elt.info
            )
        elt = elt.payload.getlayer(Dot11Elt)

    return None


def parse_vht_capabilities_ie(vht_body: bytes):

    """
    Parse VHT Capabilities IE (Tag 191) and return Wireshark-like JSON structure.
    Input: 12-byte VHT Capabilities body (excluding ID and length)
    Output: Dictionary formatted like Wireshark JSON
    """

    if len(vht_body) != 12:
        raise ValueError("VHT Capabilities body must be exactly 12 bytes")

    # ---- Split structure ----
    vht_cap_info = struct.unpack_from("<I", vht_body, 0)[0]
    rx_mcs_map = struct.unpack_from("<H", vht_body, 4)[0]
    rx_highest = struct.unpack_from("<H", vht_body, 6)[0]
    tx_mcs_map = struct.unpack_from("<H", vht_body, 8)[0]
    tx_highest_raw = struct.unpack_from("<H", vht_body, 10)[0]

    tx_highest = tx_highest_raw & 0x1FFF   # keep bits 0–12 only

    # ---- Helper for hex formatting ----
    def hex8(val): return f"0x{val:08x}"
    def hex4(val): return f"0x{val:04x}"

    # ---- Decode VHT Capabilities Info ----
    vht_tree = {
        "wlan.vht.capabilities.maxmpdulength": hex8(vht_cap_info & 0x3),
        "wlan.vht.capabilities.supportedchanwidthset": hex8((vht_cap_info >> 2) & 0x3),
        "wlan.vht.capabilities.rxldpc": str((vht_cap_info >> 4) & 0x1),
        "wlan.vht.capabilities.short80": str((vht_cap_info >> 5) & 0x1),
        "wlan.vht.capabilities.short160": str((vht_cap_info >> 6) & 0x1),
        "wlan.vht.capabilities.txstbc": str((vht_cap_info >> 7) & 0x1),
        "wlan.vht.capabilities.rxstbc": hex8((vht_cap_info >> 8) & 0x7),
        "wlan.vht.capabilities.subeamformer": str((vht_cap_info >> 11) & 0x1),
        "wlan.vht.capabilities.subeamformee": str((vht_cap_info >> 12) & 0x1),
        "wlan.vht.capabilities.beamformee_sts_cap": hex8((vht_cap_info >> 13) & 0x7),
        "wlan.vht.capabilities.soundingdimensions": hex8((vht_cap_info >> 16) & 0x7),
        "wlan.vht.capabilities.mubeamformer": str((vht_cap_info >> 19) & 0x1),
        "wlan.vht.capabilities.mubeamformee": str((vht_cap_info >> 20) & 0x1),
        "wlan.vht.capabilities.vhttxopps": str((vht_cap_info >> 21) & 0x1),
        "wlan.vht.capabilities.vhthtc": str((vht_cap_info >> 22) & 0x1),
        "wlan.vht.capabilities.maxampdu": hex8((vht_cap_info >> 23) & 0x7),
        "wlan.vht.capabilities.linkadapt": hex8((vht_cap_info >> 26) & 0x3),
        "wlan.vht.capabilities.rxpatconsist": str((vht_cap_info >> 28) & 0x1),
        "wlan.vht.capabilities.txpatconsist": str((vht_cap_info >> 29) & 0x1),
        "wlan.vht.capabilities.ext_nss_bw_support": hex8((vht_cap_info >> 30) & 0x3),
    }

    # ---- Decode MCS Map ----
    def decode_mcs_tree(mcs_map, prefix):
        tree = {}
        for ss in range(8):
            val = (mcs_map >> (ss * 2)) & 0x3
            tree[f"{prefix}.ss{ss+1}"] = hex4(val)
        return tree

    rx_tree = decode_mcs_tree(rx_mcs_map, "wlan.vht.mcsset.rxmcsmap")
    tx_tree = decode_mcs_tree(tx_mcs_map, "wlan.vht.mcsset.txmcsmap")

    # ---- Construct Wireshark-like Output ----
    output = {
        "wlan.tag": {
            "wlan.tag.number": "191",
            "wlan.tag.length": "12",
            "wlan.vht.capabilities": hex8(vht_cap_info),
            "wlan.vht.capabilities_tree": vht_tree,
            "wlan.vht.mcsset": {
                "wlan.vht.mcsset.rxmcsmap": hex4(rx_mcs_map),
                "wlan.vht.mcsset.rxmcsmap_tree": rx_tree,
                "wlan.vht.mcsset.rxhighestlonggirate": hex4(rx_highest),
                "wlan.vht.mcsset.max_nsts_total": "0",  # Wireshark derives this
                "wlan.vht.mcsset.txmcsmap": hex4(tx_mcs_map),
                "wlan.vht.mcsset.txmcsmap_tree": tx_tree,
                "wlan.vht.mcsset.txhighestlonggirate": hex4(tx_highest),
                "wlan.vht.mcsset.vht_ext_nss_bw_capable": str((tx_highest_raw >> 13) & 0x1),
                "wlan.vht.mcsset.reserved": "0x0000"
            }
        }
    }

    return output

def extract_vht_capabilities(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return None

    elt = pkt.getlayer(Dot11Elt)

    while isinstance(elt, Dot11Elt):
        if elt.ID == VHT_CAP_EID:
            length = elt.len
            body = bytes(elt.info)[:length]   # enforce exact length
            return parse_vht_capabilities_ie(body)

        elt = elt.payload.getlayer(Dot11Elt)

    return None

def parse_he_capabilities(he_body: bytes) -> dict:
    """
    Fully Wireshark-aligned HE Capabilities parser.
    Expects body excluding Element ID / Length / Ext ID.
    """

    result = {}

    # =====================================================
    # HE MAC CAPABILITIES (6 bytes)
    # =====================================================
    mac_bytes = he_body[0:6]
    mac = int.from_bytes(mac_bytes, "little")

    mac_tree = {}

    # Bits 0–23
    mac_tree["wlan.ext_tag.he_mac_cap.htc_he_support"] = str((mac >> 0) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.twt_req_support"] = str((mac >> 1) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.twt_rsp_support"] = str((mac >> 2) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.dynamic_fragmentation_support"] = str((mac >> 3) & 0x3)
    mac_tree["wlan.ext_tag.he_mac_cap.max_frag_msdus"] = str((mac >> 5) & 0x7)
    mac_tree["wlan.ext_tag.he_mac_cap.min_frag_size"] = str((mac >> 8) & 0x3)
    mac_tree["wlan.ext_tag.he_mac_cap.trig_frm_mac_padding_dur"] = str((mac >> 10) & 0x3)
    mac_tree["wlan.ext_tag.he_mac_cap.multi_tid_agg_rx_support"] = str((mac >> 12) & 0x7)
    mac_tree["wlan.ext_tag.he_mac_cap.he_link_adaptation_support"] = str((mac >> 15) & 0x3)
    mac_tree["wlan.ext_tag.he_mac_cap.all_ack_support"] = str((mac >> 17) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.trs_support"] = str((mac >> 18) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.bsr_support"] = str((mac >> 19) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.broadcast_twt_support"] = str((mac >> 20) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.32_bit_ba_bitmap_support"] = str((mac >> 21) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.mu_cascading_support"] = str((mac >> 22) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.ack_enabled_agg_support"] = str((mac >> 23) & 1)

    # Reserved bit 24
    mac_tree["wlan.ext_tag.he_mac_cap.reserved_b24"] = \
        f"0x{((mac >> 24) & 1):016x}"

    # Bits 25–47
    mac_tree["wlan.ext_tag.he_mac_cap.om_control_support"] = str((mac >> 25) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.ofdma_ra_support"] = str((mac >> 26) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.max_a_mpdu_len_exp_ext"] = str((mac >> 27) & 0x3)
    mac_tree["wlan.ext_tag.he_mac_cap.a_msdu_frag_support"] = str((mac >> 29) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.flexible_twt_sched_support"] = str((mac >> 30) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.rx_ctl_frm_multibss"] = str((mac >> 31) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.bsrp_bqrp_a_mpdu_agg"] = str((mac >> 32) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.qtp_support"] = str((mac >> 33) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.bqr_support"] = str((mac >> 34) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.psr_responder"] = str((mac >> 35) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.ndp_feedback_report_support"] = str((mac >> 36) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.ops_support"] = str((mac >> 37) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.a_msdu_in_a_mpdu_support"] = str((mac >> 38) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.multi_tid_agg_tx_support"] = str((mac >> 39) & 0x7)
    mac_tree["wlan.ext_tag.he_mac_cap.subchannel_selective_xmit_support"] = str((mac >> 42) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.ul_2_996_tone_ru_support"] = str((mac >> 43) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.om_cntl_ul_mu_data_disable_rx_support"] = str((mac >> 44) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.dynamic_sm_power_save"] = str((mac >> 45) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.punctured_sounding_support"] = str((mac >> 46) & 1)
    mac_tree["wlan.ext_tag.he_mac_cap.ht_and_vht_trigger_frame_rx_support"] = str((mac >> 47) & 1)

    result["wlan.ext_tag.he_mac_caps"] = f"0x{mac:016x}"
    result["wlan.ext_tag.he_mac_caps_tree"] = mac_tree

    # =====================================================
    # HE PHY CAPABILITIES (11 bytes = 88 bits)
    # =====================================================
    phy = he_body[6:17]
    phy_val = int.from_bytes(phy, "little")

    def bits(start, length):
        return (phy_val >> start) & ((1 << length) - 1)

    phy_tree = {}

    # -----------------------------------------------------
    # Byte 0 (B0–B7)
    # -----------------------------------------------------
    phy_tree["wlan.ext_tag.he_phy_cap.reserved_b0"] = f"0x{phy[0]:02x}"
    phy_tree["wlan.ext_tag.he_phy_cap.reserved_b0_tree"] = {
        "wlan.ext_tag.he_phy_cap.fbyte.reserved_b0": f"0x{phy[0]:02x}"
    }

    # -----------------------------------------------------
    # Byte 1 (B8–B15)
    # -----------------------------------------------------
    fbyte = phy[1]
    phy_tree["wlan.ext_tag.he_phy_cap.fbytes"] = f"0x{fbyte:02x}"
    phy_tree["wlan.ext_tag.he_phy_cap.fbytes_tree"] = {
        "wlan.ext_tag.he_phy_cap.chan_width.set.5GHz_b0_reserved": f"0x{bits(8, 1):02x}",
        "wlan.ext_tag.he_phy_cap.chan_width_set.40_80_in_5ghz": str(bits(9, 1)),
        "wlan.ext_tag.he_phy_cap.chan_width_set.160_in_5ghz": str(bits(10, 1)),
        "wlan.ext_tag.he_phy_cap.chan_width_set.160_80_80_in_5ghz": str(bits(11, 1)),
        "wlan.ext_tag.he_phy_cap.chan_width.set.5GHz_b4_reserved": f"0x{bits(12, 1):02x}",
        "wlan.ext_tag.he_phy_cap.chan_width_set.242_tone_in_5ghz": str(bits(13, 1)),
        "wlan.ext_tag.he_phy_cap.chan_width_set.reserved": f"0x{bits(14, 2):02x}"
    }

    # -----------------------------------------------------
    # Bits 8–23
    # -----------------------------------------------------
    b8_23 = bits(8, 16)
    phy_tree["wlan.ext_tag.he_phy_cap.bits_8_to_23"] = f"0x{b8_23:04x}"
    phy_tree["wlan.ext_tag.he_phy_cap.bits_8_to_23_tree"] = {
        "wlan.ext_tag.he_phy_cap.punc_preamble_rx": f"0x{bits(8, 2):04x}",
        "wlan.ext_tag.he_phy_cap.device_class": f"0x{bits(10, 1):04x}",
        "wlan.ext_tag.he_phy_cap.ldpc_coding_in_payload": str(bits(11, 1)),
        "wlan.ext_tag.he_phy_cap.he_su_ppdu_with_1x_he_ltf_08us": str(bits(12, 1)),
        "wlan.ext_tag.he_phy_cap.midamble_tx_rx_max_nsts": f"0x{bits(13, 2):04x}",
        "wlan.ext_tag.he_phy_cap.ndp_with_4x_he_ltf_4x_3.2us": str(bits(15, 1)),
        "wlan.ext_tag.he_phy_cap.stbc_tx_lt_80mhz": str(bits(16, 1)),
        "wlan.ext_tag.he_phy_cap.stbc_rx_lt_80mhz": str(bits(17, 1)),
        "wlan.ext_tag.he_phy_cap.doppler_tx": str(bits(18, 1)),
        "wlan.ext_tag.he_phy_cap.doppler_rx": str(bits(19, 1)),
        "wlan.ext_tag.he_phy_cap.full_bw_ul_mu_mimo": str(bits(20, 1)),
        "wlan.ext_tag.he_phy_cap.partial_bw_ul_mu_mimo": str(bits(21, 1)),
    }

    # -----------------------------------------------------
    # Bits 24–39
    # -----------------------------------------------------
    b24_39 = bits(24, 16)
    phy_tree["wlan.ext_tag.he_phy_cap.bits_24_to_39"] = f"0x{b24_39:04x}"
    phy_tree["wlan.ext_tag.he_phy_cap.bits_24_to_39_tree"] = {
        "wlan.ext_tag.he_phy_cap.dcm_max_const_tx": f"0x{bits(24, 2):04x}",
        "wlan.ext_tag.he_phy_cap.dcm_max_nss_tx": f"0x{bits(26, 1):04x}",
        "wlan.ext_tag.he_phy_cap.dcm_max_const_rx": f"0x{bits(27, 2):04x}",
        "wlan.ext_tag.he_phy_cap.dcm_max_nss_rx": f"0x{bits(29, 1):04x}",
        "wlan.ext_tag.he_phy_cap.rx_partial_bw_su_20mhz_he_mu_ppdu": str(bits(30, 1)),
        "wlan.ext_tag.he_phy_cap.su_beamformer": str(bits(31, 1)),
        "wlan.ext_tag.he_phy_cap.su_beamformee": str(bits(32, 1)),
        "wlan.ext_tag.he_phy_cap.mu_beamformer": str(bits(33, 1)),
        "wlan.ext_tag.he_phy_cap.beamformee_sts_lte_80mhz": f"0x{bits(34, 3):04x}",
        "wlan.ext_tag.he_phy_cap.beamformee_sts_gt_80mhz": f"0x{bits(37, 3):04x}",
    }

    # -----------------------------------------------------
    # Bits 40–55
    # -----------------------------------------------------
    b40_55 = bits(40, 16)
    phy_tree["wlan.ext_tag.he_phy_cap.bits_40_to_55"] = f"0x{b40_55:04x}"
    phy_tree["wlan.ext_tag.he_phy_cap.bits_40_to_55_tree"] = {
        "wlan.ext_tag.he_phy_cap.no_sounding_dims_lte_80": str(bits(40, 3)),
        "wlan.ext_tag.he_phy_cap.no_sounding_dims_gt_80": str(bits(43, 3)),
        "wlan.ext_tag.he_phy_cap.ng_eq_16_su_fb": str(bits(46, 1)),
        "wlan.ext_tag.he_phy_cap.ng_eq_16_mu_fb": str(bits(47, 1)),
        "wlan.ext_tag.he_phy_cap.codebook_size_su_fb": str(bits(48, 1)),
        "wlan.ext_tag.he_phy_cap.codebook_size_mu_fb": str(bits(49, 1)),
        "wlan.ext_tag.he_phy_cap.trig_su_bf_fb": str(bits(50, 1)),
        "wlan.ext_tag.he_phy_cap.trig_mu_bf_fb": str(bits(51, 1)),
        "wlan.ext_tag.he_phy_cap.trig_cqi_fb": str(bits(52, 1)),
        "wlan.ext_tag.he_phy_cap.partial_bw_er": str(bits(53, 1)),
        "wlan.ext_tag.he_phy_cap.partial_bw_dl_mu_mimo": str(bits(54, 1)),
        "wlan.ext_tag.he_phy_cap.ppe_thres_present": str(bits(55, 1)),
    }

    # -----------------------------------------------------
    # Bits 56–71
    # -----------------------------------------------------
    b56_71 = bits(56, 16)
    phy_tree["wlan.ext_tag.he_phy_cap.bits_56_to_71"] = f"0x{b56_71:04x}"
    phy_tree["wlan.ext_tag.he_phy_cap.bits_56_to_71_tree"] = {
        "wlan.ext_tag.he_phy_cap.psr_based_sr_sup": str(bits(56, 1)),
        "wlan.ext_tag.he_phy_cap.pwr_bst_factor_ar_sup": str(bits(57, 1)),
        "wlan.ext_tag.he_phy_cap.he_su_ppdu_etc_gi": str(bits(58, 1)),
        "wlan.ext_tag.he_phy_cap.max_nc": str(bits(59, 3)),
        "wlan.ext_tag.he_phy_cap.stbc_tx_gt_80_mhz": str(bits(62, 1)),
        "wlan.ext_tag.he_phy_cap.stbc_rx_gt_80_mhz": str(bits(63, 1)),
        "wlan.ext_tag.he_phy_cap.he_er_su_ppdu_4xxx_gi": str(bits(64, 1)),
        "wlan.ext_tag.he_phy_cap.20_mhz_in_40_in_2_4ghz": str(bits(65, 1)),
        "wlan.ext_tag.he_phy_cap.20_mhz_in_160_80p80_ppdu": str(bits(66, 1)),
        "wlan.ext_tag.he_phy_cap.80_mhz_in_160_80p80_ppdu": str(bits(67, 1)),
        "wlan.ext_tag.he_phy_cap.he_er_su_ppdu_1xxx_gi": str(bits(68, 1)),
        "wlan.ext_tag.he_phy_cap.midamble_tx_rx_2x_1x_he_ltf": str(bits(69, 1)),
        "wlan.ext_tag.he_phy_cap.dcm_max_ru": f"0x{bits(70, 2):04x}",
    }

    # -----------------------------------------------------
    # Bits 72–87
    # -----------------------------------------------------
    b72_87 = bits(72, 16)
    phy_tree["wlan.ext_tag.he_phy_cap.bits_72_to_87"] = f"0x{b72_87:04x}"
    phy_tree["wlan.ext_tag.he_phy_cap.bits_72_to_87_tree"] = {
        "wlan.ext_tag.he_phy_cap.longer_than_16_he_sigb_ofdm_sym_support": str(bits(72, 1)),
        "wlan.ext_tag.he_phy_cap.non_triggered_feedback": str(bits(73, 1)),
        "wlan.ext_tag.he_phy_cap.tx_1024_qam_support_lt_242_tone_ru": str(bits(74, 1)),
        "wlan.ext_tag.he_phy_cap.rx_1024_qam_support_lt_242_tone_ru": str(bits(75, 1)),
        "wlan.ext_tag.he_phy_cap.rx_full_bw_su_using_he_mu_ppdu_with_compressed_sigb": str(bits(76, 1)),
        "wlan.ext_tag.he_phy_cap.rx_full_bw_su_using_he_mu_ppdu_with_non_compressed_sigb": str(bits(77, 1)),
        "wlan.ext_tag.he_phy_cap.nominal_packet_padding": str(bits(78, 2)),
        "wlan.ext_tag.he_phy_cap.he_mu_ppdu_ru_rx_max": str(bits(80, 3)),
        "wlan.ext_tag.he_phy_cap.reserved_b81_b87": f"0x{bits(81, 7):04x}",
    }

    result["HE PHY Capabilities Information"] = phy_tree

    # =====================================================
    # HE MCS (≤80 MHz)
    # =====================================================
    offset = 17
    rx_map = int.from_bytes(he_body[offset:offset+2], "little")
    tx_map = int.from_bytes(he_body[offset+2:offset+4], "little")

    mcs_rx_tree = {}
    mcs_tx_tree = {}

    for ss in range(8):
        mcs_rx_tree[f"wlan.ext_tag.he_mcs_map.max_he_mcs_80_rx_{ss+1}_ss"] = \
            f"0x{(rx_map >> (2*ss)) & 0x3:04x}"
        mcs_tx_tree[f"wlan.ext_tag.he_mcs_map.max_he_mcs_80_tx_{ss+1}_ss"] = \
            f"0x{(tx_map >> (2*ss)) & 0x3:04x}"

    result["Supported HE-MCS and NSS Set"] = {
        "Rx and Tx MCS Maps <= 80 MHz": {
            "wlan.ext_tag.he_mcs_map.rx_he_mcs_map_lte_80": f"0x{rx_map:04x}",
            "wlan.ext_tag.he_mcs_map.rx_he_mcs_map_lte_80_tree": mcs_rx_tree,
            "wlan.ext_tag.he_mcs_map.tx_he_mcs_map_lte_80": f"0x{tx_map:04x}",
            "wlan.ext_tag.he_mcs_map.tx_he_mcs_map_lte_80_tree": mcs_tx_tree
        }
    }

    return result


def extract_he_capabilities(pkt):
    if not pkt.haslayer(Dot11Beacon):
        return None

    elt = pkt.getlayer(Dot11Elt)

    while isinstance(elt, Dot11Elt):

        # HE is EXTENSION TAG (255)
        if elt.ID == EXT_TAG_EID:

            body = bytes(elt.info)

            if len(body) < 1:
                return None

            ext_id = body[0]

            # Check if this is HE Capabilities (Ext ID 35)
            if ext_id == HE_CAP_EXT_ID:
                he_body = body[1:]  # remove extension ID byte

                parsed = parse_he_capabilities(he_body)

                return {
                    "wlan.tag": {
                        "wlan.tag.number": "255",
                        "wlan.tag.length": str(elt.len),
                        "wlan.tag.ext_id": "35",
                        **parsed
                    }
                }

        elt = elt.payload.getlayer(Dot11Elt)

    return None

def parse_eht_capabilities(eht_body: bytes) -> dict:
    """
    Parse EHT Capabilities (802.11be) body.
    Input: body excluding Element ID / Length / Extension ID
    Output: Wireshark-like JSON dictionary
    """

    result = {}

    # -------------------------------------------------
    # EHT MAC CAPABILITIES (2 bytes)
    # -------------------------------------------------
    mac = int.from_bytes(eht_body[0:2], "little")

    mac_tree = {
        "wlan.eht.mac_capabilities.epcs_priority_access_support": str((mac >> 0) & 1),
        "wlan.eht.mac_capabilities.eht_om_control_support": str((mac >> 1) & 1),
        "wlan.eht.mac_capabilities.triggered_txop_sharing_mode_1_support": str((mac >> 2) & 1),
        "wlan.eht.mac_capabilities.triggered_txop_sharing_mode_2_support": str((mac >> 3) & 1),
        "wlan.eht.mac_capabilities.restricted_twt_support": str((mac >> 4) & 1),
        "wlan.eht.mac_capabilities.scs_traffic_description_support": str((mac >> 5) & 1),
        "wlan.eht.mac_capabilities.maximum_mpdu_length": hex((mac >> 6) & 0x3),
        "wlan.eht.mac_capabilities.maximum_a_mpdu_length_exponent_extension": str((mac >> 8) & 0x3),
        "wlan.eht.mac_capabilities.eht_trs_support": str((mac >> 10) & 1),
        "wlan.eht.mac_capabilities.txop_return_support_in_txop_sharing_mode_2": str((mac >> 11) & 1),
        "wlan.eht.mac_capabilities.two_bqrs_support": str((mac >> 12) & 1),
        "wlan.eht.mac_capabilities.eht_link_adaptation_support": str((mac >> 13) & 1),
        "wlan.eht.mac_capabilities.unsolicited_epcs_prio_access_para_update": str((mac >> 14) & 1),
        "wlan.eht.mac_capabilities.reserved": hex((mac >> 15) & 0x1)
    }

    result["wlan.eht.mac_capabilities_info"] = hex(mac)
    result["wlan.eht.mac_capabilities_info_tree"] = mac_tree

    # -------------------------------------------------
    # EHT PHY CAPABILITIES (9 bytes)
    # -------------------------------------------------
    phy = int.from_bytes(eht_body[2:11], "little")

    bits_0_15 = phy & 0xFFFF
    bits_16_31 = (phy >> 16) & 0xFFFF
    bits_32_39 = (phy >> 32) & 0xFF
    bits_40_63 = (phy >> 40) & 0xFFFFFF
    bits_64_71 = int.from_bytes(eht_body[10:13].ljust(3, b"\x00"), "little")


    phy_caps = {}

    # -------- bits 0–15 --------
    phy_caps["wlan.eht.phy_capabilities.bits_0_15"] = hex(bits_0_15)
    phy_caps["wlan.eht.phy_capabilities.bits_0_15_tree"] = {
        "wlan.eht.phy_capabilities.bits_0_15.reserved": hex(bits_0_15 & 0x1),
        "wlan.eht.phy_capabilities.bits_0_15.support_for_320mhz_in_6ghz": str((bits_0_15 >> 1) & 1),
        "wlan.eht.phy_capabilities.bits_0_15.support_for_242_tone_ru_in_bw_wider_20mhz": str((bits_0_15 >> 2) & 1),
        "wlan.eht.phy_capabilities.bits_0_15.ndp_with_4x_eht_ltf_and_3_2_us_gi": str((bits_0_15 >> 3) & 1),
        "wlan.eht.phy_capabilities.bits_0_15.partial_bandwidth_ul_mu_mimo": str((bits_0_15 >> 4) & 1),
        "wlan.eht.phy_capabilities.bits_0_15.su_beamformer": str((bits_0_15 >> 5) & 1),
        "wlan.eht.phy_capabilities.bits_0_15.su_beamformee": str((bits_0_15 >> 6) & 1),
        "wlan.eht.phy_capabilities.bits_0_15.beamformee_ss_le_80mhz": hex((bits_0_15 >> 7) & 0x7),
        "wlan.eht.phy_capabilities.bits_0_15.beamformee_ss_eq_160mhz": hex((bits_0_15 >> 10) & 0x7),
        "wlan.eht.phy_capabilities.bits_0_15.beamformee_ss_eq_320_mhz": hex((bits_0_15 >> 13) & 0x7),
    }

    # -------- bits 16–31 --------
    phy_caps["wlan.eht.phy_capabilities.bits_16_31"] = hex(bits_16_31)
    phy_caps["wlan.eht.phy_capabilities.bits_16_31_tree"] = {
        "wlan.eht.phy_capabilities.bits_16_31.number_of_sounding_dims_le_80_mhz": hex(bits_16_31 & 0x7),
        "wlan.eht.phy_capabilities.bits_16_31.number_of_sounding_dims_eq_160_mhz": hex((bits_16_31 >> 3) & 0x7),
        "wlan.eht.phy_capabilities.bits_16_31.number_of_sounding_dims_eq_320_mhz": hex((bits_16_31 >> 6) & 0x7),
        "wlan.eht.phy_capabilities.bits_16_31.ng_eq_16_su_fbck": str((bits_16_31 >> 9) & 1),
        "wlan.eht.phy_capabilities.bits_16_31.ng_eq_16_mu_fbck": str((bits_16_31 >> 10) & 1),
        "wlan.eht.phy_capabilities.bits_16_31.codebook_size_eq_4_2_su_fbck": str((bits_16_31 >> 11) & 1),
        "wlan.eht.phy_capabilities.bits_16_31.codebook_size_eq_7_5_mu_fbck": str((bits_16_31 >> 12) & 1),
        "wlan.eht.phy_capabilities.bits_16_31.triggered_su_beamforming_fbck": str((bits_16_31 >> 13) & 1),
        "wlan.eht.phy_capabilities.bits_16_31.triggered_mu_beamforming_partial_fbck": str((bits_16_31 >> 14) & 1),
        "wlan.eht.phy_capabilities.bits_16_31.triggered_cqi_fbck": str((bits_16_31 >> 15) & 1),
    }

    # -------- bits 32–39 --------
    phy_caps["wlan.eht.phy_capabilities.bits_32_39"] = hex(bits_32_39)
    phy_caps["wlan.eht.phy_capabilities.bits_32_39_tree"] = {
        "wlan.eht.phy_capabilities.bits_32_39.partial_bw_dl_mu_mimo": str(bits_32_39 & 1),
        "wlan.eht.phy_capabilities.bits_32_39.eht_psr_based_sr_support": str((bits_32_39 >> 1) & 1),
        "wlan.eht.phy_capabilities.bits_32_39.power_boost_factor_support": str((bits_32_39 >> 2) & 1),
        "wlan.eht.phy_capabilities.bits_32_39.eht_mu_ppdu_w_4x_eht_ltf_08_us_gi": str((bits_32_39 >> 3) & 1),
        "wlan.eht.phy_capabilities.bits_32_39.max_nc": str((bits_32_39 >> 4) & 0x7),
    }

    # -------- bits 40–63 --------
    phy_caps["wlan.eht.phy_capabilities.bits_40_63"] = hex(bits_40_63)

    # (individual flags simplified here)
    phy_caps["wlan.eht.phy_capabilities.bits_40_63_tree"] = {
        "wlan.eht.phy_capabilities.bits_40_63.non_triggered_cqi_fbck": str((bits_40_63 >> 0) & 1),
        "wlan.eht.phy_capabilities.bits_40_63.tx_1024_4096_qam_lt_242_ru_support": str((bits_40_63 >> 1) & 1),
        "wlan.eht.phy_capabilities.bits_40_63.rx_1024_4096_qam_lt_242_ru_support": str((bits_40_63 >> 2) & 1),
        "wlan.eht.phy_capabilities.bits_40_63.ppe_thresholds_present": str((bits_40_63 >> 3) & 1),
        "wlan.eht.phy_capabilities.bits_40_63.common_nominal_packet_padding": str((bits_40_63 >> 4) & 0x3),
        "wlan.eht.phy_capabilities.bits_40_63.max_num_supported_eht_ltfs": str((bits_40_63 >> 6) & 0x3),
        "wlan.eht.phy_capabilities.bits_40_63.support_of_mcs_15": str((bits_40_63 >> 9) & 1),
        "wlan.eht.phy_capabilities.bits_40_63.support_eht_dup_6_ghz": str((bits_40_63 >> 15) & 1),
        "wlan.eht.phy_capabilities.bits_40_63.support_20_mhz_sta_recv_ndp_wider_bw": str((bits_40_63 >> 16) & 1),

        "wlan.eht.phy_capabilities.bits_40_63.non_ofdma_ul_mu_mimo_bw_lt_80_mhz": str((bits_40_63 >> 17) & 1),
        "wlan.eht.phy_capabilities.bits_40_63.non_ofdma_ul_mu_mimo_bw_eq_160_mhz": str((bits_40_63 >> 18) & 1),
        "wlan.eht.phy_capabilities.bits_40_63.non_ofdma_ul_mu_mimo_bw_eq_320_mhz": str((bits_40_63 >> 19) & 1),

        "wlan.eht.phy_capabilities.bits_40_63.mu_beamformer_bw_le_80_mhz": str((bits_40_63 >> 20) & 1),
        "wlan.eht.phy_capabilities.bits_40_63.mu_beamformer_bw_eq_160_mhz": str((bits_40_63 >> 21) & 1),
        "wlan.eht.phy_capabilities.bits_40_63.mu_beamformer_bw_eq_320_mhz": str((bits_40_63 >> 22) & 1),

        "wlan.eht.phy_capabilities.bits_40_63.tb_sounding_fbck_rate_limit": str((bits_40_63 >> 23) & 1),

    }

    # -------- bits 64–71 --------
    phy_caps["wlan.eht.phy_capabilities.bits_64_71"] = hex(bits_64_71)
    phy_caps["wlan.eht.phy_capabilities.bits_64_71_tree"] = {
        "wlan.eht.phy_capabilities.bits_64_71.rx_1024_qam_in_wider_bw_dl_ofdma": str(bits_64_71 & 1),
        "wlan.eht.phy_capabilities.bits_64_71.rx_4096_qam_in_wider_bw_dl_ofdma": str((bits_64_71 >> 1) & 1),
        "wlan.eht.phy_capabilities.bits_64_71.20m_only_limited_capabilities": str((bits_64_71 >> 2) & 1),
        "wlan.eht.phy_capabilities.bits_64_71.20m_only_trig_mu_beamforming_dl_mu_mimo": str((bits_64_71 >> 3) & 1),
        "wlan.eht.phy_capabilities.bits_64_71.20m_only_mru_support": str((bits_64_71 >> 4) & 1),
        "wlan.eht.phy_capabilities.bits_64_71.reserved": hex((bits_64_71 >> 5) & 0x7),
    }

    result["EHT PHY Capabilities Information"] = phy_caps

    # -------------------------------------------------
    # SUPPORTED EHT MCS / NSS SET (3 bytes)
    # -------------------------------------------------
    mcs = int.from_bytes(eht_body[11:14], "little")

    mcs_tree = {
        "wlan.eht.supported_eht_mcs_bss_set.le_80.rx_max_nss_supports_eht_mcs_0_9": str(mcs & 0xF),
        "wlan.eht.supported_eht_mcs_bss_set.le_80.tx_max_nss_supports_eht_mcs_0_9": str((mcs >> 4) & 0xF),
        "wlan.eht.supported_eht_mcs_bss_set.le_80.rx_max_nss_supports_eht_mcs_10_11": str((mcs >> 8) & 0xF),
        "wlan.eht.supported_eht_mcs_bss_set.le_80.tx_max_nss_supports_eht_mcs_10_11": str((mcs >> 12) & 0xF),
        "wlan.eht.supported_eht_mcs_bss_set.le_80.rx_max_nss_supports_eht_mcs_12_13": str((mcs >> 16) & 0xF),
        "wlan.eht.supported_eht_mcs_bss_set.le_80.tx_max_nss_supports_eht_mcs_12_13": str((mcs >> 20) & 0xF),
    }

    result["Supported EHT-MCS and NSS Set"] = {
        "wlan.eht.supported_eht_mcs_bss_set.eht_mcs_map_bw_le_80_mhz": hex(mcs),
        "wlan.eht.supported_eht_mcs_bss_set.eht_mcs_map_bw_le_80_mhz_tree": mcs_tree
    }

    return result

def extract_eht_capabilities(pkt):

    if not pkt.haslayer(Dot11Beacon):
        return None

    elt = pkt.getlayer(Dot11Elt)

    while isinstance(elt, Dot11Elt):

        if elt.ID == EXT_TAG_EID:

            body = bytes(elt.info)

            if len(body) < 1:
                return None

            ext_id = body[0]

            if ext_id == EHT_CAP_EXT_ID:

                eht_body = body[1:]

                parsed = parse_eht_capabilities(eht_body)

                return {
                    "wlan.ext_tag": {
                        "wlan.ext_tag.length": str(elt.len),
                        "wlan.ext_tag.number": "108",
                        **parsed
                    }
                }

        elt = elt.payload.getlayer(Dot11Elt)

    return None

def get_ssid(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0:
            raw = bytes(elt.info)
            return ":".join(f"{b:02x}" for b in raw)
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
    he_count = 0
    eht_count = 0

    for i, pkt in enumerate(packets, start=1):
        if i < start or i > end:
            continue

        if pkt.haslayer(Dot11Beacon):

            packet_entry = {
                "_source": {
                    "layers": {
                        "frame": {
                            "frame.number": str(i)
                        },
                        "wlan": {}
                    }
                }
            }

            wlan_layer = packet_entry["_source"]["layers"]["wlan"]

            # BSSID
            wlan_layer["wlan.bssid"] = pkt[Dot11].addr3

            # SSID
            ssid = get_ssid(pkt)
            if ssid:
                wlan_layer["wlan.ssid"] = ssid

            # BSS Load
            parsed_qbss = extract_qbss_from_beacon(pkt)
            if parsed_qbss:
                if "wlan.tag" not in wlan_layer:
                    wlan_layer["wlan.tag"] = []

                wlan_layer["wlan.tag"].append(parsed_qbss["wlan.tag"])
                bss_count += 1


            # HT Capabilities
            ht_caps = extract_ht_capabilities(pkt)
            if ht_caps:
                if "wlan.tag" not in wlan_layer:
                    wlan_layer["wlan.tag"] = []

                wlan_layer["wlan.tag"].append(ht_caps["wlan.tag"])
                ht_count += 1

            # VHT Capabilities
            vht_caps = extract_vht_capabilities(pkt)
            if vht_caps:
                if "wlan.tag" not in wlan_layer:
                    wlan_layer["wlan.tag"] = []
                wlan_layer["wlan.tag"].append(vht_caps["wlan.tag"])
                vht_count += 1

            # HE Capabilities
            he_caps = extract_he_capabilities(pkt)
            if he_caps:
                if "wlan.tag" not in wlan_layer:
                    wlan_layer["wlan.tag"] = []

                wlan_layer["wlan.tag"].append(he_caps["wlan.tag"])
                he_count += 1

            # EHT Capabilities
            eht_caps = extract_eht_capabilities(pkt)
            if eht_caps:
                if "wlan.tag" not in wlan_layer:
                    wlan_layer["wlan.tag"] = []

                wlan_layer["wlan.tag"].append(eht_caps["wlan.ext_tag"])
                eht_count += 1

            results.append(packet_entry)


            
 

    print(f"\nTotal beacons with BSS Load: {bss_count}")
    print(f"Total beacons with HT Capabilities: {ht_count}")
    print(f"Total beacons with VHT Capabilities: {vht_count}")
    print(f"Total beacons with HE Capabilities: {he_count}")
    print(f"Total beacons with EHT Capabilities: {eht_count}")



    # --- Save results to JSON ---
    output_filename = "parsed_beacons_LLM.json"
    with open(output_filename, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\nJSON output saved to {output_filename}")
