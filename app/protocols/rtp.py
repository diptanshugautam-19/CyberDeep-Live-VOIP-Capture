import struct
import math

# G.711 PCMU/PCMA is 8000Hz. Opus is typically 48000Hz. G.722 is 16000Hz.
PAYLOAD_SAMPLE_RATES = {
    0: 8000,   # PCMU
    3: 8000,   # GSM
    4: 8000,   # G723
    8: 8000,   # PCMA
    9: 16000,  # G722
    18: 8000,  # G729
    96: 48000, # Dynamic / Opus (often)
    97: 48000,
}


def parse_rtp_header(payload_bytes: bytes) -> dict | None:
    """Parse RTP packet header.

    RTP Header format:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |V=2|P|X|  CC   |M|     PT      |       sequence number         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           timestamp                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           synchronization source (SSRC) identifier            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    if len(payload_bytes) < 12:
        return None

    # Parse version and CC
    v_p_x_cc = payload_bytes[0]
    version = (v_p_x_cc & 0xC0) >> 6
    if version != 2:
        return None

    padding = (v_p_x_cc & 0x20) >> 5
    extension = (v_p_x_cc & 0x10) >> 4
    cc = v_p_x_cc & 0x0F

    # Parse marker and payload type
    m_pt = payload_bytes[1]
    marker = (m_pt & 0x80) >> 7
    payload_type = m_pt & 0x7F

    seq_num = struct.unpack(">H", payload_bytes[2:4])[0]
    timestamp = struct.unpack(">I", payload_bytes[4:8])[0]
    ssrc = struct.unpack(">I", payload_bytes[8:12])[0]

    return {
        "version": version,
        "padding": bool(padding),
        "extension": bool(extension),
        "cc": cc,
        "marker": bool(marker),
        "payload_type": payload_type,
        "sequence_number": seq_num,
        "timestamp": timestamp,
        "ssrc": ssrc,
        "header_length": 12 + cc * 4,
    }


def compute_qos_metrics(
    sequence_numbers: list[int],
    timestamps: list[int],
    arrival_timestamps: list[float],
    payload_types: list[int],
    latency_ms: float = 30.0,
) -> dict:
    """Compute QoS metrics (Jitter, Packet Loss, MOS) from packet streams.

    Args:
        sequence_numbers: List of RTP sequence numbers
        timestamps: List of RTP packet timestamps
        arrival_timestamps: List of arrival epoch times (float seconds)
        payload_types: List of payload types per packet
        latency_ms: One-way network latency estimate in milliseconds (default 30ms)

    Returns:
        QosMetrics dict containing jitter_ms, packet_loss_pct, mos_score, and mos_label
    """
    if not sequence_numbers or len(sequence_numbers) < 2:
        return {
            "jitter_ms": 0.0,
            "packet_loss_pct": 0.0,
            "mos_score": 4.5,
            "mos_label": "Excellent",
        }

    # Packet loss calculation
    seq_min = min(sequence_numbers)
    seq_max = max(sequence_numbers)

    # Handle sequence number rollover (16-bit unsigned int wraps at 65535)
    # If the span is extremely large, assume a rollover happened
    if seq_max - seq_min > 40000:
        # Simple rollover normalization
        adjusted_seqs = []
        for s in sequence_numbers:
            adjusted_seqs.append(s + 65536 if s < 32768 else s)
        seq_min = min(adjusted_seqs)
        seq_max = max(adjusted_seqs)

    expected_packets = seq_max - seq_min + 1
    actual_packets = len(set(sequence_numbers))
    lost_packets = max(0, expected_packets - actual_packets)
    loss_fraction = lost_packets / expected_packets

    # Jitter calculation (RFC 3550)
    jitter = 0.0
    # Guess sample rate from the most common payload type
    from collections import Counter
    common_pt = Counter(payload_types).most_common(1)[0][0]
    sample_rate = PAYLOAD_SAMPLE_RATES.get(common_pt, 8000)

    # Sort inputs by sequence numbers to get chronologically correct spacing
    paired = sorted(
        zip(sequence_numbers, timestamps, arrival_timestamps),
        key=lambda x: x[0]
    )

    for i in range(1, len(paired)):
        prev_seq, prev_rtp, prev_arr = paired[i-1]
        curr_seq, curr_rtp, curr_arr = paired[i]

        # Ignore rollovers or out-of-order packets for delta calculation
        if curr_seq != prev_seq + 1:
            continue

        time_delta_arrival = curr_arr - prev_arr
        time_delta_rtp = (curr_rtp - prev_rtp) / sample_rate

        # Difference in transit time
        transit_diff = abs(time_delta_arrival - time_delta_rtp)
        jitter = jitter + (transit_diff - jitter) / 16.0

    jitter_ms = jitter * 1000.0

    # MOS Score estimation (ITU-T G.107 E-model approximation)
    # Effective latency (d) = latency_ms + 2 * jitter_ms
    d = latency_ms + 2.0 * jitter_ms

    # Impairment due to delay/jitter (Id)
    if d < 177.3:
        i_d = 0.024 * d
    else:
        i_d = 0.024 * d + 0.11 * (d - 177.3)

    # Impairment due to packet loss (Ie)
    # loss_fraction * 100 represents loss percentage
    loss_pct = loss_fraction * 100.0
    i_e = 30.0 + 70.0 * math.log(1.0 + 10.0 * loss_fraction) if loss_fraction > 0 else 0.0

    # R-Factor calculation
    r = 94.2 - i_d - i_e
    r = max(0.0, min(100.0, r))

    # Convert R-Factor to MOS Score
    if r == 0:
        mos = 1.0
    else:
        mos = 1.0 + 0.035 * r + 0.000007 * r * (r - 60.0) * (100.0 - r)
    mos = max(1.0, min(4.5, mos))

    # Map MOS score to rating
    if mos >= 4.0:
        label = "Excellent"
    elif mos >= 3.0:
        label = "Good"
    elif mos >= 2.0:
        label = "Fair"
    else:
        label = "Poor"

    return {
        "jitter_ms": round(jitter_ms, 2),
        "packet_loss_pct": round(loss_pct, 2),
        "mos_score": round(mos, 2),
        "mos_label": label,
    }
