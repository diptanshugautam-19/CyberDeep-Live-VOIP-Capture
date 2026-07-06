from .stun import parse_stun_packet

# TURN specific constants
TURN_METHODS = {
    "Allocate",
    "Refresh",
    "Send",
    "Data",
    "CreatePermission",
    "ChannelBind",
}


def parse_turn_packet(payload_bytes: bytes) -> dict | None:
    """Parse a TURN message using the STUN framing format.

    Adds TURN-specific metadata and candidate tags.
    """
    fields = parse_stun_packet(payload_bytes)
    if not fields:
        return None

    # Check if the parsed STUN message is a TURN method
    message_name = fields.get("message_name", "")
    is_turn = any(method in message_name for method in TURN_METHODS)
    if not is_turn:
        return None

    # Tag candidate and relay indications
    fields["is_turn"] = True
    fields["is_relay_creation"] = "Allocate" in message_name
    fields["is_channel_bind"] = "ChannelBind" in message_name

    # Relayed and peer candidates detection
    if "xor_relayed_address" in fields:
        fields["xor_relayed_address"]["source"] = "relayed_allocation"
    if "xor_peer_address" in fields:
        fields["xor_peer_address"]["source"] = "peer_destination"

    return fields
