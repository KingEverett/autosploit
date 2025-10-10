"""
CAN bus utility functions.

Provides helper functions for building, parsing, and validating
CAN frames and identifiers.
"""

from typing import Dict, Any, Optional
from can import Message


def build_frame(
    arbitration_id: int,
    data: bytes,
    is_extended: bool = False
) -> Message:
    """Build a CAN frame."""
    # Validate data length
    if len(data) > 8:
        raise ValueError(f"CAN data must be 0-8 bytes, got {len(data)}")

    # Validate ID range
    if is_extended:
        if not (0 <= arbitration_id <= 0x1FFFFFFF):
            raise ValueError(
                f"Extended ID must be 0x00000000-0x1FFFFFFF, "
                f"got 0x{arbitration_id:08X}"
            )
    else:
        if not (0 <= arbitration_id <= 0x7FF):
            raise ValueError(
                f"Standard ID must be 0x000-0x7FF, "
                f"got 0x{arbitration_id:03X}"
            )

    return Message(
        arbitration_id=arbitration_id,
        data=data,
        is_extended_id=is_extended
    )


def parse_frame(message: Message) -> Dict[str, Any]:
    """Parse a CAN frame into a dict."""
    return {
        'arbitration_id': message.arbitration_id,
        'id_hex': id_to_hex(message.arbitration_id, message.is_extended_id),
        'data': bytes(message.data),
        'data_hex': message.data.hex().upper(),
        'dlc': message.dlc,
        'is_extended': message.is_extended_id,
        'timestamp': message.timestamp if hasattr(message, 'timestamp') else None
    }


def is_extended_id(arbitration_id: int) -> bool:
    """Check if CAN ID requires extended format."""
    return arbitration_id > 0x7FF


def is_valid_id(arbitration_id: int, extended: bool = False) -> bool:
    """Validate CAN ID is in valid range."""
    if extended:
        return 0 <= arbitration_id <= 0x1FFFFFFF
    else:
        return 0 <= arbitration_id <= 0x7FF


def id_to_hex(arbitration_id: int, extended: bool = False) -> str:
    """Format CAN ID as hex string."""
    if extended:
        return f"0x{arbitration_id:08X}"
    else:
        return f"0x{arbitration_id:03X}"


def hex_to_id(hex_string: str) -> int:
    """Parse hex string to CAN ID."""
    # Remove 0x prefix if present
    if hex_string.startswith('0x') or hex_string.startswith('0X'):
        hex_string = hex_string[2:]

    try:
        return int(hex_string, 16)
    except ValueError:
        raise ValueError(f"Invalid hex string: {hex_string}")


def bytes_to_hex(data: bytes, separator: str = ' ') -> str:
    """Format bytes as hex string."""
    return separator.join(f"{byte:02X}" for byte in data)


def hex_to_bytes(hex_string: str) -> bytes:
    """Parse hex string to bytes."""
    # Remove spaces and common separators
    hex_string = hex_string.replace(' ', '').replace(':', '').replace('-', '')

    # Convert to bytes
    return bytes.fromhex(hex_string)


def is_valid_dlc(dlc: int) -> bool:
    """Validate DLC (Data Length Code)."""
    return 0 <= dlc <= 8