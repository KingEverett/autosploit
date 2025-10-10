"""Input validation utilities for Autosploit."""

import re
from pathlib import Path
from typing import Any, List, Optional, Union


class ValidationResult:
    """Result of a validation operation."""

    def __init__(
        self,
        is_valid: bool,
        error_message: Optional[str] = None,
        suggestion: Optional[str] = None
    ):
        self.is_valid = is_valid
        self.error_message = error_message
        self.suggestion = suggestion

    def __bool__(self) -> bool:
        return self.is_valid

    def raise_if_invalid(self) -> None:
        if not self.is_valid:
            msg = self.error_message
            if self.suggestion:
                msg += f"\n{self.suggestion}"
            raise ValueError(msg)


def validate_can_id(
    arb_id: int,
    extended: bool = False,
    allow_zero: bool = True
) -> ValidationResult:
    """Validate CAN arbitration ID."""

    if not isinstance(arb_id, int):
        return ValidationResult(
            is_valid=False,
            error_message=f"CAN ID must be an integer, got {type(arb_id).__name__}",
            suggestion="Example: 0x7E8 or 2024 (decimal)"
        )

    if arb_id < 0:
        return ValidationResult(
            is_valid=False,
            error_message=f"CAN ID cannot be negative: {arb_id}",
            suggestion="CAN IDs must be non-negative integers"
        )

    if extended:
        max_id = 0x1FFFFFFF
        if arb_id > max_id:
            return ValidationResult(
                is_valid=False,
                error_message=(
                    f"Extended CAN ID {hex(arb_id).upper()} exceeds maximum "
                    f"{hex(max_id).upper()} (29-bit)"
                ),
                suggestion=f"Extended CAN IDs must be in range 0x00000000-{hex(max_id).upper()}"
            )
    else:
        max_id = 0x7FF
        if arb_id > max_id:
            return ValidationResult(
                is_valid=False,
                error_message=(
                    f"Standard CAN ID {hex(arb_id).upper()} exceeds maximum "
                    f"{hex(max_id).upper()} (11-bit)"
                ),
                suggestion=f"Standard CAN IDs must be in range 0x000-{hex(max_id).upper()}\n"
                           f"Use extended=True for 29-bit IDs"
            )

    if not allow_zero and arb_id == 0:
        return ValidationResult(
            is_valid=False,
            error_message="CAN ID 0x000 is not allowed in this context",
            suggestion="Use a non-zero CAN ID (0x001-0x7FF for standard)"
        )

    return ValidationResult(is_valid=True)


def validate_can_data(data: bytes, max_length: int = 8) -> ValidationResult:
    """Validate CAN message data."""

    if not isinstance(data, (bytes, bytearray)):
        return ValidationResult(
            is_valid=False,
            error_message=f"CAN data must be bytes or bytearray, got {type(data).__name__}",
            suggestion="Example: b'\\x01\\x02\\x03\\x04' or bytes([1, 2, 3, 4])"
        )

    if len(data) > max_length:
        return ValidationResult(
            is_valid=False,
            error_message=(
                f"CAN data length {len(data)} exceeds maximum {max_length} bytes"
            ),
            suggestion=f"CAN 2.0 data must be 0-{max_length} bytes\n"
                       f"For CAN FD, use max_length=64"
        )

    return ValidationResult(is_valid=True)


def validate_dlc(dlc: int, can_fd: bool = False) -> ValidationResult:
    """Validate Data Length Code (DLC)."""

    if not isinstance(dlc, int):
        return ValidationResult(
            is_valid=False,
            error_message=f"DLC must be an integer, got {type(dlc).__name__}",
            suggestion="DLC (Data Length Code) must be 0-8 for CAN 2.0"
        )

    max_dlc = 15 if can_fd else 8
    protocol = "CAN FD" if can_fd else "CAN 2.0"

    if dlc < 0:
        return ValidationResult(
            is_valid=False,
            error_message=f"DLC cannot be negative: {dlc}",
            suggestion=f"DLC must be 0-{max_dlc} for {protocol}"
        )

    if dlc > max_dlc:
        return ValidationResult(
            is_valid=False,
            error_message=f"DLC {dlc} exceeds maximum {max_dlc} for {protocol}",
            suggestion=f"DLC must be 0-{max_dlc} for {protocol}\n"
                       f"Use can_fd=True for CAN FD support"
        )

    return ValidationResult(is_valid=True)


def validate_interface_name(
    name: str,
    interface_type: str = "socketcan"
) -> ValidationResult:
    """Validate CAN interface name."""

    if not isinstance(name, str):
        return ValidationResult(
            is_valid=False,
            error_message=f"Interface name must be a string, got {type(name).__name__}",
            suggestion="Example: 'can0', 'vcan0', 'slcan0'"
        )

    if not name or not name.strip():
        return ValidationResult(
            is_valid=False,
            error_message="Interface name cannot be empty",
            suggestion="Provide a valid interface name like 'can0' or 'vcan0'"
        )

    name = name.strip()

    valid_patterns = {
        "socketcan": r"^(can|vcan)\d+$",
        "slcan": r"^slcan\d+$",
        "pcan": r"^PCAN_USB(BUS)?\d+$",
        "kvaser": r"^kvaser\d+$",
        "virtual": r"^vcan\d+$",
    }

    pattern = valid_patterns.get(interface_type.lower())

    if not pattern:
        if not re.match(r"^[\w-]+$", name):
            return ValidationResult(
                is_valid=False,
                error_message=f"Interface name '{name}' contains invalid characters",
                suggestion="Use only alphanumeric characters, underscores, and hyphens"
            )
        return ValidationResult(is_valid=True)

    if not re.match(pattern, name, re.IGNORECASE):
        examples = {
            "socketcan": "can0, can1, vcan0",
            "slcan": "slcan0, slcan1",
            "pcan": "PCAN_USB1, PCAN_USBBUS1",
            "kvaser": "kvaser0, kvaser1",
            "virtual": "vcan0, vcan1",
        }

        return ValidationResult(
            is_valid=False,
            error_message=(
                f"Interface name '{name}' invalid for type '{interface_type}'"
            ),
            suggestion=f"Valid {interface_type} names: {examples.get(interface_type, 'N/A')}"
        )

    return ValidationResult(is_valid=True)


def validate_bitrate(bitrate: int) -> ValidationResult:
    """Validate CAN bus bitrate."""

    if not isinstance(bitrate, int):
        return ValidationResult(
            is_valid=False,
            error_message=f"Bitrate must be an integer, got {type(bitrate).__name__}",
            suggestion="Example: 500000 (500 kbps)"
        )

    common_bitrates = [
        10000, 20000, 50000, 100000, 125000, 250000, 500000, 800000, 1000000
    ]

    min_bitrate = 5000
    max_bitrate = 1000000

    if bitrate < min_bitrate:
        return ValidationResult(
            is_valid=False,
            error_message=f"Bitrate {bitrate} bps is too low (minimum {min_bitrate} bps)",
            suggestion=f"Common bitrates: 125000, 250000, 500000, 1000000"
        )

    if bitrate > max_bitrate:
        return ValidationResult(
            is_valid=False,
            error_message=f"Bitrate {bitrate} bps exceeds maximum {max_bitrate} bps",
            suggestion=f"Standard CAN supports up to 1 Mbps\n"
                       f"For CAN FD, higher bitrates are supported"
        )

    if bitrate not in common_bitrates:
        return ValidationResult(
            is_valid=True,
            error_message=None,
            suggestion=f"Warning: {bitrate} bps is non-standard\n"
                       f"Common bitrates: {', '.join(str(b) for b in common_bitrates)}"
        )

    return ValidationResult(is_valid=True)


def validate_range(
    value: int,
    min_val: int,
    max_val: int,
    name: str = "value"
) -> ValidationResult:
    """Validate integer is within specified range."""

    if not isinstance(value, int):
        return ValidationResult(
            is_valid=False,
            error_message=f"{name} must be an integer, got {type(value).__name__}",
            suggestion=f"{name} should be between {min_val} and {max_val}"
        )

    if value < min_val or value > max_val:
        return ValidationResult(
            is_valid=False,
            error_message=f"{name} {value} is out of range [{min_val}, {max_val}]",
            suggestion=f"{name} must be between {min_val} and {max_val} (inclusive)"
        )

    return ValidationResult(is_valid=True)


def validate_choice(
    value: Any,
    choices: List[Any],
    name: str = "value"
) -> ValidationResult:
    """Validate value is one of allowed choices."""

    if value not in choices:
        if all(isinstance(c, str) for c in choices):
            choices_str = ", ".join(f"'{c}'" for c in choices)
        else:
            choices_str = ", ".join(str(c) for c in choices)

        return ValidationResult(
            is_valid=False,
            error_message=f"{name} '{value}' is not valid",
            suggestion=f"Valid choices: {choices_str}"
        )

    return ValidationResult(is_valid=True)


def validate_path(
    path: str,
    must_exist: bool = False,
    must_be_file: bool = False,
    must_be_dir: bool = False,
    allow_create: bool = True
) -> ValidationResult:
    """Validate file system path."""

    if not isinstance(path, (str, Path)):
        return ValidationResult(
            is_valid=False,
            error_message=f"Path must be a string or Path object, got {type(path).__name__}",
            suggestion="Example: '/path/to/file.txt' or Path('/path/to/file.txt')"
        )

    path_obj = Path(path).expanduser().resolve()

    if must_exist and not path_obj.exists():
        return ValidationResult(
            is_valid=False,
            error_message=f"Path does not exist: {path_obj}",
            suggestion="Ensure the path exists and is accessible"
        )

    if path_obj.exists():
        if must_be_file and not path_obj.is_file():
            return ValidationResult(
                is_valid=False,
                error_message=f"Path is not a file: {path_obj}",
                suggestion="Provide a path to a file, not a directory"
            )

        if must_be_dir and not path_obj.is_dir():
            return ValidationResult(
                is_valid=False,
                error_message=f"Path is not a directory: {path_obj}",
                suggestion="Provide a path to a directory, not a file"
            )
    else:
        if not allow_create:
            return ValidationResult(
                is_valid=False,
                error_message=f"Path does not exist and creation not allowed: {path_obj}",
                suggestion="Path must exist or set allow_create=True"
            )

    return ValidationResult(is_valid=True)


def validate_hex_string(hex_str: str) -> ValidationResult:
    """Validate hexadecimal string."""

    if not isinstance(hex_str, str):
        return ValidationResult(
            is_valid=False,
            error_message=f"Hex string must be a string, got {type(hex_str).__name__}",
            suggestion="Example: '0x1A2B' or 'DEADBEEF'"
        )

    hex_str = hex_str.strip()

    if not hex_str:
        return ValidationResult(
            is_valid=False,
            error_message="Hex string cannot be empty",
            suggestion="Example: '0x1A2B' or 'DEADBEEF'"
        )

    if hex_str.lower().startswith("0x"):
        hex_str = hex_str[2:]

    if not re.match(r"^[0-9A-Fa-f]+$", hex_str):
        return ValidationResult(
            is_valid=False,
            error_message=f"Invalid hexadecimal string: '{hex_str}'",
            suggestion="Hex strings must contain only 0-9 and A-F\n"
                       "Example: '0x1A2B3C' or 'DEADBEEF'"
        )

    return ValidationResult(is_valid=True)