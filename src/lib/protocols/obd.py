"""
OBD-II (On-Board Diagnostics) protocol support.

Implements OBD-II modes, PIDs, frame building, and response parsing
according to SAE J1979 standard.
"""

from typing import Dict, Any, Optional, List
from can import Message
from .can_utils import build_frame

# OBD-II Modes (Services)
MODE_CURRENT_DATA = 0x01
MODE_FREEZE_FRAME = 0x02
MODE_SHOW_DTCS = 0x03
MODE_CLEAR_DTCS = 0x04
MODE_TEST_RESULTS_O2 = 0x05
MODE_TEST_RESULTS_OTHER = 0x06
MODE_PENDING_DTCS = 0x07
MODE_CONTROL = 0x08
MODE_VEHICLE_INFO = 0x09
MODE_PERMANENT_DTCS = 0x0A

# OBD-II Functional IDs
OBD_FUNCTIONAL_ID = 0x7DF
OBD_RESPONSE_IDS = range(0x7E8, 0x7F0)

# Positive response offset
POSITIVE_RESPONSE_OFFSET = 0x40

# Common PIDs for Mode 0x01 (Current Data)
PID_SUPPORTED_PIDS_01_20 = 0x00
PID_MONITOR_STATUS = 0x01
PID_FREEZE_DTC = 0x02
PID_FUEL_SYSTEM_STATUS = 0x03
PID_ENGINE_LOAD = 0x04
PID_ENGINE_COOLANT_TEMP = 0x05
PID_SHORT_FUEL_TRIM_1 = 0x06
PID_LONG_FUEL_TRIM_1 = 0x07
PID_SHORT_FUEL_TRIM_2 = 0x08
PID_LONG_FUEL_TRIM_2 = 0x09
PID_FUEL_PRESSURE = 0x0A
PID_INTAKE_PRESSURE = 0x0B
PID_ENGINE_RPM = 0x0C
PID_VEHICLE_SPEED = 0x0D
PID_TIMING_ADVANCE = 0x0E
PID_INTAKE_AIR_TEMP = 0x0F
PID_MAF_FLOW = 0x10
PID_THROTTLE_POSITION = 0x11
PID_COMMANDED_SECONDARY_AIR = 0x12
PID_OXYGEN_SENSORS_PRESENT = 0x13

# Additional PIDs
PID_SUPPORTED_PIDS_21_40 = 0x20
PID_DISTANCE_WITH_MIL = 0x21
PID_FUEL_RAIL_PRESSURE = 0x22
PID_FUEL_RAIL_GAUGE_PRESSURE = 0x23

# More PID ranges
PID_SUPPORTED_PIDS_41_60 = 0x40
PID_SUPPORTED_PIDS_61_80 = 0x60
PID_SUPPORTED_PIDS_81_A0 = 0x80
PID_SUPPORTED_PIDS_A1_C0 = 0xA0
PID_SUPPORTED_PIDS_C1_E0 = 0xC0

# Mode 0x09 Vehicle Information PIDs
PID_VIN_MESSAGE_COUNT = 0x01
PID_VIN = 0x02
PID_CALIBRATION_ID = 0x04
PID_CVN = 0x06
PID_ECU_NAME = 0x0A

# PID information for decoding
PID_INFO: Dict[int, Dict[str, Any]] = {
    PID_ENGINE_RPM: {
        'name': 'Engine RPM',
        'formula': lambda a, b: ((a * 256) + b) / 4,
        'unit': 'RPM',
        'bytes': 2
    },
    PID_VEHICLE_SPEED: {
        'name': 'Vehicle Speed',
        'formula': lambda a: a,
        'unit': 'km/h',
        'bytes': 1
    },
    PID_ENGINE_COOLANT_TEMP: {
        'name': 'Engine Coolant Temperature',
        'formula': lambda a: a - 40,
        'unit': 'C',
        'bytes': 1
    },
    PID_ENGINE_LOAD: {
        'name': 'Calculated Engine Load',
        'formula': lambda a: (a * 100) / 255,
        'unit': '%',
        'bytes': 1
    },
    PID_THROTTLE_POSITION: {
        'name': 'Throttle Position',
        'formula': lambda a: (a * 100) / 255,
        'unit': '%',
        'bytes': 1
    },
    PID_INTAKE_AIR_TEMP: {
        'name': 'Intake Air Temperature',
        'formula': lambda a: a - 40,
        'unit': 'C',
        'bytes': 1
    },
    PID_MAF_FLOW: {
        'name': 'MAF Air Flow Rate',
        'formula': lambda a, b: ((a * 256) + b) / 100,
        'unit': 'grams/sec',
        'bytes': 2
    },
    PID_TIMING_ADVANCE: {
        'name': 'Timing Advance',
        'formula': lambda a: (a / 2) - 64,
        'unit': 'deg before TDC',
        'bytes': 1
    },
    PID_FUEL_PRESSURE: {
        'name': 'Fuel Pressure',
        'formula': lambda a: a * 3,
        'unit': 'kPa',
        'bytes': 1
    },
    PID_INTAKE_PRESSURE: {
        'name': 'Intake Manifold Pressure',
        'formula': lambda a: a,
        'unit': 'kPa',
        'bytes': 1
    },
}


def build_obd_request(
    mode: int,
    pid: int,
    data: Optional[bytes] = None,
    ecu_id: int = OBD_FUNCTIONAL_ID
) -> Message:
    """Build an OBD-II request frame."""
    # Build data: [mode, pid, additional_data...]
    request_data = bytes([mode, pid])

    if data:
        request_data += data

    # First byte is the number of data bytes (excluding padding)
    length = len(request_data)
    request_data = bytes([length]) + request_data

    # Pad to 8 bytes
    request_data = request_data.ljust(8, b'\x00')

    return build_frame(ecu_id, request_data)


def parse_obd_response(message: Message) -> Optional[Dict[str, Any]]:
    """Parse an OBD-II response frame."""
    # Check if response ID is in valid range
    if message.arbitration_id not in OBD_RESPONSE_IDS:
        return None

    data = bytes(message.data)

    # Check minimum length
    if len(data) < 3:
        return None

    length = data[0]
    mode = data[1]
    pid = data[2]

    # Check if negative response (mode 0x7F)
    if mode == 0x7F:
        is_positive = False
        actual_mode = pid  # In negative response, the PID field contains the original mode
    elif mode >= POSITIVE_RESPONSE_OFFSET:
        is_positive = True
        actual_mode = mode - POSITIVE_RESPONSE_OFFSET
    else:
        is_positive = False
        actual_mode = mode

    # Extract data bytes
    data_bytes = data[3:3+length-2] if length > 2 else bytes()

    return {
        'ecu_id': message.arbitration_id,
        'mode': actual_mode,
        'pid': pid,
        'data': data_bytes,
        'is_positive': is_positive,
        'raw': data
    }


def decode_pid_value(mode: int, pid: int, data: bytes) -> Optional[Dict[str, Any]]:
    """Decode PID value from response data."""
    # Only support Mode 0x01 for now
    if mode != MODE_CURRENT_DATA:
        return None

    # Check if we have info for this PID
    if pid not in PID_INFO:
        return None

    info = PID_INFO[pid]

    # Check if we have enough data bytes
    if len(data) < info['bytes']:
        return None

    # Apply formula to decode value
    try:
        if info['bytes'] == 1:
            value = info['formula'](data[0])
        elif info['bytes'] == 2:
            value = info['formula'](data[0], data[1])
        elif info['bytes'] == 4:
            value = info['formula'](data[0], data[1], data[2], data[3])
        else:
            return None

        return {
            'name': info['name'],
            'value': value,
            'unit': info['unit'],
            'pid': pid
        }
    except Exception:
        return None


def get_pid_info(pid: int) -> Optional[Dict[str, Any]]:
    """Get information about a PID."""
    return PID_INFO.get(pid)


def is_supported_pid(pid: int, support_bitmap: bytes) -> bool:
    """Check if a PID is supported based on support bitmap."""
    if len(support_bitmap) != 4:
        return False

    # PIDs are numbered 1-32 relative to the support PID
    # PID 0x01-0x20 are checked by PID 0x00
    # PID 0x21-0x40 are checked by PID 0x20, etc.

    # Calculate relative position (0-31)
    base_pid = (pid // 32) * 32
    relative_pid = pid - base_pid - 1  # -1 because PIDs start at 1

    if relative_pid < 0 or relative_pid >= 32:
        return False

    # Calculate byte and bit position
    byte_index = relative_pid // 8
    bit_index = 7 - (relative_pid % 8)  # MSB first

    # Check if bit is set
    return bool(support_bitmap[byte_index] & (1 << bit_index))