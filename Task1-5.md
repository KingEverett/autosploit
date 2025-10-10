# Task 1.5: Protocol Libraries - Complete Implementation Guide
## CAN Utilities, OBD-II, and UDS Protocol Support

**Estimated Time**: 4-5 hours total (1.5 hrs + 1.5 hrs + 1.5 hrs)

---

## 📋 Overview

These three files provide the **protocol-level functionality** that modules will use to communicate with vehicles. Think of them as the "language translators" between your framework and automotive protocols.

**Files to Create**:
1. `src/autosploit/lib/protocols/can_utils.py` - Basic CAN operations
2. `src/autosploit/lib/protocols/obd.py` - OBD-II diagnostics
3. `src/autosploit/lib/protocols/uds.py` - UDS (Unified Diagnostic Services)

---

## 🔧 File 1: CAN Utilities (`can_utils.py`)

**File**: `src/autosploit/lib/protocols/can_utils.py`  
**Purpose**: Basic CAN frame operations and validation  
**Estimated Time**: 1.5 hours

### **What This File Does:**
- Builds and parses CAN frames
- Validates CAN IDs and data
- Provides utilities for working with CAN messages

---

### **Required Imports**:
```python
"""
CAN bus utility functions.

Provides helper functions for building, parsing, and validating
CAN frames and identifiers.
"""

from typing import Dict, Any, Optional
from can import Message
```

---

### **Function 1: `build_frame()`**
**Purpose**: Create a CAN Message object from raw data

**Implementation**:
```python
def build_frame(
    arbitration_id: int,
    data: bytes,
    is_extended: bool = False
) -> Message:
    """
    Build a CAN frame.
    
    Args:
        arbitration_id: CAN ID (11-bit or 29-bit)
        data: Data bytes (0-8 bytes)
        is_extended: True for 29-bit extended ID
    
    Returns:
        can.Message object
    
    Raises:
        ValueError: If data length > 8 or ID out of range
    
    Example:
        >>> frame = build_frame(0x7DF, bytes([0x02, 0x01, 0x0C]))
        >>> print(f"ID: 0x{frame.arbitration_id:03X}")
        ID: 0x7DF
    """
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
```

**Tools Used**: `Message` from can library, validation logic

---

### **Function 2: `parse_frame()`**
**Purpose**: Extract information from a CAN Message

**Implementation**:
```python
def parse_frame(message: Message) -> Dict[str, Any]:
    """
    Parse a CAN frame into a dict.
    
    Args:
        message: can.Message object
    
    Returns:
        Dict with frame information
    
    Example:
        >>> msg = Message(arbitration_id=0x7E8, data=[0x04, 0x41, 0x0C, 0x1A, 0x2B])
        >>> info = parse_frame(msg)
        >>> print(info['id_hex'])
        0x7E8
    """
    return {
        'arbitration_id': message.arbitration_id,
        'id_hex': f"0x{message.arbitration_id:03X}",
        'data': bytes(message.data),
        'data_hex': message.data.hex().upper(),
        'dlc': message.dlc,
        'is_extended': message.is_extended_id,
        'timestamp': message.timestamp if hasattr(message, 'timestamp') else None
    }
```

**Tools Used**: Dict construction, f-strings, `.hex()` method

---

### **Function 3: `is_extended_id()`**
**Purpose**: Check if an ID is 29-bit extended format

**Implementation**:
```python
def is_extended_id(arbitration_id: int) -> bool:
    """
    Check if CAN ID requires extended format.
    
    Args:
        arbitration_id: CAN ID to check
    
    Returns:
        True if ID > 0x7FF (requires 29-bit), False otherwise
    
    Example:
        >>> is_extended_id(0x123)
        False
        >>> is_extended_id(0x18FF1234)
        True
    """
    return arbitration_id > 0x7FF
```

**Tools Used**: Simple comparison

---

### **Function 4: `is_valid_id()`**
**Purpose**: Validate CAN ID is in correct range

**Implementation**:
```python
def is_valid_id(arbitration_id: int, extended: bool = False) -> bool:
    """
    Validate CAN ID is in valid range.
    
    Args:
        arbitration_id: CAN ID to validate
        extended: Whether to check as extended ID
    
    Returns:
        True if valid, False otherwise
    
    Example:
        >>> is_valid_id(0x7DF)
        True
        >>> is_valid_id(0x800)
        False
        >>> is_valid_id(0x18FF1234, extended=True)
        True
    """
    if extended:
        return 0 <= arbitration_id <= 0x1FFFFFFF
    else:
        return 0 <= arbitration_id <= 0x7FF
```

---

### **Function 5: `id_to_hex()`**
**Purpose**: Format CAN ID as hex string

**Implementation**:
```python
def id_to_hex(arbitration_id: int, extended: bool = False) -> str:
    """
    Format CAN ID as hex string.
    
    Args:
        arbitration_id: CAN ID
        extended: Whether it's an extended ID
    
    Returns:
        Formatted hex string
    
    Example:
        >>> id_to_hex(0x7DF)
        '0x7DF'
        >>> id_to_hex(0x18FF1234, extended=True)
        '0x18FF1234'
    """
    if extended:
        return f"0x{arbitration_id:08X}"
    else:
        return f"0x{arbitration_id:03X}"
```

---

### **Function 6: `hex_to_id()`**
**Purpose**: Parse hex string to CAN ID

**Implementation**:
```python
def hex_to_id(hex_string: str) -> int:
    """
    Parse hex string to CAN ID.
    
    Args:
        hex_string: Hex string (with or without 0x prefix)
    
    Returns:
        Integer CAN ID
    
    Raises:
        ValueError: If string is not valid hex
    
    Example:
        >>> hex_to_id('0x7DF')
        2015
        >>> hex_to_id('7E8')
        2024
    """
    # Remove 0x prefix if present
    if hex_string.startswith('0x') or hex_string.startswith('0X'):
        hex_string = hex_string[2:]
    
    try:
        return int(hex_string, 16)
    except ValueError:
        raise ValueError(f"Invalid hex string: {hex_string}")
```

---

### **Function 7: `bytes_to_hex()`**
**Purpose**: Format bytes as hex string

**Implementation**:
```python
def bytes_to_hex(data: bytes, separator: str = ' ') -> str:
    """
    Format bytes as hex string.
    
    Args:
        data: Bytes to format
        separator: Character to put between bytes
    
    Returns:
        Hex string
    
    Example:
        >>> bytes_to_hex(bytes([0x02, 0x01, 0x0C]))
        '02 01 0C'
        >>> bytes_to_hex(bytes([0x02, 0x01, 0x0C]), separator=':')
        '02:01:0C'
    """
    return separator.join(f"{byte:02X}" for byte in data)
```

---

### **Function 8: `hex_to_bytes()`**
**Purpose**: Parse hex string to bytes

**Implementation**:
```python
def hex_to_bytes(hex_string: str) -> bytes:
    """
    Parse hex string to bytes.
    
    Args:
        hex_string: Hex string (spaces optional)
    
    Returns:
        Bytes object
    
    Example:
        >>> hex_to_bytes('02 01 0C')
        b'\x02\x01\x0c'
        >>> hex_to_bytes('02010C')
        b'\x02\x01\x0c'
    """
    # Remove spaces and common separators
    hex_string = hex_string.replace(' ', '').replace(':', '').replace('-', '')
    
    # Convert to bytes
    return bytes.fromhex(hex_string)
```

---

### **Function 9: `is_valid_dlc()`**
**Purpose**: Validate Data Length Code

**Implementation**:
```python
def is_valid_dlc(dlc: int) -> bool:
    """
    Validate DLC (Data Length Code).
    
    Args:
        dlc: Data length to check
    
    Returns:
        True if DLC is 0-8, False otherwise
    
    Example:
        >>> is_valid_dlc(8)
        True
        >>> is_valid_dlc(9)
        False
    """
    return 0 <= dlc <= 8
```

---

### **Complete `can_utils.py` File**:

```python
"""
CAN bus utility functions.
"""

from typing import Dict, Any, Optional
from can import Message


def build_frame(arbitration_id: int, data: bytes,
                is_extended: bool = False) -> Message:
    """Build a CAN frame."""
    # [Full implementation above]
    pass


def parse_frame(message: Message) -> Dict[str, Any]:
    """Parse a CAN frame into a dict."""
    # [Full implementation above]
    pass


def is_extended_id(arbitration_id: int) -> bool:
    """Check if CAN ID requires extended format."""
    # [Full implementation above]
    pass


def is_valid_id(arbitration_id: int, extended: bool = False) -> bool:
    """Validate CAN ID is in valid range."""
    # [Full implementation above]
    pass


def id_to_hex(arbitration_id: int, extended: bool = False) -> str:
    """Format CAN ID as hex string."""
    # [Full implementation above]
    pass


def hex_to_id(hex_string: str) -> int:
    """Parse hex string to CAN ID."""
    # [Full implementation above]
    pass


def bytes_to_hex(data: bytes, separator: str = ' ') -> str:
    """Format bytes as hex string."""
    # [Full implementation above]
    pass


def hex_to_bytes(hex_string: str) -> bytes:
    """Parse hex string to bytes."""
    # [Full implementation above]
    pass


def is_valid_dlc(dlc: int) -> bool:
    """Validate DLC (Data Length Code)."""
    # [Full implementation above]
    pass
```

---

## 🔧 File 2: OBD-II Protocol (`obd.py`)

**File**: `src/autosploit/lib/protocols/obd.py`  
**Purpose**: OBD-II diagnostic protocol support  
**Estimated Time**: 1.5 hours

### **What This File Does:**
- Defines OBD-II modes and PIDs
- Builds OBD-II request frames
- Parses OBD-II responses
- Decodes PID values

---

### **Required Imports**:
```python
"""
OBD-II (On-Board Diagnostics) protocol support.

Implements OBD-II modes, PIDs, frame building, and response parsing
according to SAE J1979 standard.
"""

from typing import Dict, Any, Optional, List
from can import Message
from .can_utils import build_frame
```

---

### **Constants - OBD Modes**:
```python
# OBD-II Modes (Services)
MODE_CURRENT_DATA = 0x01        # Show current data
MODE_FREEZE_FRAME = 0x02        # Show freeze frame data
MODE_SHOW_DTCS = 0x03           # Show stored diagnostic trouble codes
MODE_CLEAR_DTCS = 0x04          # Clear DTCs and stored values
MODE_TEST_RESULTS_O2 = 0x05     # Test results, oxygen sensor monitoring
MODE_TEST_RESULTS_OTHER = 0x06  # Test results, other monitoring
MODE_PENDING_DTCS = 0x07        # Show pending DTCs
MODE_CONTROL = 0x08             # Control operation of onboard systems
MODE_VEHICLE_INFO = 0x09        # Request vehicle information
MODE_PERMANENT_DTCS = 0x0A      # Permanent DTCs (WWH-OBD)

# OBD-II Functional IDs
OBD_FUNCTIONAL_ID = 0x7DF       # Functional broadcast address
OBD_RESPONSE_IDS = range(0x7E8, 0x7F0)  # ECU response IDs

# Positive response offset
POSITIVE_RESPONSE_OFFSET = 0x40
```

**Tools Used**: Constants, range() for ID list

---

### **Constants - Common PIDs (Mode 0x01)**:
```python
# Common PIDs for Mode 0x01 (Current Data)
PID_SUPPORTED_PIDS_01_20 = 0x00     # PIDs supported [01-20]
PID_MONITOR_STATUS = 0x01            # Monitor status since DTCs cleared
PID_FREEZE_DTC = 0x02                # Freeze DTC
PID_FUEL_SYSTEM_STATUS = 0x03        # Fuel system status
PID_ENGINE_LOAD = 0x04               # Calculated engine load
PID_ENGINE_COOLANT_TEMP = 0x05       # Engine coolant temperature
PID_SHORT_FUEL_TRIM_1 = 0x06         # Short term fuel trim—Bank 1
PID_LONG_FUEL_TRIM_1 = 0x07          # Long term fuel trim—Bank 1
PID_SHORT_FUEL_TRIM_2 = 0x08         # Short term fuel trim—Bank 2
PID_LONG_FUEL_TRIM_2 = 0x09          # Long term fuel trim—Bank 2
PID_FUEL_PRESSURE = 0x0A             # Fuel pressure
PID_INTAKE_PRESSURE = 0x0B           # Intake manifold absolute pressure
PID_ENGINE_RPM = 0x0C                # Engine RPM
PID_VEHICLE_SPEED = 0x0D             # Vehicle speed
PID_TIMING_ADVANCE = 0x0E            # Timing advance
PID_INTAKE_AIR_TEMP = 0x0F           # Intake air temperature
PID_MAF_FLOW = 0x10                  # MAF air flow rate
PID_THROTTLE_POSITION = 0x11         # Throttle position
PID_COMMANDED_SECONDARY_AIR = 0x12   # Commanded secondary air status
PID_OXYGEN_SENSORS_PRESENT = 0x13    # Oxygen sensors present

# Additional PIDs
PID_SUPPORTED_PIDS_21_40 = 0x20      # PIDs supported [21-40]
PID_DISTANCE_WITH_MIL = 0x21         # Distance traveled with MIL on
PID_FUEL_RAIL_PRESSURE = 0x22        # Fuel Rail Pressure
PID_FUEL_RAIL_GAUGE_PRESSURE = 0x23  # Fuel Rail Gauge Pressure

# More PID ranges
PID_SUPPORTED_PIDS_41_60 = 0x40      # PIDs supported [41-60]
PID_SUPPORTED_PIDS_61_80 = 0x60      # PIDs supported [61-80]
PID_SUPPORTED_PIDS_81_A0 = 0x80      # PIDs supported [81-A0]
PID_SUPPORTED_PIDS_A1_C0 = 0xA0      # PIDs supported [A1-C0]
PID_SUPPORTED_PIDS_C1_E0 = 0xC0      # PIDs supported [C1-E0]
```

---

### **Constants - Vehicle Info PIDs (Mode 0x09)**:
```python
# Mode 0x09 Vehicle Information PIDs
PID_VIN_MESSAGE_COUNT = 0x01         # VIN Message Count
PID_VIN = 0x02                       # Vehicle Identification Number
PID_CALIBRATION_ID = 0x04            # Calibration ID
PID_CVN = 0x06                       # Calibration Verification Numbers
PID_ECU_NAME = 0x0A                  # ECU name
```

---

### **PID Information Dictionary**:
```python
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
        'unit': '°C',
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
        'unit': '°C',
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
        'unit': '° before TDC',
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
```

**Tools Used**: Dict with lambda functions for formulas

---

### **Function 1: `build_obd_request()`**
**Purpose**: Build OBD-II request frame

**Implementation**:
```python
def build_obd_request(
    mode: int,
    pid: int,
    data: Optional[bytes] = None,
    ecu_id: int = OBD_FUNCTIONAL_ID
) -> Message:
    """
    Build an OBD-II request frame.
    
    Args:
        mode: OBD mode (0x01-0x0A)
        pid: Parameter ID
        data: Optional additional data bytes
        ecu_id: Target ECU ID (default: functional broadcast)
    
    Returns:
        CAN Message object
    
    Example:
        >>> # Request engine RPM (Mode 01, PID 0C)
        >>> frame = build_obd_request(0x01, 0x0C)
        >>> print(frame.data.hex())
        '02010c0000000000'
    """
    # Build data: [length, mode, pid, additional_data...]
    request_data = bytes([mode, pid])
    
    if data:
        request_data += data
    
    # Pad to 8 bytes
    request_data = request_data.ljust(8, b'\x00')
    
    # First byte is the number of data bytes (excluding padding)
    length = 2 + (len(data) if data else 0)
    request_data = bytes([length]) + request_data[1:]
    
    return build_frame(ecu_id, request_data)
```

---

### **Function 2: `parse_obd_response()`**
**Purpose**: Parse OBD-II response frame

**Implementation**:
```python
def parse_obd_response(message: Message) -> Optional[Dict[str, Any]]:
    """
    Parse an OBD-II response frame.
    
    Args:
        message: CAN Message containing response
    
    Returns:
        Dict with parsed response or None if not valid OBD response
    
    Example:
        >>> # Response for engine RPM
        >>> msg = Message(arbitration_id=0x7E8, 
        ...               data=[0x04, 0x41, 0x0C, 0x1A, 0x2B])
        >>> response = parse_obd_response(msg)
        >>> print(response['pid'])
        12  # 0x0C
    """
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
    
    # Check if positive response (mode + 0x40)
    is_positive = (mode >= POSITIVE_RESPONSE_OFFSET)
    
    if is_positive:
        actual_mode = mode - POSITIVE_RESPONSE_OFFSET
    else:
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
```

---

### **Function 3: `decode_pid_value()`**
**Purpose**: Decode PID data into human-readable value

**Implementation**:
```python
def decode_pid_value(mode: int, pid: int, data: bytes) -> Optional[Dict[str, Any]]:
    """
    Decode PID value from response data.
    
    Args:
        mode: OBD mode
        pid: Parameter ID
        data: Response data bytes
    
    Returns:
        Dict with name, value, and unit or None if PID unknown
    
    Example:
        >>> # Decode RPM: data = [0x1A, 0x2B]
        >>> result = decode_pid_value(0x01, 0x0C, bytes([0x1A, 0x2B]))
        >>> print(f"{result['name']}: {result['value']} {result['unit']}")
        Engine RPM: 1690.75 RPM
    """
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
```

---

### **Function 4: `get_pid_info()`**
**Purpose**: Get information about a PID

**Implementation**:
```python
def get_pid_info(pid: int) -> Optional[Dict[str, Any]]:
    """
    Get information about a PID.
    
    Args:
        pid: Parameter ID
    
    Returns:
        Dict with PID info or None if unknown
    
    Example:
        >>> info = get_pid_info(0x0C)
        >>> print(info['name'])
        Engine RPM
    """
    return PID_INFO.get(pid)
```

---

### **Function 5: `is_supported_pid()`**
**Purpose**: Check if a PID is supported based on bitmap

**Implementation**:
```python
def is_supported_pid(pid: int, support_bitmap: bytes) -> bool:
    """
    Check if a PID is supported based on support bitmap.
    
    Args:
        pid: PID to check (1-32, 33-64, etc.)
        support_bitmap: 4-byte bitmap from PID 0x00, 0x20, etc.
    
    Returns:
        True if PID is supported
    
    Example:
        >>> # Check if PID 0x0C (RPM) is supported
        >>> # Bitmap from PID 0x00: [0xBE, 0x1F, 0xB8, 0x10]
        >>> is_supported_pid(0x0C, bytes([0xBE, 0x1F, 0xB8, 0x10]))
        True
    """
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
```

---

### **Complete `obd.py` File Structure**:

```python
"""
OBD-II protocol support.
"""

from typing import Dict, Any, Optional, List
from can import Message
from .can_utils import build_frame

# [All constants above]

# [All functions above]
```

---

## 🔧 File 3: UDS Protocol (`uds.py`)

**File**: `src/autosploit/lib/protocols/uds.py`  
**Purpose**: UDS (Unified Diagnostic Services) protocol support  
**Estimated Time**: 1.5 hours

### **What This File Does:**
- Defines UDS services and sub-functions
- Builds UDS request frames
- Parses UDS responses
- Handles negative responses

---

### **Required Imports**:
```python
"""
UDS (Unified Diagnostic Services) protocol support.

Implements ISO 14229 diagnostic services for automotive ECUs.
"""

from typing import Dict, Any, Optional, List
from can import Message
from .can_utils import build_frame
```

---

### **Constants - UDS Services**:
```python
# UDS Services (ISO 14229)
SERVICE_DIAGNOSTIC_SESSION_CONTROL = 0x10
SERVICE_ECU_RESET = 0x11
SERVICE_SECURITY_ACCESS = 0x27
SERVICE_COMMUNICATION_CONTROL = 0x28
SERVICE_TESTER_PRESENT = 0x3E
SERVICE_ACCESS_TIMING_PARAMETER = 0x83
SERVICE_SECURED_DATA_TRANSMISSION = 0x84
SERVICE_CONTROL_DTC_SETTING = 0x85
SERVICE_RESPONSE_ON_EVENT = 0x86
SERVICE_LINK_CONTROL = 0x87
SERVICE_READ_DATA_BY_IDENTIFIER = 0x22
SERVICE_READ_MEMORY_BY_ADDRESS = 0x23
SERVICE_READ_SCALING_DATA_BY_IDENTIFIER = 0x24
SERVICE_READ_DATA_BY_PERIODIC_IDENTIFIER = 0x2A
SERVICE_DYNAMICALLY_DEFINE_DATA_IDENTIFIER = 0x2C
SERVICE_WRITE_DATA_BY_IDENTIFIER = 0x2E
SERVICE_WRITE_MEMORY_BY_ADDRESS = 0x3D
SERVICE_CLEAR_DIAGNOSTIC_INFORMATION = 0x14
SERVICE_READ_DTC_INFORMATION = 0x19
SERVICE_INPUT_OUTPUT_CONTROL_BY_IDENTIFIER = 0x2F
SERVICE_ROUTINE_CONTROL = 0x31
SERVICE_REQUEST_DOWNLOAD = 0x34
SERVICE_REQUEST_UPLOAD = 0x35
SERVICE_TRANSFER_DATA = 0x36
SERVICE_REQUEST_TRANSFER_EXIT = 0x37
SERVICE_REQUEST_FILE_TRANSFER = 0x38

# Negative response
SERVICE_NEGATIVE_RESPONSE = 0x7F

# Positive response offset
POSITIVE_RESPONSE_OFFSET = 0x40
```

---

### **Constants - Diagnostic Session Types**:
```python
# Diagnostic Session Types (for service 0x10)
SESSION_DEFAULT = 0x01                    # Default session
SESSION_PROGRAMMING = 0x02                # Programming session
SESSION_EXTENDED_DIAGNOSTIC = 0x03        # Extended diagnostic session
SESSION_SAFETY_SYSTEM_DIAGNOSTIC = 0x04   # Safety system diagnostic
```

---

### **Constants - ECU Reset Types**:
```python
# ECU Reset Types (for service 0x11)
RESET_HARD = 0x01                 # Hard reset
RESET_KEY_OFF_ON = 0x02          # Key off/on reset
RESET_SOFT = 0x03                # Soft reset
RESET_ENABLE_RAPID_POWER_SHUTDOWN = 0x04
RESET_DISABLE_RAPID_POWER_SHUTDOWN = 0x05
```

---

### **Constants - Negative Response Codes**:
```python
# Negative Response Codes (NRC)
NRC_GENERAL_REJECT = 0x10
NRC_SERVICE_NOT_SUPPORTED = 0x11
NRC_SUB_FUNCTION_NOT_SUPPORTED = 0x12
NRC_INCORRECT_MESSAGE_LENGTH = 0x13
NRC_RESPONSE_TOO_LONG = 0x14
NRC_BUSY_REPEAT_REQUEST = 0x21
NRC_CONDITIONS_NOT_CORRECT = 0x22
NRC_REQUEST_SEQUENCE_ERROR = 0x24
NRC_NO_RESPONSE_FROM_SUBNET = 0x25
NRC_FAILURE_PREVENTS_EXECUTION = 0x26
NRC_REQUEST_OUT_OF_RANGE = 0x31
NRC_SECURITY_ACCESS_DENIED = 0x33
NRC_INVALID_KEY = 0x35
NRC_EXCEED_NUMBER_OF_ATTEMPTS = 0x36
NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED = 0x37
NRC_UPLOAD_DOWNLOAD_NOT_ACCEPTED = 0x70
NRC_TRANSFER_DATA_SUSPENDED = 0x71
NRC_GENERAL_PROGRAMMING_FAILURE = 0x72
NRC_WRONG_BLOCK_SEQUENCE_COUNTER = 0x73
NRC_RESPONSE_PENDING = 0x78
NRC_SUB_FUNCTION_NOT_SUPPORTED_IN_ACTIVE_SESSION = 0x7E
NRC_SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION = 0x7F

# NRC descriptions
NRC_DESCRIPTIONS = {
    NRC_GENERAL_REJECT: "General reject",
    NRC_SERVICE_NOT_SUPPORTED: "Service not supported",
    NRC_SUB_FUNCTION_NOT_SUPPORTED: "Sub-function not supported",
    NRC_INCORRECT_MESSAGE_LENGTH: "Incorrect message length or invalid format",
    NRC_RESPONSE_TOO_LONG: "Response too long",
    NRC_BUSY_REPEAT_REQUEST: "Busy, repeat request",
    NRC_CONDITIONS_NOT_CORRECT: "Conditions not correct",
    NRC_REQUEST_SEQUENCE_ERROR: "Request sequence error",
    NRC_NO_RESPONSE_FROM_SUBNET: "No response from subnet component",
    NRC_FAILURE_PREVENTS_EXECUTION: "Failure prevents execution of requested action",
    NRC_REQUEST_OUT_OF_RANGE: "Request out of range",
    NRC_SECURITY_ACCESS_DENIED: "Security access denied",
    NRC_INVALID_KEY: "Invalid key",
    NRC_EXCEED_NUMBER_OF_ATTEMPTS: "Exceeded number of attempts",
    NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED: "Required time delay not expired",
    NRC_UPLOAD_DOWNLOAD_NOT_ACCEPTED: "Upload/download not accepted",
    NRC_TRANSFER_DATA_SUSPENDED: "Transfer data suspended",
    NRC_GENERAL_PROGRAMMING_FAILURE: "General programming failure",
    NRC_WRONG_BLOCK_SEQUENCE_COUNTER: "Wrong block sequence counter",
    NRC_RESPONSE_PENDING: "Response pending",
    NRC_SUB_FUNCTION_NOT_SUPPORTED_IN_ACTIVE_SESSION: "Sub-function not supported in active session",
    NRC_SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION: "Service not supported in active session",
}
```

---

### **Constants - Common Data Identifiers**:
```python
# Common Data Identifiers (DIDs) for service 0x22
DID_ACTIVE_DIAGNOSTIC_SESSION = 0xF186
DID_VEHICLE_MANUFACTURER_SPARE_PART_NUMBER = 0xF187
DID_VEHICLE_MANUFACTURER_ECU_SOFTWARE_NUMBER = 0xF188
DID_VEHICLE_MANUFACTURER_ECU_SOFTWARE_VERSION = 0xF189
DID_SYSTEM_SUPPLIER_IDENTIFIER = 0xF18A
DID_ECU_MANUFACTURING_DATE_AND_TIME = 0xF18B
DID_ECU_SERIAL_NUMBER = 0xF18C
DID_VIN = 0xF190                                         # Vehicle Identification Number
DID_ECU_HARDWARE_NUMBER = 0xF191
DID_SYSTEM_SUPPLIER_ECU_HARDWARE_VERSION = 0xF193
DID_SYSTEM_SUPPLIER_ECU_SOFTWARE_VERSION = 0xF195
DID_BOOT_SOFTWARE_IDENTIFICATION = 0xF19E
```

---

### **Function 1: `build_uds_request()`**
**Purpose**: Build UDS request frame

**Implementation**:
```python
def build_uds_request(
    service: int,
    data: Optional[bytes] = None,
    ecu_id: int = 0x7E0
) -> Message:
    """
    Build a UDS request frame.
    
    Args:
        service: UDS service ID (0x10-0x3E, etc.)
        data: Optional service-specific data
        ecu_id: Target ECU ID
    
    Returns:
        CAN Message object
    
    Example:
        >>> # Request diagnostic session (service 0x10, extended session 0x03)
        >>> frame = build_uds_request(0x10, bytes([0x03]))
        >>> print(frame.data.hex())
        '021003...'
    """
    request_data = bytes([service])
    
    if data:
        request_data += data
    
    # Pad to 8 bytes
    request_data = request_data.ljust(8, b'\x00')
    
    # First byte is length
    length = 1 + (len(data) if data else 0)
    request_data = bytes([length]) + request_data[1:]
    
    return build_frame(ecu_id, request_data)
```

---

### **Function 2: `build_diagnostic_session()`**
**Purpose**: Build diagnostic session control request

**Implementation**:
```python
def build_diagnostic_session(
    session_type: int,
    ecu_id: int = 0x7E0
) -> Message:
    """
    Build diagnostic session control request (service 0x10).
    
    Args:
        session_type: Session type (0x01-0x04)
        ecu_id: Target ECU ID
    
    Returns:
        CAN Message
    
    Example:
        >>> # Enter extended diagnostic session
        >>> frame = build_diagnostic_session(0x03)
    """
    return build_uds_request(
        SERVICE_DIAGNOSTIC_SESSION_CONTROL,
        bytes([session_type]),
        ecu_id
    )
```

---

### **Function 3: `build_read_did()`**
**Purpose**: Build read data by identifier request

**Implementation**:
```python
def build_read_did(
    did: int,
    ecu_id: int = 0x7E0
) -> Message:
    """
    Build read data by identifier request (service 0x22).
    
    Args:
        did: Data Identifier (16-bit)
        ecu_id: Target ECU ID
    
    Returns:
        CAN Message
    
    Example:
        >>> # Read VIN
        >>> frame = build_read_did(0xF190)
    """
    # DID is 2 bytes (big-endian)
    did_bytes = did.to_bytes(2, byteorder='big')
    
    return build_uds_request(
        SERVICE_READ_DATA_BY_IDENTIFIER,
        did_bytes,
        ecu_id
    )
```

---

### **Function 4: `build_security_access()`**
**Purpose**: Build security access request

**Implementation**:
```python
def build_security_access(
    level: int,
    key: Optional[bytes] = None,
    ecu_id: int = 0x7E0
) -> Message:
    """
    Build security access request (service 0x27).
    
    Args:
        level: Access level (odd=request seed, even=send key)
        key: Key bytes (for even levels)
        ecu_id: Target ECU ID
    
    Returns:
        CAN Message
    
    Example:
        >>> # Request seed for level 1
        >>> frame = build_security_access(0x01)
        >>> # Send key for level 2
        >>> frame = build_security_access(0x02, bytes([0x12, 0x34, 0x56, 0x78]))
    """
    data = bytes([level])
    if key:
        data += key
    
    return build_uds_request(SERVICE_SECURITY_ACCESS, data, ecu_id)
```

---

### **Function 5: `build_tester_present()`**
**Purpose**: Build tester present request

**Implementation**:
```python
def build_tester_present(ecu_id: int = 0x7E0) -> Message:
    """
    Build tester present request (service 0x3E).
    
    Keeps ECU in diagnostic mode.
    
    Args:
        ecu_id: Target ECU ID
    
    Returns:
        CAN Message
    
    Example:
        >>> frame = build_tester_present()
    """
    # Sub-function 0x00 = suppress positive response
    return build_uds_request(SERVICE_TESTER_PRESENT, bytes([0x00]), ecu_id)
```

---

### **Function 6: `parse_uds_response()`**
**Purpose**: Parse UDS response

**Implementation**:
```python
def parse_uds_response(message: Message) -> Dict[str, Any]:
    """
    Parse a UDS response frame.
    
    Args:
        message: CAN Message containing response
    
    Returns:
        Dict with parsed response
    
    Example:
        >>> # Positive response for diagnostic session
        >>> msg = Message(arbitration_id=0x7E8, data=[0x02, 0x50, 0x03])
        >>> response = parse_uds_response(msg)
        >>> print(response['is_positive'])
        True
    """
    data = bytes(message.data)
    
    # Minimum length check
    if len(data) < 2:
        return {
            'ecu_id': message.arbitration_id,
            'is_positive': False,
            'error': 'Response too short'
        }
    
    length = data[0]
    service = data[1]
    
    # Check if negative response
    if service == SERVICE_NEGATIVE_RESPONSE:
        if len(data) >= 4:
            requested_service = data[2]
            nrc = data[3]
            
            return {
                'ecu_id': message.arbitration_id,
                'is_positive': False,
                'is_negative': True,
                'requested_service': requested_service,
                'nrc': nrc,
                'nrc_description': get_nrc_description(nrc),
                'raw': data
            }
        else:
            return {
                'ecu_id': message.arbitration_id,
                'is_positive': False,
                'is_negative': True,
                'error': 'Malformed negative response'
            }
    
    # Positive response (service + 0x40)
    if service >= POSITIVE_RESPONSE_OFFSET:
        actual_service = service - POSITIVE_RESPONSE_OFFSET
        response_data = data[2:2+length-1] if length > 1 else bytes()
        
        return {
            'ecu_id': message.arbitration_id,
            'is_positive': True,
            'is_negative': False,
            'service': actual_service,
            'data': response_data,
            'raw': data
        }
    
    # Unknown response format
    return {
        'ecu_id': message.arbitration_id,
        'is_positive': False,
        'error': 'Unknown response format',
        'raw': data
    }
```

---

### **Function 7: `is_positive_response()`**
**Purpose**: Check if response is positive

**Implementation**:
```python
def is_positive_response(data: bytes) -> bool:
    """
    Check if response is a positive response.
    
    Args:
        data: Response data bytes
    
    Returns:
        True if positive response
    
    Example:
        >>> is_positive_response(bytes([0x02, 0x50, 0x03]))
        True
        >>> is_positive_response(bytes([0x03, 0x7F, 0x10, 0x11]))
        False
    """
    if len(data) < 2:
        return False
    
    service = data[1]
    return service >= POSITIVE_RESPONSE_OFFSET and service != SERVICE_NEGATIVE_RESPONSE
```

---

### **Function 8: `is_negative_response()`**
**Purpose**: Check if response is negative

**Implementation**:
```python
def is_negative_response(data: bytes) -> bool:
    """
    Check if response is a negative response.
    
    Args:
        data: Response data bytes
    
    Returns:
        True if negative response
    
    Example:
        >>> is_negative_response(bytes([0x03, 0x7F, 0x10, 0x11]))
        True
    """
    if len(data) < 2:
        return False
    
    return data[1] == SERVICE_NEGATIVE_RESPONSE
```

---

### **Function 9: `get_nrc_description()`**
**Purpose**: Get description of negative response code

**Implementation**:
```python
def get_nrc_description(nrc: int) -> str:
    """
    Get description of negative response code.
    
    Args:
        nrc: Negative response code
    
    Returns:
        Human-readable description
    
    Example:
        >>> print(get_nrc_description(0x11))
        Service not supported
    """
    return NRC_DESCRIPTIONS.get(nrc, f"Unknown NRC: 0x{nrc:02X}")
```

---

### **Complete `uds.py` File Structure**:

```python
"""
UDS protocol support.
"""

from typing import Dict, Any, Optional, List
from can import Message
from .can_utils import build_frame

# [All constants above]

# [All functions above]
```

---

## ✅ Testing Strategy

### **Test File 1: `tests/unit/test_can_utils.py`**
```bash
# Test all CAN utility functions
uv run pytest tests/unit/test_can_utils.py -v
```

### **Test File 2: `tests/unit/test_obd.py`**
```bash
# Test OBD-II frame building and parsing
uv run pytest tests/unit/test_obd.py -v
```

### **Test File 3: `tests/unit/test_uds.py`**
```bash
# Test UDS request/response handling
uv run pytest tests/unit/test_uds.py -v
```

---

## 📋 Verification Checklist

Before considering Task 1.5 complete:

- [ ] `src/autosploit/lib/protocols/can_utils.py` created
- [ ] `src/autosploit/lib/protocols/obd.py` created
- [ ] `src/autosploit/lib/protocols/uds.py` created
- [ ] All functions implemented (no `pass` statements)
- [ ] All constants defined
- [ ] Comprehensive docstrings on all functions
- [ ] Unit tests created for all three files
- [ ] All tests passing
- [ ] 85%+ code coverage
- [ ] No linting errors: `uv run ruff check src/autosploit/lib/protocols/`
- [ ] No type errors: `uv run mypy src/autosploit/lib/protocols/`

**Test Commands**:
```bash
# Run all protocol tests
uv run pytest tests/unit/test_*protocol*.py -v

# With coverage
uv run pytest tests/unit/ --cov=src/autosploit/lib/protocols --cov-report=html
```

---

## 🎯 Summary

**What You Built**:
- CAN frame utilities (building, parsing, validation)
- OBD-II protocol support (modes, PIDs, decoding)
- UDS protocol support (services, DIDs, negative responses)

**Why It Matters**:
These are the "language translators" that modules use to talk to vehicles. Instead of every module reimplementing OBD-II or UDS, they just import these functions.

**Ready For**: Week 2 - Configuration, Safety, and First Modules!

**Total Implementation Time**: 4-5 hours (1.5hrs + 1.5hrs + 1.5hrs)