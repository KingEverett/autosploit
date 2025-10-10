"""
UDS (Unified Diagnostic Services) protocol support.

Implements ISO 14229 diagnostic services for automotive ECUs.
"""

from typing import Dict, Any, Optional, List
from can import Message
from .can_utils import build_frame

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

# Diagnostic Session Types (for service 0x10)
SESSION_DEFAULT = 0x01
SESSION_PROGRAMMING = 0x02
SESSION_EXTENDED_DIAGNOSTIC = 0x03
SESSION_SAFETY_SYSTEM_DIAGNOSTIC = 0x04

# ECU Reset Types (for service 0x11)
RESET_HARD = 0x01
RESET_KEY_OFF_ON = 0x02
RESET_SOFT = 0x03
RESET_ENABLE_RAPID_POWER_SHUTDOWN = 0x04
RESET_DISABLE_RAPID_POWER_SHUTDOWN = 0x05

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

# Common Data Identifiers (DIDs) for service 0x22
DID_ACTIVE_DIAGNOSTIC_SESSION = 0xF186
DID_VEHICLE_MANUFACTURER_SPARE_PART_NUMBER = 0xF187
DID_VEHICLE_MANUFACTURER_ECU_SOFTWARE_NUMBER = 0xF188
DID_VEHICLE_MANUFACTURER_ECU_SOFTWARE_VERSION = 0xF189
DID_SYSTEM_SUPPLIER_IDENTIFIER = 0xF18A
DID_ECU_MANUFACTURING_DATE_AND_TIME = 0xF18B
DID_ECU_SERIAL_NUMBER = 0xF18C
DID_VIN = 0xF190
DID_ECU_HARDWARE_NUMBER = 0xF191
DID_SYSTEM_SUPPLIER_ECU_HARDWARE_VERSION = 0xF193
DID_SYSTEM_SUPPLIER_ECU_SOFTWARE_VERSION = 0xF195
DID_BOOT_SOFTWARE_IDENTIFICATION = 0xF19E


def build_uds_request(
    service: int,
    data: Optional[bytes] = None,
    ecu_id: int = 0x7E0
) -> Message:
    """Build a UDS request frame."""
    request_data = bytes([service])

    if data:
        request_data += data

    # First byte is length
    length = len(request_data)
    request_data = bytes([length]) + request_data

    # Pad to 8 bytes
    request_data = request_data.ljust(8, b'\x00')

    return build_frame(ecu_id, request_data)


def build_diagnostic_session(
    session_type: int,
    ecu_id: int = 0x7E0
) -> Message:
    """Build diagnostic session control request (service 0x10)."""
    return build_uds_request(
        SERVICE_DIAGNOSTIC_SESSION_CONTROL,
        bytes([session_type]),
        ecu_id
    )


def build_read_did(
    did: int,
    ecu_id: int = 0x7E0
) -> Message:
    """Build read data by identifier request (service 0x22)."""
    # DID is 2 bytes (big-endian)
    did_bytes = did.to_bytes(2, byteorder='big')

    return build_uds_request(
        SERVICE_READ_DATA_BY_IDENTIFIER,
        did_bytes,
        ecu_id
    )


def build_security_access(
    level: int,
    key: Optional[bytes] = None,
    ecu_id: int = 0x7E0
) -> Message:
    """Build security access request (service 0x27)."""
    data = bytes([level])
    if key:
        data += key

    return build_uds_request(SERVICE_SECURITY_ACCESS, data, ecu_id)


def build_tester_present(ecu_id: int = 0x7E0) -> Message:
    """Build tester present request (service 0x3E)."""
    # Sub-function 0x00 = suppress positive response
    return build_uds_request(SERVICE_TESTER_PRESENT, bytes([0x00]), ecu_id)


def parse_uds_response(message: Message) -> Dict[str, Any]:
    """Parse a UDS response frame."""
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


def is_positive_response(data: bytes) -> bool:
    """Check if response is a positive response."""
    if len(data) < 2:
        return False

    service = data[1]
    return service >= POSITIVE_RESPONSE_OFFSET and service != SERVICE_NEGATIVE_RESPONSE


def is_negative_response(data: bytes) -> bool:
    """Check if response is a negative response."""
    if len(data) < 2:
        return False

    return data[1] == SERVICE_NEGATIVE_RESPONSE


def get_nrc_description(nrc: int) -> str:
    """Get description of negative response code."""
    return NRC_DESCRIPTIONS.get(nrc, f"Unknown NRC: 0x{nrc:02X}")