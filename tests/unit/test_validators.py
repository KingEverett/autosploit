import pytest
from pathlib import Path

from autosploit.lib.utils.validators import (
    ValidationResult,
    validate_can_id,
    validate_can_data,
    validate_dlc,
    validate_interface_name,
    validate_bitrate,
    validate_range,
    validate_choice,
    validate_path,
    validate_hex_string,
)


class TestValidationResult:
    def test_create_valid_result(self):
        result = ValidationResult(is_valid=True)

        assert result.is_valid is True
        assert result.error_message is None
        assert result.suggestion is None
        assert bool(result) is True

    def test_create_invalid_result(self):
        result = ValidationResult(
            is_valid=False,
            error_message="Test error",
            suggestion="Test suggestion"
        )

        assert result.is_valid is False
        assert result.error_message == "Test error"
        assert result.suggestion == "Test suggestion"
        assert bool(result) is False

    def test_raise_if_invalid_success(self):
        result = ValidationResult(is_valid=True)
        result.raise_if_invalid()  # Should not raise

    def test_raise_if_invalid_error(self):
        result = ValidationResult(
            is_valid=False,
            error_message="Test error",
            suggestion="Test suggestion"
        )

        with pytest.raises(ValueError) as exc_info:
            result.raise_if_invalid()

        assert "Test error" in str(exc_info.value)
        assert "Test suggestion" in str(exc_info.value)


class TestValidateCanId:
    def test_valid_standard_ids(self):
        assert validate_can_id(0x000).is_valid
        assert validate_can_id(0x123).is_valid
        assert validate_can_id(0x7FF).is_valid

    def test_valid_extended_ids(self):
        assert validate_can_id(0x00000000, extended=True).is_valid
        assert validate_can_id(0x12345678, extended=True).is_valid
        assert validate_can_id(0x1FFFFFFF, extended=True).is_valid

    def test_invalid_standard_id_too_large(self):
        result = validate_can_id(0x800)
        assert not result.is_valid
        assert "exceeds maximum" in result.error_message
        assert "0X7FF" in result.error_message

    def test_invalid_extended_id_too_large(self):
        result = validate_can_id(0x20000000, extended=True)
        assert not result.is_valid
        assert "exceeds maximum" in result.error_message

    def test_invalid_negative_id(self):
        result = validate_can_id(-1)
        assert not result.is_valid
        assert "negative" in result.error_message

    def test_invalid_type(self):
        result = validate_can_id("0x123")
        assert not result.is_valid
        assert "must be an integer" in result.error_message

    def test_zero_not_allowed(self):
        result = validate_can_id(0, allow_zero=False)
        assert not result.is_valid
        assert "0x000 is not allowed" in result.error_message

    def test_zero_allowed(self):
        result = validate_can_id(0, allow_zero=True)
        assert result.is_valid


class TestValidateCanData:
    def test_valid_data(self):
        assert validate_can_data(b"").is_valid
        assert validate_can_data(b"\x01\x02\x03").is_valid
        assert validate_can_data(b"\x01\x02\x03\x04\x05\x06\x07\x08").is_valid

    def test_valid_bytearray(self):
        assert validate_can_data(bytearray(b"\x01\x02")).is_valid

    def test_invalid_too_long(self):
        result = validate_can_data(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09")
        assert not result.is_valid
        assert "exceeds maximum" in result.error_message

    def test_invalid_type(self):
        result = validate_can_data("01 02 03")
        assert not result.is_valid
        assert "must be bytes" in result.error_message

    def test_can_fd_length(self):
        long_data = b"\x01" * 32
        assert validate_can_data(long_data, max_length=64).is_valid


class TestValidateDlc:
    def test_valid_can_dlc(self):
        for dlc in range(9):
            assert validate_dlc(dlc).is_valid

    def test_valid_can_fd_dlc(self):
        for dlc in range(16):
            assert validate_dlc(dlc, can_fd=True).is_valid

    def test_invalid_can_dlc_too_large(self):
        result = validate_dlc(9)
        assert not result.is_valid
        assert "exceeds maximum 8" in result.error_message

    def test_invalid_can_fd_dlc_too_large(self):
        result = validate_dlc(16, can_fd=True)
        assert not result.is_valid
        assert "exceeds maximum 15" in result.error_message

    def test_invalid_negative_dlc(self):
        result = validate_dlc(-1)
        assert not result.is_valid
        assert "negative" in result.error_message

    def test_invalid_type(self):
        result = validate_dlc("8")
        assert not result.is_valid
        assert "must be an integer" in result.error_message


class TestValidateInterfaceName:
    def test_valid_socketcan_names(self):
        assert validate_interface_name("can0", "socketcan").is_valid
        assert validate_interface_name("can15", "socketcan").is_valid
        assert validate_interface_name("vcan0", "socketcan").is_valid

    def test_valid_slcan_names(self):
        assert validate_interface_name("slcan0", "slcan").is_valid
        assert validate_interface_name("slcan5", "slcan").is_valid

    def test_valid_pcan_names(self):
        assert validate_interface_name("PCAN_USB1", "pcan").is_valid
        assert validate_interface_name("PCAN_USBBUS1", "pcan").is_valid

    def test_invalid_socketcan_name(self):
        result = validate_interface_name("invalid", "socketcan")
        assert not result.is_valid
        assert "invalid for type" in result.error_message

    def test_empty_name(self):
        result = validate_interface_name("", "socketcan")
        assert not result.is_valid
        assert "cannot be empty" in result.error_message

    def test_invalid_type(self):
        result = validate_interface_name(123, "socketcan")
        assert not result.is_valid
        assert "must be a string" in result.error_message

    def test_unknown_interface_type(self):
        assert validate_interface_name("test123", "unknown").is_valid


class TestValidateBitrate:
    def test_valid_common_bitrates(self):
        common_bitrates = [125000, 250000, 500000, 1000000]
        for bitrate in common_bitrates:
            assert validate_bitrate(bitrate).is_valid

    def test_valid_non_standard_bitrate(self):
        result = validate_bitrate(333333)
        assert result.is_valid
        assert "non-standard" in result.suggestion

    def test_invalid_too_low(self):
        result = validate_bitrate(1000)
        assert not result.is_valid
        assert "too low" in result.error_message

    def test_invalid_too_high(self):
        result = validate_bitrate(2000000)
        assert not result.is_valid
        assert "exceeds maximum" in result.error_message

    def test_invalid_type(self):
        result = validate_bitrate("500000")
        assert not result.is_valid
        assert "must be an integer" in result.error_message


class TestValidateRange:
    def test_valid_range(self):
        assert validate_range(50, 0, 100, "percentage").is_valid
        assert validate_range(0, 0, 100).is_valid
        assert validate_range(100, 0, 100).is_valid

    def test_invalid_below_range(self):
        result = validate_range(-1, 0, 100, "value")
        assert not result.is_valid
        assert "out of range" in result.error_message

    def test_invalid_above_range(self):
        result = validate_range(101, 0, 100, "value")
        assert not result.is_valid
        assert "out of range" in result.error_message

    def test_invalid_type(self):
        result = validate_range("50", 0, 100, "value")
        assert not result.is_valid
        assert "must be an integer" in result.error_message


class TestValidateChoice:
    def test_valid_choice(self):
        assert validate_choice("red", ["red", "green", "blue"], "color").is_valid
        assert validate_choice(1, [1, 2, 3], "number").is_valid

    def test_invalid_choice(self):
        result = validate_choice("yellow", ["red", "green", "blue"], "color")
        assert not result.is_valid
        assert "is not valid" in result.error_message
        assert "'red'" in result.suggestion

    def test_choice_formatting(self):
        result = validate_choice(4, [1, 2, 3], "number")
        assert not result.is_valid
        assert "1, 2, 3" in result.suggestion


class TestValidatePath:
    def test_valid_existing_file(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        assert validate_path(str(test_file), must_exist=True, must_be_file=True).is_valid

    def test_valid_existing_dir(self, tmp_path):
        assert validate_path(str(tmp_path), must_exist=True, must_be_dir=True).is_valid

    def test_valid_non_existing_path(self, tmp_path):
        non_existing = tmp_path / "non_existing.txt"
        assert validate_path(str(non_existing), allow_create=True).is_valid

    def test_invalid_non_existing_path(self, tmp_path):
        non_existing = tmp_path / "non_existing.txt"
        result = validate_path(str(non_existing), must_exist=True)
        assert not result.is_valid
        assert "does not exist" in result.error_message

    def test_invalid_file_as_dir(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("test")

        result = validate_path(str(test_file), must_be_dir=True)
        assert not result.is_valid
        assert "not a directory" in result.error_message

    def test_invalid_type(self):
        result = validate_path(123)
        assert not result.is_valid
        assert "must be a string" in result.error_message


class TestValidateHexString:
    def test_valid_hex_strings(self):
        assert validate_hex_string("0x1A2B").is_valid
        assert validate_hex_string("DEADBEEF").is_valid
        assert validate_hex_string("123abc").is_valid
        assert validate_hex_string("0X1A2B").is_valid

    def test_invalid_hex_string(self):
        result = validate_hex_string("GHIJ")
        assert not result.is_valid
        assert "Invalid hexadecimal" in result.error_message

    def test_empty_hex_string(self):
        result = validate_hex_string("")
        assert not result.is_valid
        assert "cannot be empty" in result.error_message

    def test_invalid_type(self):
        result = validate_hex_string(123)
        assert not result.is_valid
        assert "must be a string" in result.error_message