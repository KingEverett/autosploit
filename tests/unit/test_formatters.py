import pytest
from unittest.mock import Mock
import can

from autosploit.lib.utils.formatters import (
    format_can_frame,
    format_can_id,
    format_can_data,
    parse_can_data,
    create_module_table,
    create_options_table,
    create_progress_bar,
    create_spinner,
    format_status,
    print_success,
    print_error,
    print_info,
    print_warning,
)
from rich.table import Table
from rich.progress import Progress
from rich.live import Live
from rich.text import Text


class TestFormatCanFrame:
    def test_basic_frame_formatting(self):
        msg = can.Message(arbitration_id=0x123, data=b"\x01\x02\x03", is_extended_id=False)

        result = format_can_frame(msg)

        assert "0x123" in result
        assert "[3]" in result
        assert "01 02 03" in result

    def test_frame_with_timestamp(self):
        msg = can.Message(arbitration_id=0x123, data=b"\x01\x02", timestamp=1234.567890, is_extended_id=False)

        result = format_can_frame(msg, include_timestamp=True)

        assert "1234.567890" in result
        assert "0x123" in result

    def test_empty_data_frame(self):
        msg = can.Message(arbitration_id=0x123, data=b"", is_extended_id=False)

        result = format_can_frame(msg)

        assert "0x123" in result
        assert "[0]" in result

    def test_remote_frame(self):
        msg = can.Message(arbitration_id=0x123, data=b"", is_remote_frame=True)

        result = format_can_frame(msg)

        assert "(RTR)" in result

    def test_error_frame(self):
        msg = can.Message(arbitration_id=0x123, data=b"", is_error_frame=True)

        result = format_can_frame(msg)

        assert "(ERR)" in result

    def test_extended_frame(self):
        msg = can.Message(arbitration_id=0x12345678, data=b"\x01", is_extended_id=True)

        result = format_can_frame(msg)

        assert "0x12345678" in result


class TestFormatCanId:
    def test_standard_id_formatting(self):
        assert format_can_id(0x123) == "0x123"
        assert format_can_id(0x7FF) == "0x7FF"
        assert format_can_id(0x001) == "0x001"

    def test_extended_id_formatting(self):
        assert format_can_id(0x12345678, extended=True) == "0x12345678"
        assert format_can_id(0x1FFFFFFF, extended=True) == "0x1FFFFFFF"
        assert format_can_id(0x00000001, extended=True) == "0x00000001"


class TestFormatCanData:
    def test_default_separator(self):
        assert format_can_data(b"\x01\x02\x03") == "01 02 03"
        assert format_can_data(b"\xFF\x00\xAB") == "FF 00 AB"

    def test_custom_separator(self):
        assert format_can_data(b"\x01\x02\x03", separator=":") == "01:02:03"
        assert format_can_data(b"\x01\x02\x03", separator="-") == "01-02-03"

    def test_empty_data(self):
        assert format_can_data(b"") == ""


class TestParseCanData:
    def test_space_separated(self):
        assert parse_can_data("01 02 03") == b"\x01\x02\x03"
        assert parse_can_data("FF 00 AB") == b"\xFF\x00\xAB"

    def test_colon_separated(self):
        assert parse_can_data("01:02:03") == b"\x01\x02\x03"

    def test_comma_separated(self):
        assert parse_can_data("01,02,03") == b"\x01\x02\x03"

    def test_hex_prefixes(self):
        assert parse_can_data("0x01 0x02 0x03") == b"\x01\x02\x03"
        assert parse_can_data("0x01, 0x02, 0x03") == b"\x01\x02\x03"

    def test_mixed_separators(self):
        assert parse_can_data("0x01, 02:03 04") == b"\x01\x02\x03\x04"

    def test_empty_string(self):
        assert parse_can_data("") == b""


class TestCreateModuleTable:
    def test_basic_module_table(self):
        modules = [
            {
                "name": "test_module",
                "category": "scanner",
                "risk_level": "low",
                "description": "Test description"
            }
        ]

        table = create_module_table(modules)

        assert isinstance(table, Table)
        assert table.title
        assert len(table.columns) == 4

    def test_empty_module_list(self):
        table = create_module_table([])

        assert isinstance(table, Table)
        assert len(table.rows) == 0

    def test_module_with_missing_fields(self):
        modules = [{"name": "incomplete_module"}]

        table = create_module_table(modules)

        assert isinstance(table, Table)

    def test_risk_level_coloring(self):
        modules = [
            {"name": "low_risk", "risk_level": "low"},
            {"name": "high_risk", "risk_level": "high"},
            {"name": "critical_risk", "risk_level": "critical"},
        ]

        table = create_module_table(modules)

        assert isinstance(table, Table)
        assert len(table.rows) == 3


class TestCreateOptionsTable:
    def test_basic_options_table(self):
        options = {
            "target_id": {
                "value": "0x123",
                "required": True,
                "description": "Target CAN ID"
            },
            "timeout": {
                "value": 10,
                "required": False,
                "description": "Timeout in seconds"
            }
        }

        table = create_options_table(options)

        assert isinstance(table, Table)
        assert len(table.columns) == 4

    def test_empty_options(self):
        table = create_options_table({})

        assert isinstance(table, Table)
        assert len(table.rows) == 0

    def test_unset_values(self):
        options = {
            "unset_option": {
                "value": None,
                "required": True,
                "description": "Not set"
            }
        }

        table = create_options_table(options)

        assert isinstance(table, Table)

    def test_large_integer_formatting(self):
        options = {
            "large_value": {
                "value": 1024,
                "required": False,
                "description": "Large integer"
            }
        }

        table = create_options_table(options)

        assert isinstance(table, Table)


class TestCreateProgressBar:
    def test_basic_progress_bar(self):
        progress = create_progress_bar(100)

        assert isinstance(progress, Progress)

    def test_progress_bar_with_time(self):
        progress = create_progress_bar(100, show_time=True)

        assert isinstance(progress, Progress)

    def test_progress_bar_without_time(self):
        progress = create_progress_bar(100, show_time=False)

        assert isinstance(progress, Progress)


class TestCreateSpinner:
    def test_basic_spinner(self):
        spinner = create_spinner()

        assert isinstance(spinner, Live)

    def test_custom_spinner(self):
        spinner = create_spinner("Custom task", "dots2")

        assert isinstance(spinner, Live)


class TestFormatStatus:
    def test_info_status(self):
        result = format_status("Test message", "info")

        assert isinstance(result, Text)

    def test_success_status(self):
        result = format_status("Success message", "success")

        assert isinstance(result, Text)

    def test_error_status(self):
        result = format_status("Error message", "error")

        assert isinstance(result, Text)

    def test_warning_status(self):
        result = format_status("Warning message", "warning")

        assert isinstance(result, Text)

    def test_debug_status(self):
        result = format_status("Debug message", "debug")

        assert isinstance(result, Text)

    def test_unknown_status(self):
        result = format_status("Unknown message", "unknown")

        assert isinstance(result, Text)

    def test_with_timestamp(self):
        result = format_status("Test message", "info", include_timestamp=True)

        assert isinstance(result, Text)


class TestPrintFunctions:
    def test_print_success(self, capsys):
        print_success("Success message")

        captured = capsys.readouterr()
        assert "Success message" in captured.out

    def test_print_error(self, capsys):
        print_error("Error message")

        captured = capsys.readouterr()
        assert "Error message" in captured.out

    def test_print_info(self, capsys):
        print_info("Info message")

        captured = capsys.readouterr()
        assert "Info message" in captured.out

    def test_print_warning(self, capsys):
        print_warning("Warning message")

        captured = capsys.readouterr()
        assert "Warning message" in captured.out