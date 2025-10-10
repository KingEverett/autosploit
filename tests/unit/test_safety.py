import pytest
import time
import signal
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from threading import Event

from autosploit.lib.safety.manager import (
    SafetyManager,
    SafetyViolation,
    BusHealthMetrics,
)
from autosploit.lib.safety.decorators import (
    require_confirmation,
    rate_limit,
    blacklist_check,
    safe_can_operation,
)
from autosploit.lib.safety.rate_limiter import RateLimiter
from autosploit.lib.safety.blacklist import BlacklistManager, BlacklistEntry
from autosploit.core.config import SafetyConfig


@pytest.fixture
def safety_config():
    return SafetyConfig(
        require_confirmation=True,
        dangerous_ids=[0x100, 0x200, 0x300],
        max_messages_per_second=10,
        enable_bus_monitoring=True,
        emergency_stop_enabled=True,
        auto_backup_before_write=True,
        monitor_interval_seconds=0.1,
        error_threshold=5,
    )


@pytest.fixture
def safety_manager(safety_config):
    return SafetyManager(safety_config)


class TestSafetyViolation:
    def test_create_violation(self):
        violation = SafetyViolation(
            timestamp=datetime.now(),
            violation_type="test",
            details="Test violation",
            severity="medium",
            action_taken="blocked",
            context={"key": "value"}
        )

        assert violation.violation_type == "test"
        assert violation.severity == "medium"
        assert violation.context["key"] == "value"

    def test_to_dict(self):
        violation = SafetyViolation(
            timestamp=datetime.now(),
            violation_type="test",
            details="Test",
            severity="low",
            action_taken="logged"
        )

        d = violation.to_dict()

        assert isinstance(d, dict)
        assert "timestamp" in d
        assert d["violation_type"] == "test"


class TestBusHealthMetrics:
    def test_create_metrics(self):
        metrics = BusHealthMetrics()

        assert metrics.error_frame_count == 0
        assert metrics.message_rate == 0.0
        assert len(metrics.unique_ids_seen) == 0

    def test_reset_metrics(self):
        metrics = BusHealthMetrics()
        metrics.error_frame_count = 10
        metrics.unique_ids_seen.add(0x123)

        metrics.reset()

        assert metrics.error_frame_count == 0
        assert len(metrics.unique_ids_seen) == 0


class TestSafetyManager:
    def test_initialization(self, safety_manager):
        assert safety_manager is not None
        assert len(safety_manager._blacklisted_ids) == 3
        assert 0x100 in safety_manager._blacklisted_ids

    def test_is_blacklisted_id(self, safety_manager):
        assert safety_manager.is_blacklisted_id(0x100) is True
        assert safety_manager.is_blacklisted_id(0x999) is False

    def test_add_blacklist_id(self, safety_manager):
        safety_manager.add_blacklist_id(0x400, "Test reason")

        assert 0x400 in safety_manager._blacklisted_ids
        assert safety_manager._blacklist_reasons[0x400] == "Test reason"

    def test_add_invalid_can_id(self, safety_manager):
        with pytest.raises(ValueError):
            safety_manager.add_blacklist_id(0x20000000, "Invalid ID")

    def test_remove_blacklist_id(self, safety_manager):
        safety_manager.remove_blacklist_id(0x100)

        assert 0x100 not in safety_manager._blacklisted_ids

    def test_get_blacklist(self, safety_manager):
        blacklist = safety_manager.get_blacklist()

        assert isinstance(blacklist, dict)
        assert 0x100 in blacklist
        assert blacklist[0x100] == "Default critical system ID"

    def test_check_rate_limit(self, safety_manager):
        # Should allow first 10 calls
        for i in range(10):
            assert safety_manager.check_rate_limit("test_key", max_per_second=10) is True

        # 11th call should be blocked
        assert safety_manager.check_rate_limit("test_key", max_per_second=10) is False

    def test_rate_limit_sliding_window(self, safety_manager):
        # Fill rate limit
        for i in range(10):
            assert safety_manager.check_rate_limit("test_key", max_per_second=10) is True

        # Should be blocked
        assert safety_manager.check_rate_limit("test_key", max_per_second=10) is False

        # Wait for window to slide
        time.sleep(1.1)

        # Should allow again
        assert safety_manager.check_rate_limit("test_key", max_per_second=10) is True

    def test_get_rate_limit_status(self, safety_manager):
        # Make some calls
        for i in range(5):
            safety_manager.check_rate_limit("test_key")

        status = safety_manager.get_rate_limit_status("test_key")

        assert "current_count" in status
        assert "current_rate" in status
        assert status["key"] == "test_key"

    def test_reset_rate_limit(self, safety_manager):
        # Fill rate limit
        for i in range(10):
            safety_manager.check_rate_limit("test_key", max_per_second=10)

        # Reset
        safety_manager.reset_rate_limit("test_key")

        # Should allow again immediately
        assert safety_manager.check_rate_limit("test_key", max_per_second=10) is True

    @patch('rich.prompt.Confirm.ask', return_value=True)
    def test_require_confirmation_accepted(self, mock_confirm, safety_manager):
        result = safety_manager.require_confirmation("Test action")

        assert result is True
        mock_confirm.assert_called_once()

    @patch('rich.prompt.Confirm.ask', return_value=False)
    def test_require_confirmation_declined(self, mock_confirm, safety_manager):
        result = safety_manager.require_confirmation("Test action")

        assert result is False

    def test_require_confirmation_auto_confirm(self, safety_manager):
        result = safety_manager.require_confirmation(
            "Test action",
            auto_confirm=True
        )

        assert result is True

    def test_require_confirmation_emergency_stop(self, safety_manager):
        safety_manager._emergency_stop.set()

        result = safety_manager.require_confirmation("Test action")

        assert result is False

    def test_emergency_stop_flag(self, safety_manager):
        assert safety_manager.is_emergency_stop_active() is False

        safety_manager._emergency_stop.set()

        assert safety_manager.is_emergency_stop_active() is True

    def test_clear_emergency_stop(self, safety_manager):
        safety_manager._emergency_stop.set()
        safety_manager.clear_emergency_stop()

        assert safety_manager.is_emergency_stop_active() is False

    def test_record_violation(self, safety_manager):
        violation = SafetyViolation(
            timestamp=datetime.now(),
            violation_type="test",
            details="Test",
            severity="low",
            action_taken="logged"
        )

        safety_manager._record_violation(violation)

        assert len(safety_manager._violations) == 1

    def test_get_violations(self, safety_manager):
        # Add test violations
        for i in range(3):
            violation = SafetyViolation(
                timestamp=datetime.now(),
                violation_type="test",
                details=f"Test {i}",
                severity="low" if i % 2 == 0 else "high",
                action_taken="logged"
            )
            safety_manager._record_violation(violation)

        # Get all violations
        all_violations = safety_manager.get_violations()
        assert len(all_violations) == 3

        # Filter by severity
        high_violations = safety_manager.get_violations(severity="high")
        assert len(high_violations) == 1

    def test_get_violation_summary(self, safety_manager):
        # Add violations
        for i in range(3):
            violation = SafetyViolation(
                timestamp=datetime.now(),
                violation_type="blacklist" if i == 0 else "rate_limit",
                details=f"Test {i}",
                severity="medium",
                action_taken="blocked"
            )
            safety_manager._record_violation(violation)

        summary = safety_manager.get_violation_summary()

        assert summary["total_violations"] == 3
        assert "blacklist" in summary["by_type"]
        assert "rate_limit" in summary["by_type"]

    def test_clear_violations(self, safety_manager):
        violation = SafetyViolation(
            timestamp=datetime.now(),
            violation_type="test",
            details="Test",
            severity="low",
            action_taken="logged"
        )
        safety_manager._record_violation(violation)

        safety_manager.clear_violations()

        assert len(safety_manager._violations) == 0

    def test_export_violations(self, safety_manager, tmp_path):
        violation = SafetyViolation(
            timestamp=datetime.now(),
            violation_type="test",
            details="Test",
            severity="low",
            action_taken="logged"
        )
        safety_manager._record_violation(violation)

        output_file = tmp_path / "violations.json"
        safety_manager.export_violations(output_file)

        assert output_file.exists()

        import json
        with open(output_file) as f:
            data = json.load(f)

        assert len(data) == 1
        assert data[0]["violation_type"] == "test"


class TestRateLimiter:
    def test_basic_rate_limiting(self):
        limiter = RateLimiter(max_per_second=2)

        # Should allow 2 calls
        assert limiter.allow("test") is True
        assert limiter.allow("test") is True

        # Third call should be blocked
        assert limiter.allow("test") is False

    def test_different_keys(self):
        limiter = RateLimiter(max_per_second=1)

        # Different keys should have separate limits
        assert limiter.allow("key1") is True
        assert limiter.allow("key2") is True

        # But same key should be blocked
        assert limiter.allow("key1") is False

    def test_reset(self):
        limiter = RateLimiter(max_per_second=1)

        # Fill limit
        assert limiter.allow("test") is True
        assert limiter.allow("test") is False

        # Reset and try again
        limiter.reset("test")
        assert limiter.allow("test") is True

    def test_get_remaining(self):
        limiter = RateLimiter(max_per_second=3)

        assert limiter.get_remaining("test") == 3

        limiter.allow("test")
        assert limiter.get_remaining("test") == 2


class TestBlacklistManager:
    def test_default_blacklist(self):
        manager = BlacklistManager(load_defaults=True)

        # Should have default entries
        assert len(manager.get_all()) > 0
        assert manager.is_blacklisted(0x050)  # Airbag sensor

    def test_add_remove(self):
        manager = BlacklistManager(load_defaults=False)

        manager.add(0x123, "Test reason")
        assert manager.is_blacklisted(0x123)

        entry = manager.get(0x123)
        assert entry is not None
        assert entry.reason == "Test reason"

        assert manager.remove(0x123) is True
        assert not manager.is_blacklisted(0x123)

    def test_invalid_can_id(self):
        manager = BlacklistManager(load_defaults=False)

        with pytest.raises(ValueError):
            manager.add(0x20000000, "Invalid")

    def test_save_load(self, tmp_path):
        manager = BlacklistManager(load_defaults=False)
        manager.add(0x123, "Test entry")

        file_path = tmp_path / "blacklist.json"
        manager.save(file_path)

        new_manager = BlacklistManager(load_defaults=False)
        new_manager.load(file_path)

        assert new_manager.is_blacklisted(0x123)
        entry = new_manager.get(0x123)
        assert entry.reason == "Test entry"


class TestDecorators:
    def test_require_confirmation_decorator(self, safety_manager):
        class TestClass:
            def __init__(self):
                self.safety_manager = safety_manager
                self.called = False

            @require_confirmation("Test operation", risk_level="low")
            def test_method(self):
                self.called = True

        obj = TestClass()

        with patch('rich.prompt.Confirm.ask', return_value=True):
            obj.test_method()

        assert obj.called is True

    def test_require_confirmation_decorator_declined(self, safety_manager):
        class TestClass:
            def __init__(self):
                self.safety_manager = safety_manager

            @require_confirmation("Test operation")
            def test_method(self):
                return "executed"

        obj = TestClass()

        with patch('rich.prompt.Confirm.ask', return_value=False):
            with pytest.raises(PermissionError):
                obj.test_method()

    def test_rate_limit_decorator(self, safety_manager):
        class TestClass:
            def __init__(self):
                self.safety_manager = safety_manager
                self.count = 0

            @rate_limit(max_per_second=2)
            def test_method(self):
                self.count += 1

        obj = TestClass()

        # Should allow 2 calls
        obj.test_method()
        obj.test_method()
        assert obj.count == 2

        # Third call should raise
        with pytest.raises(RuntimeError):
            obj.test_method()

    def test_blacklist_check_decorator(self, safety_manager):
        class TestClass:
            def __init__(self):
                self.safety_manager = safety_manager

            @blacklist_check(param_name="can_id")
            def send_message(self, can_id, data):
                return f"Sent to {hex(can_id)}"

        obj = TestClass()

        # Should allow non-blacklisted ID
        result = obj.send_message(0x999, b"\x01\x02")
        assert "0x999" in result

        # Should block blacklisted ID
        with pytest.raises(PermissionError):
            obj.send_message(0x100, b"\x01\x02")

    def test_safe_can_operation_decorator(self, safety_manager):
        class TestClass:
            def __init__(self):
                self.safety_manager = safety_manager

            @safe_can_operation(risk_level="low")
            def send_message(self, arb_id, data):
                return f"Sent to {hex(arb_id)}"

        obj = TestClass()

        with patch('rich.prompt.Confirm.ask', return_value=True):
            # Should work for non-blacklisted ID
            result = obj.send_message(0x999, b"\x01\x02")
            assert "0x999" in result

            # Should block blacklisted ID even with confirmation
            with pytest.raises(PermissionError):
                obj.send_message(0x100, b"\x01\x02")