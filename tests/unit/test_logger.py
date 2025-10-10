import pytest
import logging
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from freezegun import freeze_time

from autosploit.core.logger import (
    Logger,
    SessionLogger,
    configure_structlog,
    setup_logging,
    get_logger,
    log_execution,
    log_performance,
    add_app_context,
    censor_sensitive_data,
)
from autosploit.core.config import LoggingConfig


class TestLogger:
    """Test Logger class functionality."""

    def setup_method(self):
        """Set up basic logging for each test."""
        logging.basicConfig(level=logging.DEBUG, format='%(message)s')

    def test_logger_creation(self):
        logger = Logger("test_module")
        assert logger is not None

    def test_logger_auto_name(self):
        logger = Logger()
        assert logger is not None

    def test_logger_bind_context(self):
        logger = Logger("test")
        bound = logger.bind(session_id="123", user="admin")

        assert bound is not logger
        assert bound._context["session_id"] == "123"
        assert bound._context["user"] == "admin"

    def test_logger_unbind_context(self):
        logger = Logger("test").bind(a="1", b="2", c="3")
        unbound = logger.unbind("b")

        assert "a" in unbound._context
        assert "b" not in unbound._context
        assert "c" in unbound._context

    def test_logger_levels(self, caplog):
        logger = Logger("test")

        with caplog.at_level(logging.DEBUG):
            logger.debug("debug message")
            logger.info("info message")
            logger.warning("warning message")
            logger.error("error message")
            logger.critical("critical message")

        assert "debug message" in caplog.text
        assert "info message" in caplog.text
        assert "warning message" in caplog.text
        assert "error message" in caplog.text
        assert "critical message" in caplog.text

    def test_logger_with_context(self, caplog):
        logger = Logger("test")

        with caplog.at_level(logging.INFO):
            logger.info("event occurred", event_id=123, status="success")

        assert "event occurred" in caplog.text


class TestProcessors:
    """Test custom log processors."""

    def test_add_app_context(self):
        event_dict = {}
        result = add_app_context(None, None, event_dict)

        assert "app" in result
        assert result["app"] == "autosploit"
        assert "pid" in result
        assert isinstance(result["pid"], int)

    def test_censor_sensitive_data(self):
        event_dict = {
            "password": "secret123",
            "username": "admin",
            "api_key": "abc123",
            "normal_field": "visible",
        }

        result = censor_sensitive_data(None, None, event_dict)

        assert result["password"] == "****REDACTED****"
        assert result["api_key"] == "****REDACTED****"
        assert result["username"] == "admin"
        assert result["normal_field"] == "visible"

    def test_censor_nested_sensitive_data(self):
        event_dict = {
            "config": {
                "password": "secret",
                "host": "localhost",
            }
        }

        result = censor_sensitive_data(None, None, event_dict)

        assert result["config"]["password"] == "****REDACTED****"
        assert result["config"]["host"] == "localhost"


class TestDecorators:
    """Test logging decorators."""

    def test_log_execution_basic(self, caplog):
        @log_execution()
        def test_func():
            return "result"

        with caplog.at_level(logging.INFO):
            result = test_func()

        assert result == "result"
        assert "Entering test_func" in caplog.text
        assert "Exiting test_func" in caplog.text

    def test_log_execution_with_args(self, caplog):
        @log_execution(include_args=True)
        def test_func(a, b, c=3):
            return a + b + c

        with caplog.at_level(logging.INFO):
            result = test_func(1, 2, c=4)

        assert result == 7
        assert "Entering test_func" in caplog.text

    def test_log_execution_with_exception(self, caplog):
        @log_execution()
        def test_func():
            raise ValueError("test error")

        with caplog.at_level(logging.INFO):
            with pytest.raises(ValueError):
                test_func()

        assert "Exception in test_func" in caplog.text

    def test_log_performance_fast(self, caplog):
        @log_performance(threshold_ms=1000)
        def fast_func():
            return "done"

        with caplog.at_level(logging.DEBUG):
            result = fast_func()

        assert result == "done"

    def test_log_performance_slow(self, caplog):
        import time

        @log_performance(threshold_ms=10)
        def slow_func():
            time.sleep(0.02)  # 20ms
            return "done"

        with caplog.at_level(logging.WARNING):
            result = slow_func()

        assert result == "done"
        assert "Slow execution" in caplog.text


class TestSessionLogger:
    """Test SessionLogger functionality."""

    def test_session_logger_creation(self, tmp_path):
        session = SessionLogger(
            session_id="test123",
            interface="can0",
            workspace_path=tmp_path
        )

        assert session.session_id == "test123"
        assert session.interface == "can0"
        assert session.log_dir.exists()

        metadata_file = session.log_dir / "metadata.json"
        assert metadata_file.exists()

    def test_session_log_command(self, tmp_path, caplog):
        session = SessionLogger(
            session_id="test123",
            workspace_path=tmp_path
        )

        with caplog.at_level(logging.INFO):
            session.log_command("use scanner/can_discovery")

        assert "Command executed" in caplog.text
        assert "use scanner/can_discovery" in caplog.text

    def test_session_log_module_execution(self, tmp_path, caplog):
        session = SessionLogger(
            session_id="test123",
            workspace_path=tmp_path
        )

        options = {"interface": "can0", "timeout": 5}

        with caplog.at_level(logging.INFO):
            session.log_module_execution(
                "scanner/can_discovery",
                options=options,
                result={"found": 10}
            )

        assert "Module executed successfully" in caplog.text

    def test_session_log_can_message(self, tmp_path):
        session = SessionLogger(
            session_id="test123",
            workspace_path=tmp_path
        )

        session.log_can_message(
            can_id=0x123,
            data=b"\x01\x02\x03\x04",
            is_extended=False,
            is_tx=True
        )

        assert session.can_log_file.exists()

        content = session.can_log_file.read_text()
        assert "TX" in content
        assert "123" in content
        assert "01020304" in content

    @freeze_time("2025-01-15 10:30:00")
    def test_session_close(self, tmp_path):
        session = SessionLogger(
            session_id="test123",
            workspace_path=tmp_path
        )

        with freeze_time("2025-01-15 10:35:00"):
            session.close()

        metadata_file = session.log_dir / "metadata.json"
        import json
        with open(metadata_file) as f:
            metadata = json.load(f)

        assert "end_time" in metadata
        assert "duration_seconds" in metadata
        assert metadata["duration_seconds"] == 300  # 5 minutes


class TestConfiguration:
    """Test logging configuration."""

    def test_configure_structlog(self, tmp_path):
        config = LoggingConfig(
            level="DEBUG",
            file_path=str(tmp_path / "test.log"),
        )

        configure_structlog(config)

        logger = get_logger("test")
        logger.info("test message")

        log_file = Path(config.file_path)
        assert log_file.exists()

    def test_setup_logging(self, tmp_path):
        config = LoggingConfig(
            level="INFO",
            file_path=str(tmp_path / "app.log"),
            console_output=True,
        )

        setup_logging(config)

        logger = get_logger("test")
        logger.info("setup test")

        assert Path(config.file_path).exists()

    def test_log_level_filtering(self, tmp_path, caplog):
        config = LoggingConfig(level="WARNING")
        configure_structlog(config)

        logger = get_logger("test")

        with caplog.at_level(logging.WARNING):
            logger.debug("debug - should not appear")
            logger.info("info - should not appear")
            logger.warning("warning - should appear")
            logger.error("error - should appear")

        assert "debug" not in caplog.text
        assert "info" not in caplog.text
        assert "warning - should appear" in caplog.text
        assert "error - should appear" in caplog.text


class TestUtilityFunctions:
    """Test utility functions."""

    def test_get_logger(self):
        logger = get_logger("my_module")
        assert logger is not None
        assert isinstance(logger, Logger)

    def test_get_logger_with_auto_name(self):
        logger = get_logger()
        assert logger is not None

    def test_set_log_level(self, caplog):
        from autosploit.core.logger import set_log_level

        with caplog.at_level(logging.DEBUG):
            set_log_level("ERROR")

    def test_log_system_info(self, caplog):
        from autosploit.core.logger import log_system_info

        with caplog.at_level(logging.INFO):
            log_system_info()

        assert "System information" in caplog.text


class TestIntegration:
    """Test integration between logging and configuration."""

    def test_config_integration(self, tmp_path):
        from autosploit.core.config import ConfigManager

        config_manager = ConfigManager()
        config = config_manager.load_config()

        # Should work without errors
        setup_logging(config.logging)

        logger = get_logger("integration_test")
        logger.info("Integration test successful")

    def test_environment_variable_integration(self, tmp_path, monkeypatch):
        from autosploit.core.config import ConfigManager

        monkeypatch.setenv("AUTOSPLOIT_LOGGING__LEVEL", "DEBUG")

        config_manager = ConfigManager()
        config = config_manager.load_config()

        assert config.logging.level == "DEBUG"

        setup_logging(config.logging)
        logger = get_logger("env_test")
        logger.debug("Debug level from environment variable")


class TestErrorHandling:
    """Test error handling scenarios."""

    def test_logger_with_none_name(self):
        logger = Logger(None)
        assert logger is not None

    def test_session_logger_with_missing_workspace(self):
        # Should create workspace directory if it doesn't exist
        session = SessionLogger("test_session")
        assert session.log_dir.exists()

    def test_censor_with_non_dict_values(self):
        event_dict = {
            "password": "secret",
            "list_field": [1, 2, 3],
            "none_field": None,
            "number_field": 42,
        }

        result = censor_sensitive_data(None, None, event_dict)

        assert result["password"] == "****REDACTED****"
        assert result["list_field"] == [1, 2, 3]
        assert result["none_field"] is None
        assert result["number_field"] == 42


class TestConcurrency:
    """Test concurrent logging scenarios."""

    def test_multiple_session_loggers(self, tmp_path):
        session1 = SessionLogger("session1", workspace_path=tmp_path)
        session2 = SessionLogger("session2", workspace_path=tmp_path)

        session1.log_command("command1")
        session2.log_command("command2")

        # Both should have separate directories
        assert session1.log_dir != session2.log_dir
        assert session1.log_dir.exists()
        assert session2.log_dir.exists()

    def test_context_binding_isolation(self):
        base_logger = Logger("test")
        logger1 = base_logger.bind(session="1")
        logger2 = base_logger.bind(session="2")

        # Should be independent
        assert logger1._context["session"] == "1"
        assert logger2._context["session"] == "2"
        assert "session" not in base_logger._context