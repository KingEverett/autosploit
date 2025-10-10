import sys
import logging
import logging.config
import logging.handlers
import os
from pathlib import Path
from typing import Optional, Any
from datetime import datetime

import structlog
from structlog.typing import EventDict, WrappedLogger
from structlog.stdlib import BoundLogger
from rich.console import Console
from rich.logging import RichHandler

from autosploit.core.config import LoggingConfig


def add_app_context(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Add application context to log entries."""
    event_dict["app"] = "autosploit"
    event_dict["pid"] = os.getpid()
    return event_dict


def add_module_info(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Add module and function name to log entries."""
    import inspect

    frame = inspect.currentframe()
    if frame:
        # Walk back through frames to find non-structlog code
        for _ in range(10):  # Max 10 frames
            frame = frame.f_back
            if not frame:
                break

            module = inspect.getmodule(frame)
            if module and 'structlog' not in module.__name__:
                event_dict["module"] = module.__name__
                event_dict["func"] = frame.f_code.co_name
                event_dict["line"] = frame.f_lineno
                break

    return event_dict


def censor_sensitive_data(
    logger: WrappedLogger, method_name: str, event_dict: EventDict
) -> EventDict:
    """Censor sensitive information in log entries."""
    sensitive_keys = {
        "password", "passwd", "pwd",
        "token", "api_key", "secret",
        "auth", "authorization",
    }

    def censor_dict(d: dict) -> dict:
        """Recursively censor dictionary values."""
        result = {}
        for key, value in d.items():
            if isinstance(key, str) and any(s in key.lower() for s in sensitive_keys):
                result[key] = "****REDACTED****"
            elif isinstance(value, dict):
                result[key] = censor_dict(value)
            else:
                result[key] = value
        return result

    return censor_dict(event_dict)


def configure_structlog(
    config: LoggingConfig,
    console_output: bool = True,
    file_output: bool = True
) -> None:
    """Configure structlog with processors and outputs."""
    is_tty = sys.stderr.isatty()

    shared_processors = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.CallsiteParameterAdder(
            [
                structlog.processors.CallsiteParameter.MODULE,
                structlog.processors.CallsiteParameter.FUNC_NAME,
                structlog.processors.CallsiteParameter.LINENO,
            ]
        ),
        add_app_context,
        censor_sensitive_data,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.ExceptionRenderer(),
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ]

    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "plain": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processors": [
                    structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    structlog.processors.JSONRenderer(),
                ],
                "foreign_pre_chain": shared_processors,
            },
            "colored": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processors": [
                    structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    structlog.dev.ConsoleRenderer(colors=True),
                ],
                "foreign_pre_chain": shared_processors,
            },
        },
        "handlers": {},
        "loggers": {
            "": {
                "handlers": [],
                "level": config.level,
                "propagate": True,
            }
        }
    }

    # Add console handler if enabled
    if console_output and config.console_output:
        if is_tty:
            logging_config["handlers"]["console"] = {
                "level": config.level,
                "class": "rich.logging.RichHandler",
                "formatter": "colored",
            }
        else:
            logging_config["handlers"]["console"] = {
                "level": config.level,
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr",
                "formatter": "plain",
            }
        logging_config["loggers"][""]["handlers"].append("console")

    # Add file handler if enabled
    if file_output and config.file_path:
        log_path = Path(config.file_path).expanduser().resolve()
        log_path.parent.mkdir(parents=True, exist_ok=True)

        logging_config["handlers"]["file"] = {
            "level": "DEBUG",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": str(log_path),
            "maxBytes": config.max_bytes,
            "backupCount": config.backup_count,
            "formatter": "plain",
        }
        logging_config["loggers"][""]["handlers"].append("file")

    logging.config.dictConfig(logging_config)

    structlog.configure(
        processors=shared_processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


class Logger:
    """Structured logger wrapper with context management."""

    def __init__(self, name: Optional[str] = None):
        if name is None:
            import inspect
            frame = inspect.currentframe()
            if frame and frame.f_back:
                name = frame.f_back.f_globals.get("__name__", "autosploit")

        self._logger: BoundLogger = structlog.get_logger(name)
        self._context: dict = {}

    def bind(self, **kwargs: Any) -> "Logger":
        """Create new logger with additional context."""
        new_logger = Logger.__new__(Logger)
        new_logger._logger = self._logger.bind(**kwargs)
        new_logger._context = {**self._context, **kwargs}
        return new_logger

    def unbind(self, *keys: str) -> "Logger":
        """Create new logger with context removed."""
        new_context = {k: v for k, v in self._context.items() if k not in keys}
        new_logger = Logger.__new__(Logger)
        new_logger._logger = self._logger.bind(**new_context)
        new_logger._context = new_context
        return new_logger

    def debug(self, msg: str, **kwargs: Any) -> None:
        self._logger.debug(msg, **kwargs)

    def info(self, msg: str, **kwargs: Any) -> None:
        self._logger.info(msg, **kwargs)

    def warning(self, msg: str, **kwargs: Any) -> None:
        self._logger.warning(msg, **kwargs)

    def error(self, msg: str, **kwargs: Any) -> None:
        self._logger.error(msg, **kwargs)

    def critical(self, msg: str, **kwargs: Any) -> None:
        self._logger.critical(msg, **kwargs)

    def exception(self, msg: str, **kwargs: Any) -> None:
        self._logger.exception(msg, **kwargs)


def log_execution(
    level: str = "info",
    include_args: bool = False,
    include_result: bool = False
):
    """Decorator to log function execution."""
    def decorator(func):
        import functools

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            logger = Logger(func.__module__)

            log_data = {
                "function": func.__name__,
                "module": func.__module__,
            }

            if include_args:
                log_data["args"] = args
                log_data["kwargs"] = kwargs

            getattr(logger, level)(f"Entering {func.__name__}", **log_data)

            try:
                result = func(*args, **kwargs)

                exit_data = {"function": func.__name__}
                if include_result:
                    exit_data["result"] = result

                getattr(logger, level)(f"Exiting {func.__name__}", **exit_data)

                return result

            except Exception as e:
                logger.exception(
                    f"Exception in {func.__name__}",
                    function=func.__name__,
                    exception_type=type(e).__name__,
                )
                raise

        return wrapper
    return decorator


def log_performance(threshold_ms: float = 100):
    """Decorator to log slow function executions."""
    def decorator(func):
        import functools
        import time

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            logger = Logger(func.__module__)

            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                elapsed = (time.perf_counter() - start) * 1000

                if elapsed > threshold_ms:
                    logger.warning(
                        f"Slow execution: {func.__name__}",
                        function=func.__name__,
                        elapsed_ms=round(elapsed, 2),
                        threshold_ms=threshold_ms,
                    )
                else:
                    logger.debug(
                        f"Function executed: {func.__name__}",
                        function=func.__name__,
                        elapsed_ms=round(elapsed, 2),
                    )

        return wrapper
    return decorator


class SessionLogger:
    """Logger for CAN session with dedicated log file."""

    def __init__(
        self,
        session_id: str,
        interface: Optional[str] = None,
        workspace_path: Optional[Path] = None
    ):
        self.session_id = session_id
        self.interface = interface
        self.start_time = datetime.now()

        if workspace_path is None:
            workspace_path = Path.home() / ".autosploit" / "workspace"

        self.log_dir = workspace_path / "sessions" / session_id
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.log_file = self.log_dir / f"session_{session_id}.log"
        self.can_log_file = self.log_dir / f"can_traffic_{session_id}.log"

        self.logger = Logger("session").bind(
            session_id=session_id,
            interface=interface,
        )

        self._write_metadata()

    def _write_metadata(self) -> None:
        """Write session metadata to file."""
        metadata = {
            "session_id": self.session_id,
            "interface": self.interface,
            "start_time": self.start_time.isoformat(),
            "log_file": str(self.log_file),
            "can_log_file": str(self.can_log_file),
        }

        metadata_file = self.log_dir / "metadata.json"
        import json
        with open(metadata_file, "w") as f:
            json.dump(metadata, f, indent=2)

    def log_command(self, command: str, **context: Any) -> None:
        self.logger.info(
            "Command executed",
            command=command,
            timestamp=datetime.now().isoformat(),
            **context
        )

    def log_module_execution(
        self,
        module_name: str,
        options: dict,
        result: Any = None,
        error: Optional[str] = None
    ) -> None:
        log_data = {
            "module": module_name,
            "options": options,
            "timestamp": datetime.now().isoformat(),
        }

        if result is not None:
            log_data["result"] = result

        if error:
            log_data["error"] = error
            self.logger.error("Module execution failed", **log_data)
        else:
            self.logger.info("Module executed successfully", **log_data)

    def log_can_message(
        self,
        can_id: int,
        data: bytes,
        is_extended: bool = False,
        is_tx: bool = False
    ) -> None:
        timestamp = datetime.now().isoformat()
        direction = "TX" if is_tx else "RX"
        id_str = f"{can_id:08X}" if is_extended else f"{can_id:03X}"
        data_hex = data.hex().upper()

        log_line = f"{timestamp} {direction} {id_str} {data_hex}\n"

        with open(self.can_log_file, "a") as f:
            f.write(log_line)

        self.logger.debug(
            "CAN message",
            direction=direction,
            can_id=id_str,
            data=data_hex,
            is_extended=is_extended,
        )

    def log_event(self, event_type: str, **context: Any) -> None:
        self.logger.info(
            f"Session event: {event_type}",
            event_type=event_type,
            timestamp=datetime.now().isoformat(),
            **context
        )

    def close(self) -> None:
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        self.logger.info(
            "Session closed",
            end_time=end_time.isoformat(),
            duration_seconds=duration,
        )

        metadata_file = self.log_dir / "metadata.json"
        import json
        with open(metadata_file, "r") as f:
            metadata = json.load(f)

        metadata["end_time"] = end_time.isoformat()
        metadata["duration_seconds"] = duration

        with open(metadata_file, "w") as f:
            json.dump(metadata, f, indent=2)


def setup_logging(config: LoggingConfig) -> None:
    """Initialize logging system with configuration."""
    configure_structlog(config)

    if config.file_path:
        log_path = Path(config.file_path).expanduser()
        log_path.parent.mkdir(parents=True, exist_ok=True)


def get_logger(name: Optional[str] = None) -> Logger:
    """Get logger instance."""
    return Logger(name)


def get_session_logger(
    session_id: str,
    interface: Optional[str] = None,
    workspace_path: Optional[Path] = None
) -> SessionLogger:
    """Create session logger."""
    return SessionLogger(session_id, interface, workspace_path)


def set_log_level(level: str) -> None:
    """Change global log level at runtime."""
    numeric_level = getattr(logging, level.upper())
    logging.getLogger().setLevel(numeric_level)

    logger = get_logger(__name__)
    logger.info(f"Log level changed to {level}")


def log_system_info() -> None:
    """Log system information at startup."""
    import platform
    import getpass

    logger = get_logger(__name__)
    logger.info(
        "System information",
        python_version=platform.python_version(),
        platform=platform.platform(),
        cwd=str(Path.cwd()),
        user=getpass.getuser(),
    )