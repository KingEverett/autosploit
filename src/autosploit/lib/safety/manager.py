import time
import signal
import threading
import sys
from typing import Optional, Dict, List, Set, Any
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import deque, defaultdict

from rich.console import Console
from rich.prompt import Confirm
from rich.panel import Panel

from autosploit.core.config import SafetyConfig
from autosploit.core.logger import get_logger


@dataclass
class SafetyViolation:
    timestamp: datetime
    violation_type: str
    details: str
    severity: str
    action_taken: str
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "violation_type": self.violation_type,
            "details": self.details,
            "severity": self.severity,
            "action_taken": self.action_taken,
            "context": self.context,
        }


@dataclass
class BusHealthMetrics:
    error_frame_count: int = 0
    bus_off_count: int = 0
    last_message_time: Optional[datetime] = None
    message_rate: float = 0.0
    unique_ids_seen: Set[int] = field(default_factory=set)

    def reset(self) -> None:
        self.error_frame_count = 0
        self.bus_off_count = 0
        self.last_message_time = None
        self.message_rate = 0.0
        self.unique_ids_seen.clear()


class SafetyManager:
    """Manages safety mechanisms for automotive testing."""

    def __init__(self, config: SafetyConfig):
        self.config = config
        self.logger = get_logger(__name__)
        self.console = Console()

        # Violation tracking
        self._violations: List[SafetyViolation] = []
        self._violation_lock = threading.Lock()

        # Emergency stop state
        self._emergency_stop = threading.Event()
        self._emergency_stop_registered = False

        # Bus health monitoring
        self._bus_metrics = BusHealthMetrics()
        self._monitoring_active = False
        self._monitor_thread: Optional[threading.Thread] = None

        # Rate limiting state
        self._rate_limit_state: Dict[str, deque] = defaultdict(lambda: deque())
        self._rate_limit_lock = threading.Lock()

        # Blacklist management
        self._blacklisted_ids: Set[int] = set(config.dangerous_ids)
        self._blacklist_reasons: Dict[int, str] = {}

        for can_id in config.dangerous_ids:
            self._blacklist_reasons[can_id] = "Default critical system ID"

        self.logger.info(
            "Safety manager initialized",
            blacklist_count=len(self._blacklisted_ids),
            rate_limit=config.max_messages_per_second,
            monitoring_enabled=config.enable_bus_monitoring,
        )

    def require_confirmation(
        self,
        action: str,
        details: Optional[str] = None,
        risk_level: str = "medium",
        auto_confirm: bool = False
    ) -> bool:
        if self._emergency_stop.is_set():
            self.logger.warning("Operation blocked: Emergency stop active")
            return False

        if not self.config.require_confirmation:
            self.logger.debug("Confirmation bypassed (disabled in config)", action=action)
            return True

        if auto_confirm:
            self.logger.debug("Confirmation bypassed (auto_confirm=True)", action=action)
            return True

        risk_colors = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "bold red",
        }
        color = risk_colors.get(risk_level, "yellow")

        panel_content = f"[{color}]WARNING: SAFETY CONFIRMATION REQUIRED[/{color}]\n\n"
        panel_content += f"Action: {action}\n"
        panel_content += f"Risk Level: [{color}]{risk_level.upper()}[/{color}]\n"

        if details:
            panel_content += f"\nDetails:\n{details}\n"

        panel = Panel(panel_content, title="[bold]Safety Check[/bold]", border_style=color)
        self.console.print(panel)

        confirmed = Confirm.ask(f"[{color}]Do you want to proceed?[/{color}]", default=False)

        violation = SafetyViolation(
            timestamp=datetime.now(),
            violation_type="confirmation_required",
            details=action,
            severity=risk_level,
            action_taken="allowed" if confirmed else "blocked",
            context={"details": details} if details else {}
        )
        self._record_violation(violation)

        if confirmed:
            self.logger.info("User confirmed dangerous operation", action=action, risk_level=risk_level)
        else:
            self.logger.warning("User declined dangerous operation", action=action, risk_level=risk_level)

        return confirmed

    def is_blacklisted_id(self, arb_id: int) -> bool:
        is_blocked = arb_id in self._blacklisted_ids

        if is_blocked:
            reason = self._blacklist_reasons.get(arb_id, "Unknown reason")
            self.logger.warning("Blocked access to blacklisted CAN ID", can_id=hex(arb_id), reason=reason)

            violation = SafetyViolation(
                timestamp=datetime.now(),
                violation_type="blacklist_violation",
                details=f"Attempted access to blacklisted CAN ID {hex(arb_id)}",
                severity="high",
                action_taken="blocked",
                context={"can_id": arb_id, "reason": reason}
            )
            self._record_violation(violation)

        return is_blocked

    def add_blacklist_id(self, arb_id: int, reason: str = "User-added") -> None:
        if not (0x000 <= arb_id <= 0x7FF or 0x00000000 <= arb_id <= 0x1FFFFFFF):
            raise ValueError(
                f"Invalid CAN ID {hex(arb_id)}. "
                f"Must be standard (0x000-0x7FF) or extended (0x00000000-0x1FFFFFFF)"
            )

        self._blacklisted_ids.add(arb_id)
        self._blacklist_reasons[arb_id] = reason
        self.logger.info("Added CAN ID to blacklist", can_id=hex(arb_id), reason=reason)

    def remove_blacklist_id(self, arb_id: int) -> None:
        if arb_id in self._blacklisted_ids:
            self._blacklisted_ids.remove(arb_id)
            reason = self._blacklist_reasons.pop(arb_id, None)
            self.logger.warning("Removed CAN ID from blacklist", can_id=hex(arb_id), previous_reason=reason)
        else:
            self.logger.debug("CAN ID not in blacklist", can_id=hex(arb_id))

    def get_blacklist(self) -> Dict[int, str]:
        return dict(self._blacklist_reasons)

    def check_rate_limit(
        self,
        key: str,
        max_per_second: Optional[int] = None,
        window_seconds: float = 1.0
    ) -> bool:
        if max_per_second is None:
            max_per_second = self.config.max_messages_per_second

        current_time = time.perf_counter()

        with self._rate_limit_lock:
            call_times = self._rate_limit_state[key]

            # Remove calls outside the time window
            cutoff_time = current_time - window_seconds
            while call_times and call_times[0] < cutoff_time:
                call_times.popleft()

            if len(call_times) >= max_per_second:
                violation = SafetyViolation(
                    timestamp=datetime.now(),
                    violation_type="rate_limit_exceeded",
                    details=f"Rate limit exceeded for key '{key}'",
                    severity="medium",
                    action_taken="blocked",
                    context={
                        "key": key,
                        "limit": max_per_second,
                        "window": window_seconds,
                        "current_rate": len(call_times) / window_seconds,
                    }
                )
                self._record_violation(violation)

                self.logger.warning(
                    "Rate limit exceeded",
                    key=key,
                    limit=max_per_second,
                    current_count=len(call_times),
                )

                return False

            call_times.append(current_time)
            return True

    def get_rate_limit_status(self, key: str) -> Dict[str, Any]:
        with self._rate_limit_lock:
            call_times = self._rate_limit_state.get(key, deque())

            if not call_times:
                return {
                    "key": key,
                    "current_count": 0,
                    "current_rate": 0.0,
                    "limit": self.config.max_messages_per_second,
                    "percent_used": 0.0,
                }

            window = 1.0
            cutoff_time = time.perf_counter() - window
            recent_calls = [t for t in call_times if t >= cutoff_time]

            current_rate = len(recent_calls) / window
            percent_used = (current_rate / self.config.max_messages_per_second) * 100

            return {
                "key": key,
                "current_count": len(recent_calls),
                "current_rate": current_rate,
                "limit": self.config.max_messages_per_second,
                "percent_used": percent_used,
            }

    def reset_rate_limit(self, key: Optional[str] = None) -> None:
        with self._rate_limit_lock:
            if key is None:
                self._rate_limit_state.clear()
                self.logger.info("Reset all rate limit counters")
            elif key in self._rate_limit_state:
                self._rate_limit_state[key].clear()
                self.logger.info("Reset rate limit counter", key=key)

    def start_bus_monitoring(self, interface) -> None:
        if not self.config.enable_bus_monitoring:
            self.logger.debug("Bus monitoring disabled in config")
            return

        if self._monitoring_active:
            self.logger.warning("Bus monitoring already active")
            return

        self._monitoring_active = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_bus_health,
            args=(interface,),
            daemon=True,
            name="BusHealthMonitor"
        )
        self._monitor_thread.start()
        self.logger.info("Started bus health monitoring")

    def stop_bus_monitoring(self) -> None:
        if not self._monitoring_active:
            return

        self._monitoring_active = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5.0)

        self.logger.info("Stopped bus health monitoring")

    def _monitor_bus_health(self, interface) -> None:
        self.logger.debug("Bus health monitor thread started")

        message_count = 0
        start_time = time.perf_counter()

        while self._monitoring_active and not self._emergency_stop.is_set():
            try:
                time.sleep(self.config.monitor_interval_seconds)

                elapsed = time.perf_counter() - start_time
                if elapsed > 0:
                    self._bus_metrics.message_rate = message_count / elapsed

                if self._bus_metrics.error_frame_count > self.config.error_threshold:
                    self.logger.error(
                        "High error frame count detected",
                        count=self._bus_metrics.error_frame_count,
                        threshold=self.config.error_threshold,
                    )

                    violation = SafetyViolation(
                        timestamp=datetime.now(),
                        violation_type="bus_health_error",
                        details="Excessive error frames detected on bus",
                        severity="high",
                        action_taken="logged",
                        context={"error_count": self._bus_metrics.error_frame_count}
                    )
                    self._record_violation(violation)

                if elapsed > 60:
                    message_count = 0
                    start_time = time.perf_counter()
                    self._bus_metrics.reset()

            except Exception as e:
                self.logger.exception("Error in bus health monitor", error=str(e))

        self.logger.debug("Bus health monitor thread stopped")

    def report_bus_message(self, arb_id: int, is_error_frame: bool = False) -> None:
        self._bus_metrics.last_message_time = datetime.now()
        self._bus_metrics.unique_ids_seen.add(arb_id)

        if is_error_frame:
            self._bus_metrics.error_frame_count += 1

            if self._bus_metrics.error_frame_count % 10 == 0:
                self.logger.warning("Error frame count increasing", count=self._bus_metrics.error_frame_count)

    def get_bus_health(self) -> Dict[str, Any]:
        return {
            "error_frames": self._bus_metrics.error_frame_count,
            "bus_off_count": self._bus_metrics.bus_off_count,
            "message_rate": self._bus_metrics.message_rate,
            "unique_ids": len(self._bus_metrics.unique_ids_seen),
            "last_message": self._bus_metrics.last_message_time.isoformat()
                if self._bus_metrics.last_message_time else None,
            "monitoring_active": self._monitoring_active,
        }

    def register_emergency_handler(self) -> None:
        if self._emergency_stop_registered:
            self.logger.warning("Emergency handler already registered")
            return

        def emergency_handler(signum, frame):
            if not self._emergency_stop.is_set():
                self.console.print("\n[bold red]WARNING: EMERGENCY STOP REQUESTED[/bold red]")
                self.console.print("[yellow]Press Ctrl+C again to confirm immediate stop[/yellow]")
                self.console.print("[green]Waiting... (operations will complete gracefully)[/green]")

                self._emergency_stop.set()
                self.logger.critical("Emergency stop requested by user")

                violation = SafetyViolation(
                    timestamp=datetime.now(),
                    violation_type="emergency_stop",
                    details="User requested emergency stop (Ctrl+C)",
                    severity="critical",
                    action_taken="stopping",
                    context={}
                )
                self._record_violation(violation)
            else:
                self.console.print("\n[bold red]EMERGENCY STOP CONFIRMED - FORCE QUITTING[/bold red]")
                self.logger.critical("Emergency stop confirmed - forcing exit")

                self._emergency_cleanup()
                sys.exit(130)

        signal.signal(signal.SIGINT, emergency_handler)
        self._emergency_stop_registered = True
        self.logger.info("Emergency stop handler registered (Ctrl+C)")

    def _emergency_cleanup(self) -> None:
        try:
            if self._monitoring_active:
                self.stop_bus_monitoring()

            self.logger.critical("Emergency cleanup complete", total_violations=len(self._violations))
        except Exception as e:
            self.logger.exception("Error during emergency cleanup", error=str(e))

    def is_emergency_stop_active(self) -> bool:
        return self._emergency_stop.is_set()

    def clear_emergency_stop(self) -> None:
        self._emergency_stop.clear()
        self.logger.warning("Emergency stop flag cleared")

    def _record_violation(self, violation: SafetyViolation) -> None:
        with self._violation_lock:
            self._violations.append(violation)

        self.logger.warning("Safety violation recorded", **violation.to_dict())

    def get_violations(
        self,
        violation_type: Optional[str] = None,
        severity: Optional[str] = None,
        since: Optional[datetime] = None
    ) -> List[SafetyViolation]:
        with self._violation_lock:
            violations = list(self._violations)

        if violation_type:
            violations = [v for v in violations if v.violation_type == violation_type]

        if severity:
            violations = [v for v in violations if v.severity == severity]

        if since:
            violations = [v for v in violations if v.timestamp >= since]

        return violations

    def get_violation_summary(self) -> Dict[str, Any]:
        with self._violation_lock:
            violations = list(self._violations)

        type_counts = defaultdict(int)
        for v in violations:
            type_counts[v.violation_type] += 1

        severity_counts = defaultdict(int)
        for v in violations:
            severity_counts[v.severity] += 1

        one_hour_ago = datetime.now() - timedelta(hours=1)
        recent = [v for v in violations if v.timestamp >= one_hour_ago]

        return {
            "total_violations": len(violations),
            "by_type": dict(type_counts),
            "by_severity": dict(severity_counts),
            "recent_violations": len(recent),
            "last_violation": violations[-1].to_dict() if violations else None,
        }

    def clear_violations(self) -> None:
        with self._violation_lock:
            count = len(self._violations)
            self._violations.clear()

        self.logger.info("Cleared safety violations", count=count)

    def export_violations(self, path: Path) -> None:
        import json

        with self._violation_lock:
            violations_dict = [v.to_dict() for v in self._violations]

        with open(path, "w") as f:
            json.dump(violations_dict, f, indent=2)

        self.logger.info("Exported violations", path=str(path), count=len(violations_dict))