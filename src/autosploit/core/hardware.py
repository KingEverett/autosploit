from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
import time
import can
from can import Message, Bus

class HardwareInterface(ABC):
    #base class for hardware interfaces.
    @abstractmethod
    def connect(self) -> bool:
        pass

    @abstractmethod
    def disconnect(self):
        pass

    @abstractmethod
    def send(self, data: bytes, arbitration_id: int, is_extended: bool = False) -> bool:
        pass

    @abstractmethod
    def recv(self, timeout: float = 1.0) -> Optional[Message]:
        pass

    def _should_reconnect(self) -> bool:
        """Determine if we should attempt reconnection."""
        pass

    def _attempt_reconnect(self):
        """Attempt to reconnect to the hardware."""
        pass

    def get_health_status(self) -> Dict[str, Any]:
        """Get connection health status."""
        pass

    def reset_error_count(self):
        """Reset error counter."""
        pass

    def is_healthy(self, max_errors: int = 10,
                   max_idle_time: float = 60.0) -> bool:
        """Check if connection is healthy."""
        pass

    def flush(self):
        """Flush receive buffer."""
        pass

    def send_and_wait(self, data: bytes, arbitration_id: int,
                      response_id: Optional[int] = None,
                      timeout: float = 1.0,
                      is_extended: bool = False) -> Optional[Message]:
        """Send a message and wait for response."""
        pass

    def __enter__(self):
        """Context manager entry."""
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        pass


class CANInterface(HardwareInterface):
    """CAN bus hardware interface using python-can library."""

    SUPPORTED_INTERFACES = ['socketcan', 'pcan', 'vector', 'kvaser']

    def __init__(self, interface_type: str, channel: str,
                 bitrate: int = 500000, **kwargs):
        """Initialize CAN interface."""
        from autosploit.lib.utils.validators import validate_choice, validate_interface_name, validate_bitrate
        from autosploit.core.logger import get_logger

        # Validate inputs
        validate_choice(interface_type, self.SUPPORTED_INTERFACES, "interface_type").raise_if_invalid()
        validate_interface_name(channel, interface_type).raise_if_invalid()
        validate_bitrate(bitrate).raise_if_invalid()

        self.interface_type = interface_type
        self.channel = channel
        self.bitrate = bitrate
        self.kwargs = kwargs

        self.bus: Optional[Bus] = None
        self._connection_attempts = 0
        self._max_reconnect_attempts = 3
        self._last_error: Optional[str] = None

        # For health monitoring
        self._last_message_time = 0.0
        self._error_count = 0

        self.logger = get_logger(__name__)

    @property
    def interface_name(self) -> str:
        """Get human-readable interface name."""
        return f"{self.interface_type}:{self.channel}"

    @property
    def is_connected(self) -> bool:
        """Check if interface is connected."""
        return self.bus is not None

    def connect(self) -> bool:
        """Connect to the CAN interface."""
        from autosploit.lib.utils.formatters import print_info, print_success, print_error

        try:
            print_info(f"Connecting to {self.interface_name}...")
            self.logger.info("Connecting to CAN interface", interface=self.interface_name)

            # Create python-can Bus object
            self.bus = can.Bus(
                interface=self.interface_type,
                channel=self.channel,
                bitrate=self.bitrate,
                **self.kwargs
            )

            self._connection_attempts = 0
            self._last_error = None
            self._last_message_time = time.time()

            print_success(f"Connected to {self.interface_name} at {self.bitrate} bps")
            self.logger.info("CAN interface connected", interface=self.interface_name, bitrate=self.bitrate)
            return True

        except can.CanError as e:
            self._last_error = str(e)
            print_error(f"CAN Error: {e}")
            self.logger.error("CAN connection error", error=str(e), interface=self.interface_name)
            return False

        except OSError as e:
            self._last_error = str(e)

            # Provide helpful error messages
            if "No such device" in str(e):
                print_error(f"Interface {self.channel} not found")
                print_info(f"For virtual CAN, run: sudo modprobe vcan; "
                           f"sudo ip link add dev {self.channel} type vcan; "
                           f"sudo ip link set up {self.channel}")
            elif "Permission denied" in str(e):
                print_error(f"Permission denied. Try: sudo chmod 666 /dev/{self.channel}")
            else:
                print_error(f"OS Error: {e}")

            self.logger.error("OS error during connection", error=str(e), interface=self.interface_name)
            return False

        except Exception as e:
            self._last_error = str(e)
            print_error(f"Unexpected error: {e}")
            self.logger.exception("Unexpected connection error", interface=self.interface_name)
            return False

    def disconnect(self):
        """Disconnect from the CAN interface."""
        from autosploit.lib.utils.formatters import print_success, print_error

        if self.bus is not None:
            try:
                self.bus.shutdown()
                print_success(f"Disconnected from {self.interface_name}")
                self.logger.info("CAN interface disconnected", interface=self.interface_name)
            except Exception as e:
                print_error(f"Error during disconnect: {e}")
                self.logger.error("Error during disconnect", error=str(e), interface=self.interface_name)
            finally:
                self.bus = None
                self._last_message_time = 0.0

    def send(self, data: bytes, arbitration_id: int,
             is_extended: bool = False) -> bool:
        """Send data on the CAN bus."""
        from autosploit.lib.utils.validators import validate_can_data, validate_can_id
        from autosploit.lib.utils.formatters import print_error

        if not self.is_connected:
            raise ConnectionError("Not connected to hardware")

        # Validate using our validators
        validate_can_data(data).raise_if_invalid()
        validate_can_id(arbitration_id, extended=is_extended).raise_if_invalid()

        try:
            # Create CAN message
            message = Message(
                arbitration_id=arbitration_id,
                data=data,
                is_extended_id=is_extended
            )

            # Send on bus
            self.bus.send(message)
            self._last_message_time = time.time()

            return True

        except can.CanError as e:
            self._error_count += 1
            self._last_error = str(e)
            print_error(f"Send error: {e}")
            self.logger.error("CAN send error", error=str(e), arbitration_id=hex(arbitration_id))

            # Attempt auto-reconnect
            if self._should_reconnect():
                self._attempt_reconnect()

            return False

        except Exception as e:
            self._error_count += 1
            self._last_error = str(e)
            print_error(f"Unexpected send error: {e}")
            self.logger.exception("Unexpected send error", arbitration_id=hex(arbitration_id))
            return False

    def recv(self, timeout: float = 1.0) -> Optional[Message]:
        """Receive a message from the CAN bus."""
        if not self.is_connected:
            return None

        try:
            # Receive with timeout
            message = self.bus.recv(timeout=timeout)

            if message:
                self._last_message_time = time.time()
                self._error_count = 0  # Reset error count on successful recv

            return message

        except can.CanError as e:
            self._error_count += 1
            self._last_error = str(e)
            from autosploit.lib.utils.formatters import print_error
            print_error(f"Receive error: {e}")
            self.logger.error("CAN receive error", error=str(e))

            # Attempt auto-reconnect
            if self._should_reconnect():
                self._attempt_reconnect()

            return None

        except Exception as e:
            from autosploit.lib.utils.formatters import print_error
            print_error(f"Unexpected receive error: {e}")
            self.logger.exception("Unexpected receive error")
            return None

    def _should_reconnect(self) -> bool:
        """Determine if we should attempt reconnection."""
        if self._connection_attempts >= self._max_reconnect_attempts:
            return False
        if self._error_count < 3:
            return False
        return True

    def _attempt_reconnect(self):
        """Attempt to reconnect to the hardware."""
        from autosploit.lib.utils.formatters import print_warning, print_info, print_success, print_error

        self._connection_attempts += 1
        print_warning(f"Reconnection attempt {self._connection_attempts}/{self._max_reconnect_attempts}")
        self.logger.info("Attempting reconnection", attempt=self._connection_attempts, max_attempts=self._max_reconnect_attempts)

        self.disconnect()

        delay = 2 ** (self._connection_attempts - 1)
        print_info(f"Waiting {delay} seconds...")
        time.sleep(delay)

        if self.connect():
            print_success("Reconnection successful!")
            self._error_count = 0
        else:
            print_error("Reconnection failed")
            self.logger.error("Reconnection failed", attempt=self._connection_attempts)

    def get_health_status(self) -> Dict[str, Any]:
        """Get connection health status."""
        return {
            'connected': self.is_connected,
            'interface': self.interface_name,
            'bitrate': self.bitrate,
            'error_count': self._error_count,
            'last_error': self._last_error,
            'time_since_last_message': time.time() - self._last_message_time
                                        if self._last_message_time > 0 else -1,
            'reconnect_attempts': self._connection_attempts,
        }

    def reset_error_count(self):
        """Reset error counter."""
        self._error_count = 0
        self._connection_attempts = 0

    def is_healthy(self, max_errors: int = 10, max_idle_time: float = 60.0) -> bool:
        """Check if connection is healthy."""
        if not self.is_connected:
            return False
        if self._error_count > max_errors:
            return False
        if self._last_message_time > 0:
            idle_time = time.time() - self._last_message_time
            if idle_time > max_idle_time:
                return False
        return True

    def flush(self):
        """Flush receive buffer."""
        if not self.is_connected:
            return
        count = 0
        while True:
            msg = self.recv(timeout=0.01)
            if msg is None:
                break
            count += 1
        if count > 0:
            from autosploit.lib.utils.formatters import print_info
            print_info(f"Flushed {count} pending messages")
            self.logger.info("Flushed pending messages", count=count)

    def send_and_wait(self, data: bytes, arbitration_id: int,
                      response_id: Optional[int] = None,
                      timeout: float = 1.0,
                      is_extended: bool = False) -> Optional[Message]:
        """Send a message and wait for response."""
        self.flush()

        if not self.send(data, arbitration_id, is_extended):
            return None

        start_time = time.time()
        while (time.time() - start_time) < timeout:
            msg = self.recv(timeout=0.1)

            if msg is None:
                continue

            if response_id is None or msg.arbitration_id == response_id:
                return msg

        return None

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
        return False

