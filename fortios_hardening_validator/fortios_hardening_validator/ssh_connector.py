"""SSH connector module for FortiOS Hardening Validator."""

import time
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


class SSHConnector:
    """Handles SSH connections to FortiGate devices."""

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        port: int = 22,
        timeout: int = 60,
    ):
        """Initialize the SSH connector.

        Args:
            ip: IP address of the FortiGate device
            username: SSH username
            password: SSH password
            port: SSH port (default: 22)
            timeout: Connection timeout in seconds (default: 60)
        """
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.connection = None

    def connect(self) -> bool:
        """Establish SSH connection to the FortiGate device.

        Returns:
            bool: True if connection was successful, False otherwise
        """
        try:
            device_params = {
                "device_type": "fortinet",
                "host": self.ip,
                "username": self.username,
                "password": self.password,
                "port": self.port,
                "timeout": self.timeout,
            }
            self.connection = ConnectHandler(**device_params)
            return True
        except NetmikoAuthenticationException:
            raise ConnectionError("Authentication failed. Check credentials.")
        except NetmikoTimeoutException:
            raise ConnectionError(f"Connection to {self.ip} timed out.")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {self.ip}: {str(e)}")

    def disconnect(self) -> None:
        """Close the SSH connection."""
        if self.connection and self.connection.is_alive():
            self.connection.disconnect()

    def execute_command(self, command: str, timeout: Optional[int] = None) -> str:
        """Execute a command on the FortiGate device.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds (uses default if None)

        Returns:
            str: Command output

        Raises:
            ConnectionError: If connection is not established
        """
        if not self.connection or not self.connection.is_alive():
            raise ConnectionError("Not connected to device. Call connect() first.")

        timeout = timeout or self.timeout
        try:
            output = self.connection.send_command(
                command, 
                expect_string=r"#", 
                delay_factor=2, 
                max_loops=500, 
                strip_prompt=True,
                strip_command=True
            )
            return output
        except Exception as e:
            raise RuntimeError(f"Error executing command: {str(e)}")

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect() 