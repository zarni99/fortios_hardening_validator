"""Config fetcher module for FortiOS Hardening Validator."""

from typing import Dict, Any, List, Optional

from .ssh_connector import SSHConnector


class ConfigFetcher:
    """Fetches and parses FortiGate configuration."""

    def __init__(self, connector: SSHConnector):
        """Initialize the config fetcher.

        Args:
            connector: SSHConnector instance
        """
        self.connector = connector
        self.raw_config = ""
        self.parsed_config: Dict[str, Any] = {}

    def fetch_config(self) -> str:
        """Fetch full configuration from the FortiGate device.

        Returns:
            str: Raw configuration text
        """
        self.raw_config = self.connector.execute_command("show full-configuration")
        return self.raw_config

    def parse_config(self) -> Dict[str, Any]:
        """Parse the raw configuration into a structured format.

        Returns:
            Dict[str, Any]: Parsed configuration
        """
        if not self.raw_config:
            self.fetch_config()

        result: Dict[str, Any] = {}
        current_section = None
        section_stack = []
        indent_level = 0

        for line in self.raw_config.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue

            # Calculate indent level
            current_indent = len(line) - len(line.lstrip())
            
            if stripped.startswith('config '):
                section_name = stripped[7:]  # Remove 'config ' prefix
                if current_section is None:
                    result[section_name] = {}
                    current_section = result[section_name]
                else:
                    if section_name not in current_section:
                        current_section[section_name] = {}
                    section_stack.append((current_section, indent_level))
                    current_section = current_section[section_name]
                indent_level = current_indent

            elif stripped.startswith('edit '):
                edit_value = stripped[5:].strip('"\'')  # Remove 'edit ' prefix and quotes
                if 'entries' not in current_section:
                    current_section['entries'] = {}
                if edit_value not in current_section['entries']:
                    current_section['entries'][edit_value] = {}
                section_stack.append((current_section, indent_level))
                current_section = current_section['entries'][edit_value]
                indent_level = current_indent

            elif stripped.startswith('set '):
                parts = stripped[4:].split(' ', 1)  # Remove 'set ' prefix and split
                key = parts[0]
                value = parts[1].strip('"\'') if len(parts) > 1 else ''
                current_section[key] = value

            elif stripped == 'next':
                if section_stack:
                    current_section, indent_level = section_stack.pop()

            elif stripped == 'end':
                if section_stack:
                    current_section, indent_level = section_stack.pop()
                else:
                    current_section = None
                    indent_level = 0

        self.parsed_config = result
        return result

    def get_system_global(self) -> Dict[str, str]:
        """Get system global configuration section.

        Returns:
            Dict[str, str]: System global configuration
        """
        if not self.parsed_config:
            self.parse_config()
        
        return self.parsed_config.get('system', {}).get('global', {})

    def get_system_interface(self) -> Dict[str, Dict]:
        """Get system interface configuration.

        Returns:
            Dict[str, Dict]: System interface configuration
        """
        if not self.parsed_config:
            self.parse_config()
        
        interfaces = self.parsed_config.get('system', {}).get('interface', {}).get('entries', {})
        return interfaces

    def get_system_admin(self) -> Dict[str, Dict]:
        """Get system admin configuration.

        Returns:
            Dict[str, Dict]: System admin configuration
        """
        if not self.parsed_config:
            self.parse_config()
        
        admins = self.parsed_config.get('system', {}).get('admin', {}).get('entries', {})
        return admins

    def get_vpn_ssl_settings(self) -> Dict[str, str]:
        """Get VPN SSL settings.

        Returns:
            Dict[str, str]: VPN SSL settings
        """
        if not self.parsed_config:
            self.parse_config()
        
        return self.parsed_config.get('vpn', {}).get('ssl', {}).get('settings', {})

    def get_log_settings(self) -> Dict[str, Any]:
        """Get logging settings.

        Returns:
            Dict[str, Any]: Logging settings
        """
        if not self.parsed_config:
            self.parse_config()
        
        return {
            'syslogd': self.parsed_config.get('log', {}).get('syslogd', {}).get('setting', {}),
            'fortianalyzer': self.parsed_config.get('log', {}).get('fortianalyzer', {}).get('setting', {}),
            'memory': self.parsed_config.get('log', {}).get('memory', {}).get('setting', {}),
            'disk': self.parsed_config.get('log', {}).get('disk', {}).get('setting', {})
        } 