"""Config fetcher module for FortiOS Hardening Validator."""

from typing import Dict, Any, List, Optional, Set, Tuple
import re
import logging

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
        self.admin_config = ""  # Specific admin configuration
        self.parsed_config: Dict[str, Any] = {}
        self.device_version = ""
        self.device_model = ""

    def _get_device_info(self) -> Dict[str, str]:
        """Get basic device information for version-specific handling.
        
        Returns:
            Dict[str, str]: Basic device information
        """
        try:
            status_output = self.connector.execute_command("get system status")
            version_match = re.search(r"Version:\s+(.+)", status_output)
            model_match = re.search(r"Version:\s+(\w+)-", status_output)
            
            info = {}
            if version_match:
                self.device_version = version_match.group(1).strip()
                info["version"] = self.device_version
            if model_match:
                self.device_model = model_match.group(1).strip()
                info["model"] = self.device_model
                
            return info
        except Exception:
            return {}

    def fetch_config(self) -> str:
        """Fetch full configuration from the FortiGate device using multiple strategies.

        Returns:
            str: Raw configuration text
        """
        # Get basic device information first
        self._get_device_info()
        
        # Try primary config command
        self.raw_config = self.connector.execute_command("show full-configuration")
        
        # Check if admin config section exists, if not try to supplement
        admin_section_found = bool(re.search(r"config\s+system\s+admin", self.raw_config))
        
        # Fetch admin-specific config if needed
        if not admin_section_found:
            try:
                admin_cmd_output = self.connector.execute_command("show system admin")
                self.admin_config = admin_cmd_output
                # Check for CLI prompt format and extract actual config
                cli_pattern = r"(config\s+system\s+admin.*?)(\n\w+-\w+\s+#|\Z)"
                match = re.search(cli_pattern, admin_cmd_output, re.DOTALL)
                if match:
                    self.admin_config = match.group(1)
                self.raw_config += "\n" + self.admin_config
            except Exception:
                # Try alternative command
                try:
                    admin_config = self.connector.execute_command("get system admin")
                    self.admin_config = admin_config
                    self.raw_config += "\n" + self.admin_config
                except Exception:
                    pass
            
            # Last resort: diagnostic command
            if not self.admin_config:
                try:
                    debug_output = self.connector.execute_command("diagnose debug config-error-log read")
                    # Extract admin sections from debug log
                    admin_sections = re.findall(r"(config system admin.*?end)", debug_output, re.DOTALL)
                    if admin_sections:
                        self.admin_config = "\n".join(admin_sections)
                        self.raw_config += "\n" + self.admin_config
                except Exception:
                    pass
        
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
        
        # Clean up CLI prompts and normalize line endings
        cleaned_config = self._clean_config(self.raw_config)

        for line in cleaned_config.splitlines():
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
    
    def _clean_config(self, config: str) -> str:
        """Clean FortiOS configuration output by removing CLI prompts and normalizing.
        
        Args:
            config: Raw configuration string
            
        Returns:
            str: Cleaned configuration string
        """
        # Remove CLI prompts (FortiGate-XXX # )
        lines = []
        for line in config.splitlines():
            # Remove FortiGate CLI prompts
            prompt_pattern = r"^\s*\w+-\w+(-\w+)*\s+#\s+"
            line = re.sub(prompt_pattern, "", line)
            
            # Skip empty lines after removing prompt
            if line.strip():
                lines.append(line)
                
        return "\n".join(lines)

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
        """Get system admin configuration using multiple detection methods.

        Returns:
            Dict[str, Dict]: System admin configuration
        """
        if not self.parsed_config:
            self.parse_config()
        
        # For deeper debugging, log the structure of the parsed config
        admin_config = self.parsed_config.get('system', {}).get('admin', {})
        
        # This is a common structure in FortiOS config
        admins = admin_config.get('entries', {})
        
        # If empty and we have any config, try advanced detection methods
        if not admins and (self.raw_config or self.admin_config):
            # Use all available text sources
            all_text = self.raw_config
            if self.admin_config and self.admin_config not in self.raw_config:
                all_text += "\n" + self.admin_config
            
            # Create a dictionary for admin users detected with manual methods
            manual_admins = self._extract_admin_users(all_text)
            
            # If we found admin users with manual parsing, use them
            if manual_admins:
                return manual_admins
                
            # Last resort - try to extract from CLI command outputs
            if not manual_admins:
                manual_admins = self._extract_admin_from_cli_output(all_text)
                
            # If we found any admins, return them
            if manual_admins:
                return manual_admins
                
            # Absolute last resort - assume default admin account
            return {
                "admin": {
                    "two-factor": "disable",  # Default assumption
                    "accprofile": "super_admin"  # Default assumption
                }
            }
        
        return admins
    
    def _extract_admin_users(self, text: str) -> Dict[str, Dict]:
        """Extract admin user information from raw text using multiple patterns.
        
        Args:
            text: Raw configuration or admin-specific text
            
        Returns:
            Dict[str, Dict]: Dictionary of admin users and their settings
        """
        manual_admins = {}
        
        # Method 1: Complete admin sections with standard format
        in_admin_section = False
        current_admin = None
        admin_data = {}
        section_level = 0
        
        for line in text.splitlines():
            stripped = line.strip()
            
            # Skip empty lines and comments
            if not stripped or stripped.startswith('#'):
                continue
                
            # Detect entry into admin config section
            if re.match(r"config\s+system\s+admin", stripped):
                in_admin_section = True
                section_level = 1
                continue
                
            # Track nested config levels
            if in_admin_section and stripped.startswith("config "):
                section_level += 1
                continue
                
            # Exit admin section or nested config
            if in_admin_section and stripped == "end":
                section_level -= 1
                if section_level <= 0:
                    in_admin_section = False
                continue
            
            # If we're in admin section at the right level
            if in_admin_section and section_level == 1:
                # Detect new admin user
                if stripped.startswith('edit '):
                    # If we have a previous admin, save it
                    if current_admin:
                        manual_admins[current_admin] = admin_data.copy()
                    
                    # Start new admin
                    admin_name = stripped[5:].strip().strip('"\'')
                    current_admin = admin_name
                    admin_data = {}
                
                # Detect settings for current admin
                elif current_admin and stripped.startswith('set '):
                    try:
                        parts = stripped[4:].split(' ', 1)
                        key = parts[0]
                        value = parts[1].strip('"\'') if len(parts) > 1 else ''
                        admin_data[key] = value
                    except Exception:
                        # Skip malformed settings
                        pass
                
                # End of this admin user
                elif stripped == "next" and current_admin:
                    manual_admins[current_admin] = admin_data.copy()
                    admin_data = {}
                    current_admin = None
        
        # Method 2: If method 1 failed, try more aggressive pattern matching
        if not manual_admins:
            # Look for admin edit entries
            admin_entries = re.finditer(r"edit\s+[\"']?(\w+)[\"']?", text)
            for match in admin_entries:
                admin_name = match.group(1).strip()
                
                # Context check to ensure this is an admin user
                context_start = max(0, match.start() - 200)
                context_end = min(len(text), match.end() + 500)
                context = text[context_start:context_end]
                
                # Check if this looks like an admin section
                if "system admin" in context or "accprofile" in context:
                    manual_admins[admin_name] = {}
                    
                    # Extract common admin settings
                    for setting in ["two-factor", "trusthost1", "accprofile"]:
                        setting_pattern = rf"set\s+{setting}\s+([^\s\"']+|\"[^\"]+\"|'[^']+')"
                        setting_match = re.search(setting_pattern, context)
                        if setting_match:
                            value = setting_match.group(1).strip('"\'')
                            manual_admins[admin_name][setting] = value
                    
                    # Default to disabled 2FA if not specified
                    if "two-factor" not in manual_admins[admin_name]:
                        manual_admins[admin_name]["two-factor"] = "disable"
        
        # Method 3: Look for specific key patterns in admin commands output
        if not manual_admins:
            # Find admin users by looking for specific patterns in CLI/diagnostic output
            for key_pattern in [
                r"edit\s+\"?(\w+)\"?\s+.*?set\s+accprofile",
                r"edit\s+\"?(\w+)\"?\s+.*?set\s+password",
                r"system\s+admin.*?edit\s+\"?(\w+)\"?"
            ]:
                matches = re.finditer(key_pattern, text, re.DOTALL)
                for match in matches:
                    admin_name = match.group(1).strip()
                    if admin_name and admin_name not in manual_admins:
                        # Get context around this match
                        context_start = max(0, match.start() - 100)
                        context_end = min(len(text), match.start() + 500)
                        context = text[context_start:context_end]
                        
                        manual_admins[admin_name] = {}
                        
                        # Try to extract two-factor setting
                        two_factor_match = re.search(r"set\s+two-factor\s+(\w+)", context)
                        if two_factor_match:
                            manual_admins[admin_name]['two-factor'] = two_factor_match.group(1)
                        else:
                            manual_admins[admin_name]['two-factor'] = 'disable'  # Default
        
        return manual_admins
    
    def _extract_admin_from_cli_output(self, text: str) -> Dict[str, Dict]:
        """Extract admin information from CLI output formats.
        
        Args:
            text: CLI output text
            
        Returns:
            Dict[str, Dict]: Dictionary of admin users and their settings
        """
        admins = {}
        
        # Handle CLI command output format (FortiGate-XXX # get system admin)
        cli_lines = text.splitlines()
        
        # Look for any admin-related entries
        for i, line in enumerate(cli_lines):
            if "system admin" in line.lower() and i < len(cli_lines) - 1:
                # This might be the start of admin config
                # Check next 10 lines for admin user info
                for j in range(i+1, min(i+20, len(cli_lines))):
                    if re.search(r"edit\s+[\"']?(\w+)[\"']?", cli_lines[j]):
                        match = re.search(r"edit\s+[\"']?(\w+)[\"']?", cli_lines[j])
                        admin_name = match.group(1)
                        
                        # Found admin user, extract settings
                        admins[admin_name] = {"two-factor": "disable"}  # Default
                        
                        # Check next lines for settings
                        k = j + 1
                        while k < len(cli_lines) and k < j + 20:
                            if re.match(r"\s*set\s+two-factor\s+(\w+)", cli_lines[k]):
                                setting_match = re.match(r"\s*set\s+two-factor\s+(\w+)", cli_lines[k])
                                if setting_match:
                                    admins[admin_name]["two-factor"] = setting_match.group(1)
                            # Stop when we hit end of this admin config
                            if re.match(r"\s*next", cli_lines[k]) or re.match(r"\s*end", cli_lines[k]):
                                break
                            k += 1
            
            # Check for standalone admin mentions
            admin_match = re.search(r"admin\s+user:\s+(\w+)", line, re.IGNORECASE)
            if admin_match and admin_match.group(1) not in admins:
                admin_name = admin_match.group(1)
                admins[admin_name] = {"two-factor": "disable"}  # Default
        
        return admins

    def get_vpn_ssl_settings(self) -> Dict[str, str]:
        """Get VPN SSL settings.

        Returns:
            Dict[str, str]: VPN SSL settings
        """
        if not self.parsed_config:
            self.parse_config()
        
        # Check standard location
        ssl_settings = self.parsed_config.get('vpn', {}).get('ssl', {}).get('settings', {})
        
        # If empty, try fallback methods
        if not ssl_settings and self.raw_config:
            # Extract settings using regex patterns
            ssl_settings = {}
            
            # Common SSL VPN settings to look for
            for setting in ["servercert", "ssl-cipher", "tlsv1-0", "tlsv1-1", "tlsv1-2"]:
                pattern = rf"set\s+{setting}\s+([^\s\"']+|\"[^\"]+\"|'[^']+')"
                match = re.search(pattern, self.raw_config)
                if match:
                    value = match.group(1).strip('"\'')
                    ssl_settings[setting] = value
        
        return ssl_settings

    def get_log_settings(self) -> Dict[str, Any]:
        """Get logging settings.

        Returns:
            Dict[str, Any]: Logging settings
        """
        if not self.parsed_config:
            self.parse_config()
        
        settings = {
            'syslogd': self.parsed_config.get('log', {}).get('syslogd', {}).get('setting', {}),
            'fortianalyzer': self.parsed_config.get('log', {}).get('fortianalyzer', {}).get('setting', {}),
            'memory': self.parsed_config.get('log', {}).get('memory', {}).get('setting', {}),
            'disk': self.parsed_config.get('log', {}).get('disk', {}).get('setting', {})
        }
        
        # If settings are empty, try fallback regex methods
        if not any(settings.values()) and self.raw_config:
            # Extract settings using regex patterns
            for log_type in settings.keys():
                # Look for log status setting
                pattern = rf"config\s+log\s+{log_type}.*?set\s+status\s+(\w+)"
                match = re.search(pattern, self.raw_config, re.DOTALL)
                if match:
                    settings[log_type] = {"status": match.group(1)}
        
        return settings 