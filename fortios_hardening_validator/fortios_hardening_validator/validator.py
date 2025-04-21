"""Validation module for FortiOS Hardening Validator."""

import re
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple

from .config_fetcher import ConfigFetcher
from .hardening_checks import CheckResult, CheckStatus, HardeningChecker


class ResultValidator:
    """Validates the results of hardening checks against raw configuration."""

    def __init__(self, config_fetcher: ConfigFetcher, hardening_checker: HardeningChecker):
        """Initialize the result validator.
        
        Args:
            config_fetcher: ConfigFetcher instance with raw and parsed config
            hardening_checker: HardeningChecker instance with check results
        """
        self.config_fetcher = config_fetcher
        self.hardening_checker = hardening_checker
        self.validation_results: List[CheckResult] = []
        
    def validate_all(self, level: str = "basic") -> List[CheckResult]:
        """Run all validations at the specified level.
        
        Args:
            level: Validation level (basic, thorough, or paranoid)
            
        Returns:
            List[CheckResult]: Results of validation checks
        """
        self.validation_results = []
        
        # Basic validation
        self.validation_results.append(self.validate_config_structure())
        self.validation_results.append(self.validate_admin_parsing())
        
        if level in ["thorough", "paranoid"]:
            # Thorough validation
            self.validation_results.append(self.validate_parsing_consistency())
            self.validation_results.append(self.validate_result_consistency())
            
        if level == "paranoid":
            # Paranoid validation - most thorough but may produce false positives
            self.validation_results.append(self.validate_results_against_raw())
            self.validation_results.append(self.compare_regex_parsing())
            
        return self.validation_results
    
    def validate_config_structure(self) -> CheckResult:
        """Validate the basic structure of the parsed configuration.
        
        Returns:
            CheckResult: Validation result
        """
        expected_sections = ["system", "vpn", "log"]
        expected_subsections = {
            "system": ["global", "admin", "interface"],
            "vpn": ["ssl"],
            "log": ["memory", "disk", "fortianalyzer", "syslogd"]
        }
        
        missing_sections = []
        missing_subsections = []
        
        # Check top-level sections
        for section in expected_sections:
            if section not in self.config_fetcher.parsed_config:
                missing_sections.append(section)
            else:
                # Check subsections
                for subsection in expected_subsections.get(section, []):
                    if subsection not in self.config_fetcher.parsed_config.get(section, {}):
                        missing_subsections.append(f"{section}.{subsection}")
        
        if missing_sections or missing_subsections:
            details = []
            if missing_sections:
                details.append(f"Missing top-level sections: {', '.join(missing_sections)}")
            if missing_subsections:
                details.append(f"Missing subsections: {', '.join(missing_subsections)}")
                
            return CheckResult(
                id="VALIDATE-01",
                name="Configuration Structure",
                status=CheckStatus.WARNING,
                description="Validates basic configuration structure",
                details="\n".join(details),
                recommendation="Check configuration parsing logic or ensure FortiGate exports complete config"
            )
        
        return CheckResult(
            id="VALIDATE-01",
            name="Configuration Structure",
            status=CheckStatus.PASS,
            description="Validates basic configuration structure",
            details="All expected configuration sections found",
            recommendation=None
        )
    
    def validate_admin_parsing(self) -> CheckResult:
        """Specifically validate admin user parsing which is critical for 2FA checks.
        
        Returns:
            CheckResult: Validation result
        """
        raw_config = self.config_fetcher.raw_config
        
        # Count admin users in raw config using regex
        admin_pattern = r"config system admin\s+.*?edit\s+[\"']?(\w+)[\"']?"
        admin_matches = re.finditer(admin_pattern, raw_config, re.DOTALL)
        admin_users_raw = [m.group(1) for m in admin_matches if m.group(1)]
        
        # Get admin users from parsed config
        parsed_admins = self.config_fetcher.get_system_admin()
        
        # Compare counts and names
        admin_count_raw = len(admin_users_raw)
        admin_count_parsed = len(parsed_admins)
        
        if admin_count_raw != admin_count_parsed:
            return CheckResult(
                id="VALIDATE-02",
                name="Admin User Parsing",
                status=CheckStatus.WARNING,
                description="Validates admin user parsing",
                details=f"Found {admin_count_raw} admin users in raw config but {admin_count_parsed} in parsed config.\n"
                        f"Raw admins: {', '.join(admin_users_raw)}\n"
                        f"Parsed admins: {', '.join(parsed_admins.keys())}",
                recommendation="Review admin configuration parsing logic"
            )
            
        # If counts match, check for specific admin settings
        admin_checks = [
            ("two-factor", r"set two-factor\s+(\w+)"),
            ("trusthost1", r"set trusthost1\s+(\S+)")
        ]
        
        setting_issues = []
        
        for admin_name, admin_config in parsed_admins.items():
            # Find the admin section in raw config
            admin_section_pattern = fr"edit\s+[\"']?{admin_name}[\"']?.*?next"
            admin_section_match = re.search(admin_section_pattern, raw_config, re.DOTALL)
            
            if not admin_section_match:
                setting_issues.append(f"Could not find section for admin '{admin_name}' in raw config")
                continue
                
            admin_section = admin_section_match.group(0)
            
            for setting_name, setting_pattern in admin_checks:
                # Check if setting exists in the parsed config
                parsed_value = admin_config.get(setting_name)
                
                # Look for the setting in raw config
                setting_match = re.search(setting_pattern, admin_section)
                raw_value = setting_match.group(1) if setting_match else None
                
                if parsed_value != raw_value:
                    setting_issues.append(
                        f"Admin '{admin_name}' setting '{setting_name}' mismatch: "
                        f"'{parsed_value}' in parsed config vs '{raw_value}' in raw config"
                    )
        
        if setting_issues:
            return CheckResult(
                id="VALIDATE-02",
                name="Admin User Parsing",
                status=CheckStatus.WARNING,
                description="Validates admin user parsing",
                details=f"Found issues in admin settings parsing:\n" + "\n".join(setting_issues),
                recommendation="Review admin configuration parsing logic"
            )
            
        return CheckResult(
            id="VALIDATE-02",
            name="Admin User Parsing",
            status=CheckStatus.PASS,
            description="Validates admin user parsing",
            details=f"All {admin_count_parsed} admin users and their settings parsed correctly",
            recommendation=None
        )
    
    def validate_parsing_consistency(self) -> CheckResult:
        """Validate that parsing is consistent across multiple runs.
        
        Returns:
            CheckResult: Validation result
        """
        # Save original parsed config
        original_config = self.config_fetcher.parsed_config
        
        # Reparse the config
        self.config_fetcher.parsed_config = {}
        self.config_fetcher.parse_config()
        reparsed_config = self.config_fetcher.parsed_config
        
        # Compare structure and key values
        differences = self._compare_parsed_configs(original_config, reparsed_config)
        
        # Restore original config
        self.config_fetcher.parsed_config = original_config
        
        if differences:
            return CheckResult(
                id="VALIDATE-03",
                name="Parsing Consistency",
                status=CheckStatus.WARNING,
                description="Validates parsing consistency across multiple runs",
                details=f"Found {len(differences)} inconsistencies in parsing results:\n" + 
                        "\n".join(differences[:10]) +
                        (f"\n... and {len(differences) - 10} more issues" if len(differences) > 10 else ""),
                recommendation="Parsing logic may be non-deterministic or affected by external factors"
            )
            
        return CheckResult(
            id="VALIDATE-03",
            name="Parsing Consistency",
            status=CheckStatus.PASS,
            description="Validates parsing consistency across multiple runs",
            details="Configuration parsing is consistent between runs",
            recommendation=None
        )
    
    def validate_result_consistency(self) -> CheckResult:
        """Validate internal consistency between different check results.
        
        Returns:
            CheckResult: Validation result
        """
        inconsistencies = []
        
        # Check for consistency in admin checks
        checks_by_id = {check.id: check for check in self.hardening_checker.results}
        
        # Compare admin counts between trusted hosts and 2FA checks
        if "F-ADMIN-01" in checks_by_id and "F-ADMIN-02" in checks_by_id:
            th_check = checks_by_id["F-ADMIN-01"]
            fa_check = checks_by_id["F-ADMIN-02"]
            
            # Extract admin count from details (a bit fragile but should work)
            if "Found" in th_check.details and "Found" in fa_check.details:
                th_count = re.search(r"Found (\d+) admins", th_check.details)
                fa_count = re.search(r"Found (\d+) admins", fa_check.details)
                
                if th_count and fa_count and th_count.group(1) != fa_count.group(1):
                    inconsistencies.append(
                        f"Admin count mismatch: {th_count.group(1)} in trusted hosts check vs "
                        f"{fa_count.group(1)} in 2FA check"
                    )
        
        # Check for consistent status in related checks
        related_checks = [
            ("F-CERT-01", "F-VPN-01")  # Admin cert and SSL VPN cert
        ]
        
        for check1_id, check2_id in related_checks:
            if check1_id in checks_by_id and check2_id in checks_by_id:
                check1 = checks_by_id[check1_id]
                check2 = checks_by_id[check2_id]
                
                # If checks are related and should have similar results, flag inconsistencies
                if check1.status != check2.status:
                    inconsistencies.append(
                        f"Related checks have different statuses: {check1_id} is {check1.status.value} "
                        f"but {check2_id} is {check2.status.value}"
                    )
        
        if inconsistencies:
            return CheckResult(
                id="VALIDATE-04",
                name="Result Consistency",
                status=CheckStatus.WARNING,
                description="Validates internal consistency between check results",
                details="Found inconsistencies between related check results:\n" + "\n".join(inconsistencies),
                recommendation="Review the inconsistent checks for potential false positives/negatives"
            )
            
        return CheckResult(
            id="VALIDATE-04",
            name="Result Consistency",
            status=CheckStatus.PASS,
            description="Validates internal consistency between check results",
            details="All check results are internally consistent",
            recommendation=None
        )
    
    def validate_results_against_raw(self) -> CheckResult:
        """Validate check results directly against patterns in raw configuration.
        
        Returns:
            CheckResult: Validation result
        """
        raw_config = self.config_fetcher.raw_config
        checks_by_id = {check.id: check for check in self.hardening_checker.results}
        validation_issues = []
        
        # Define validation rules: check ID, pattern to search for, expected status if pattern found
        validation_rules = [
            ("F-PW-01", r"set password-policy enable", CheckStatus.PASS),
            ("F-PW-01", r"set password-policy disable", CheckStatus.FAIL),
            ("F-ADMIN-02", r"set two-factor enable", CheckStatus.PASS),
            ("F-ADMIN-02", r"set two-factor disable", CheckStatus.FAIL),
            ("F-CERT-01", r"set admin-server-cert\s+[\"']?self-sign[\"']?", CheckStatus.WARNING),
            ("F-VPN-01", r"set servercert\s+[\"']?self-sign[\"']?", CheckStatus.WARNING),
            ("F-SESS-01", r"set admin-timeout\s+0", CheckStatus.FAIL),
        ]
        
        for check_id, pattern, expected_status in validation_rules:
            if check_id not in checks_by_id:
                continue
                
            check_result = checks_by_id[check_id]
            pattern_matches = re.search(pattern, raw_config) is not None
            
            # If pattern exists in raw config, check should have expected status
            if pattern_matches and check_result.status != expected_status:
                validation_issues.append(
                    f"Check {check_id} ({check_result.name}) has status {check_result.status.value} "
                    f"but raw config contains pattern '{pattern}' which suggests {expected_status.value}"
                )
        
        if validation_issues:
            return CheckResult(
                id="VALIDATE-05",
                name="Raw Config Validation",
                status=CheckStatus.WARNING,
                description="Validates check results against patterns in raw configuration",
                details="Found potential discrepancies between check results and raw configuration:\n" + 
                        "\n".join(validation_issues),
                recommendation="Review identified checks for potential false results"
            )
            
        return CheckResult(
            id="VALIDATE-05",
            name="Raw Config Validation",
            status=CheckStatus.PASS,
            description="Validates check results against patterns in raw configuration",
            details="All validated check results match expected patterns in raw configuration",
            recommendation=None
        )
    
    def compare_regex_parsing(self) -> CheckResult:
        """Compare main parsing with regex-based parsing for critical settings.
        
        Returns:
            CheckResult: Validation result
        """
        raw_config = self.config_fetcher.raw_config
        discrepancies = []
        
        # Define critical settings to verify with regex
        critical_settings = [
            # Setting path in parsed config, regex pattern, extraction group index or name
            (("system", "global", "password-policy"), 
             r"config system global\s+.*?set password-policy\s+(\w+)", 1),
            
            (("system", "global", "admin-timeout"), 
             r"config system global\s+.*?set admin-timeout\s+(\d+)", 1),
             
            (("system", "global", "admin-server-cert"), 
             r"config system global\s+.*?set admin-server-cert\s+[\"']?(\S+)[\"']?", 1),
        ]
        
        for config_path, regex_pattern, group_idx in critical_settings:
            # Get value from parsed config
            parsed_value = self._get_nested_value(self.config_fetcher.parsed_config, config_path)
            
            # Get value using regex
            regex_match = re.search(regex_pattern, raw_config, re.DOTALL)
            regex_value = regex_match.group(group_idx) if regex_match else None
            
            if parsed_value != regex_value:
                discrepancies.append(
                    f"Setting {'.'.join(config_path)} value mismatch: "
                    f"'{parsed_value}' in parsed config vs '{regex_value}' from regex"
                )
        
        if discrepancies:
            return CheckResult(
                id="VALIDATE-06",
                name="Alternative Parsing Comparison",
                status=CheckStatus.WARNING,
                description="Compares main parsing with regex-based parsing for critical settings",
                details="Found discrepancies between parsing methods:\n" + "\n".join(discrepancies),
                recommendation="Review config parsing logic for potential issues"
            )
            
        return CheckResult(
            id="VALIDATE-06",
            name="Alternative Parsing Comparison",
            status=CheckStatus.PASS,
            description="Compares main parsing with regex-based parsing for critical settings",
            details="All critical settings match between different parsing methods",
            recommendation=None
        )
    
    def _compare_parsed_configs(self, config1: Dict, config2: Dict, path: str = "") -> List[str]:
        """Compare two parsed configurations recursively.
        
        Args:
            config1: First configuration dictionary
            config2: Second configuration dictionary
            path: Current path in the configuration (for reporting)
            
        Returns:
            List[str]: List of differences found
        """
        differences = []
        
        # Check keys in config1
        all_keys = set(config1.keys()) | set(config2.keys())
        
        for key in all_keys:
            current_path = f"{path}.{key}" if path else key
            
            # Check if key exists in both configs
            if key not in config1:
                differences.append(f"Key '{current_path}' missing in first config")
                continue
                
            if key not in config2:
                differences.append(f"Key '{current_path}' missing in second config")
                continue
                
            # Compare values
            value1, value2 = config1[key], config2[key]
            
            if isinstance(value1, dict) and isinstance(value2, dict):
                # Recursively compare dictionaries
                differences.extend(self._compare_parsed_configs(value1, value2, current_path))
            elif value1 != value2:
                differences.append(
                    f"Value mismatch for '{current_path}': '{value1}' vs '{value2}'"
                )
        
        return differences
    
    def _get_nested_value(self, config: Dict, path: Tuple) -> Any:
        """Get a value from a nested dictionary.
        
        Args:
            config: Configuration dictionary
            path: Tuple of keys to traverse
            
        Returns:
            Any: The value at the specified path, or None if not found
        """
        current = config
        for key in path:
            if not isinstance(current, dict) or key not in current:
                return None
            current = current[key]
        return current 