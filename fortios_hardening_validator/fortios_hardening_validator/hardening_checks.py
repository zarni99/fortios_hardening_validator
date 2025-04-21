"""Hardening checks module for FortiOS Hardening Validator."""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Any, Optional, Set

from .config_fetcher import ConfigFetcher


class CheckStatus(Enum):
    """Status of a hardening check."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class CheckResult:
    """Result of a hardening check."""

    id: str
    name: str
    status: CheckStatus
    description: str
    details: Optional[str] = None
    recommendation: Optional[str] = None


class HardeningChecker:
    """Implements hardening checks for FortiOS."""

    def __init__(self, config_fetcher: ConfigFetcher):
        """Initialize the hardening checker.

        Args:
            config_fetcher: ConfigFetcher instance
        """
        self.config_fetcher = config_fetcher
        self.results: List[CheckResult] = []

    def run_all_checks(self) -> List[CheckResult]:
        """Run all hardening checks.

        Returns:
            List[CheckResult]: Results of all checks
        """
        self.results = []
        
        # Run all check methods
        self.check_password_policy()
        self.check_insecure_protocols()
        self.check_admin_server_cert()
        self.check_trusted_hosts()
        self.check_two_factor_auth()
        self.check_strong_ciphers()
        self.check_logging()
        self.check_ssl_vpn_cert()
        self.check_session_timeout()
        
        return self.results

    def check_password_policy(self) -> CheckResult:
        """Check if password policy is enabled.

        Returns:
            CheckResult: Result of the check
        """
        system_global = self.config_fetcher.get_system_global()
        password_policy = system_global.get("password-policy", "disable")
        
        result = CheckResult(
            id="F-PW-01",
            name="Password Policy",
            description="Checks if password policy is enabled",
            status=CheckStatus.PASS if password_policy == "enable" else CheckStatus.FAIL,
            details=f"Password policy is {password_policy}",
            recommendation="Enable password policy with 'set password-policy enable'"
        )
        
        self.results.append(result)
        return result

    def check_insecure_protocols(self) -> CheckResult:
        """Check if insecure protocols (HTTP, Telnet) are disabled.

        Returns:
            CheckResult: Result of the check
        """
        interfaces = self.config_fetcher.get_system_interface()
        insecure_interfaces = []
        
        for iface_name, iface in interfaces.items():
            allow_access = iface.get("allowaccess", "")
            if "http" in allow_access or "telnet" in allow_access:
                insecure_interfaces.append(
                    f"{iface_name}: {allow_access}"
                )
        
        result = CheckResult(
            id="F-PROT-01",
            name="Insecure Protocols",
            description="Checks if insecure protocols (HTTP, Telnet) are disabled",
            status=CheckStatus.PASS if not insecure_interfaces else CheckStatus.FAIL,
            details=f"Found {len(insecure_interfaces)} interfaces with insecure protocols" if insecure_interfaces else "No insecure protocols found",
            recommendation="Remove 'http' and 'telnet' from allowaccess for all interfaces"
        )
        
        if insecure_interfaces:
            result.details += f": {', '.join(insecure_interfaces)}"
        
        self.results.append(result)
        return result

    def check_admin_server_cert(self) -> CheckResult:
        """Check if HTTPS access uses a valid certificate.

        Returns:
            CheckResult: Result of the check
        """
        system_global = self.config_fetcher.get_system_global()
        admin_server_cert = system_global.get("admin-server-cert", "self-sign")
        
        result = CheckResult(
            id="F-CERT-01",
            name="Admin Server Certificate",
            description="Checks if HTTPS access uses a valid certificate",
            status=CheckStatus.PASS if admin_server_cert != "self-sign" else CheckStatus.WARNING,
            details=f"Admin server certificate is set to '{admin_server_cert}'",
            recommendation="Use a valid certificate instead of 'self-sign' for admin-server-cert"
        )
        
        self.results.append(result)
        return result

    def check_trusted_hosts(self) -> CheckResult:
        """Check if trusted hosts are configured for admin users.

        Returns:
            CheckResult: Result of the check
        """
        admins = self.config_fetcher.get_system_admin()
        admins_without_trusted_hosts = []
        
        for admin_name, admin in admins.items():
            trusted_hosts = [
                h for h in [
                    admin.get("trusthost1"),
                    admin.get("trusthost2"),
                    admin.get("trusthost3"),
                ] 
                if h and h != "0.0.0.0/0"
            ]
            
            if not trusted_hosts:
                admins_without_trusted_hosts.append(admin_name)
        
        result = CheckResult(
            id="F-ADMIN-01",
            name="Trusted Hosts",
            description="Checks if trusted hosts are configured for admin users",
            status=CheckStatus.PASS if not admins_without_trusted_hosts else CheckStatus.FAIL,
            details=f"Found {len(admins_without_trusted_hosts)} admins without trusted hosts" if admins_without_trusted_hosts else "All admins have trusted hosts configured",
            recommendation="Configure trusted hosts for all admin users"
        )
        
        if admins_without_trusted_hosts:
            result.details += f": {', '.join(admins_without_trusted_hosts)}"
        
        self.results.append(result)
        return result

    def check_two_factor_auth(self) -> CheckResult:
        """Check if two-factor authentication is enabled for admin users.

        Returns:
            CheckResult: Result of the check
        """
        admins = self.config_fetcher.get_system_admin()
        admins_without_2fa = []
        
        for admin_name, admin in admins.items():
            two_factor = admin.get("two-factor", "disable")
            if two_factor == "disable":
                admins_without_2fa.append(admin_name)
        
        result = CheckResult(
            id="F-ADMIN-02",
            name="Two-Factor Authentication",
            description="Checks if two-factor authentication is enabled for admin users",
            status=CheckStatus.PASS if not admins_without_2fa else CheckStatus.FAIL,
            details=f"Found {len(admins_without_2fa)} admins without 2FA" if admins_without_2fa else "All admins have 2FA enabled",
            recommendation="Enable two-factor authentication for all admin users"
        )
        
        if admins_without_2fa:
            result.details += f": {', '.join(admins_without_2fa)}"
        
        self.results.append(result)
        return result

    def check_strong_ciphers(self) -> CheckResult:
        """Check if only strong ciphers are used.

        Returns:
            CheckResult: Result of the check
        """
        system_global = self.config_fetcher.get_system_global()
        ssl_versions = system_global.get("admin-https-ssl-versions", "")
        weak_ciphers = set()
        
        if "tlsv1-0" in ssl_versions:
            weak_ciphers.add("TLSv1.0")
        if "tlsv1-1" in ssl_versions:
            weak_ciphers.add("TLSv1.1")
        if "sslv3" in ssl_versions:
            weak_ciphers.add("SSLv3")
        
        # Check SSL VPN settings
        ssl_settings = self.config_fetcher.get_vpn_ssl_settings()
        ssl_cipher = ssl_settings.get("ssl-cipher", "")
        
        if "high" not in ssl_cipher and "medium" not in ssl_cipher:
            weak_ciphers.add(f"SSL VPN ciphers: {ssl_cipher}")
        if "rc4" in ssl_cipher:
            weak_ciphers.add("RC4")
        if "md5" in ssl_cipher:
            weak_ciphers.add("MD5")
        
        result = CheckResult(
            id="F-CIPH-01",
            name="Strong Ciphers",
            description="Checks if only strong ciphers are used",
            status=CheckStatus.PASS if not weak_ciphers else CheckStatus.FAIL,
            details=f"Found weak ciphers: {', '.join(weak_ciphers)}" if weak_ciphers else "Only strong ciphers are used",
            recommendation="Use only TLSv1.2 or higher and avoid weak ciphers like RC4 and MD5"
        )
        
        self.results.append(result)
        return result

    def check_logging(self) -> CheckResult:
        """Check if logging is enabled to FortiAnalyzer or syslog.

        Returns:
            CheckResult: Result of the check
        """
        log_settings = self.config_fetcher.get_log_settings()
        logging_enabled = False
        
        # Check FortiAnalyzer logging
        if log_settings.get("fortianalyzer", {}).get("status", "disable") == "enable":
            logging_enabled = True
        
        # Check syslog logging
        if log_settings.get("syslogd", {}).get("status", "disable") == "enable":
            logging_enabled = True
        
        result = CheckResult(
            id="F-LOG-01",
            name="Logging",
            description="Checks if logging is enabled to FortiAnalyzer or syslog",
            status=CheckStatus.PASS if logging_enabled else CheckStatus.FAIL,
            details="Logging is enabled" if logging_enabled else "Logging is not enabled to FortiAnalyzer or syslog",
            recommendation="Enable logging to FortiAnalyzer or syslog"
        )
        
        self.results.append(result)
        return result

    def check_ssl_vpn_cert(self) -> CheckResult:
        """Check if SSL VPN uses a valid certificate.

        Returns:
            CheckResult: Result of the check
        """
        ssl_settings = self.config_fetcher.get_vpn_ssl_settings()
        servercert = ssl_settings.get("servercert", "self-sign")
        
        result = CheckResult(
            id="F-VPN-01",
            name="SSL VPN Certificate",
            description="Checks if SSL VPN uses a valid certificate",
            status=CheckStatus.PASS if servercert != "self-sign" else CheckStatus.WARNING,
            details=f"SSL VPN certificate is set to '{servercert}'",
            recommendation="Use a valid certificate instead of 'self-sign' for SSL VPN"
        )
        
        self.results.append(result)
        return result

    def check_session_timeout(self) -> CheckResult:
        """Check if session timeout is configured and low.

        Returns:
            CheckResult: Result of the check
        """
        system_global = self.config_fetcher.get_system_global()
        admin_timeout = system_global.get("admin-timeout", "0")
        
        try:
            timeout_min = int(admin_timeout)
            if timeout_min == 0:
                status = CheckStatus.FAIL
                details = "Admin timeout is disabled (0)"
            elif timeout_min > 15:
                status = CheckStatus.WARNING
                details = f"Admin timeout is set to {timeout_min} minutes, which is higher than recommended"
            else:
                status = CheckStatus.PASS
                details = f"Admin timeout is set to {timeout_min} minutes"
        except ValueError:
            status = CheckStatus.FAIL
            details = f"Invalid admin timeout value: {admin_timeout}"
        
        result = CheckResult(
            id="F-SESS-01",
            name="Session Timeout",
            description="Checks if session timeout is configured and low",
            status=status,
            details=details,
            recommendation="Set admin timeout to 15 minutes or less"
        )
        
        self.results.append(result)
        return result 