# FortiOS Hardening Validator

A Python CLI tool that connects to FortiGate devices and validates their configuration against FortiOS 7.6.0 hardening best practices.

## Features

- Securely connects to FortiGate devices using SSH
- Fetches full configuration using `show full-configuration`
- Parses configuration and validates against security best practices
- Generates detailed reports in CLI or JSON format
- Configurable connection options (timeout, port)
- Secure password handling with interactive prompt

## Security Checks

| ID | Name | Description |
|---|---|---|
| F-PW-01 | Password Policy | Ensures password policy is enabled |
| F-PROT-01 | Insecure Protocols | Checks if HTTP and Telnet are disabled on all interfaces |
| F-CERT-01 | Admin Server Certificate | Validates HTTPS admin access uses proper certificates |
| F-ADMIN-01 | Trusted Hosts | Verifies trusted hosts are configured for admin users |
| F-ADMIN-02 | Two-Factor Authentication | Checks if 2FA is enabled for admin accounts |
| F-CIPH-01 | Strong Ciphers | Validates only strong ciphers are in use (no RC4, MD5) |
| F-LOG-01 | Logging | Confirms logging is enabled to FortiAnalyzer or syslog |
| F-VPN-01 | SSL VPN Certificate | Checks if SSL VPN uses a valid certificate |
| F-SESS-01 | Session Timeout | Verifies session timeout is configured and reasonably low |

## Installation

### Option 1: Install from the repository (recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/fortios_hardening_validator.git
cd fortios_hardening_validator

# Install the package in development mode
pip install -e .
```

### Option 2: Install dependencies only

```bash
# Clone the repository
git clone https://github.com/yourusername/fortios_hardening_validator.git
cd fortios_hardening_validator

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Command-line interface

```bash
# Basic usage with interactive password prompt (recommended)
fortios-audit --ip 192.168.1.1 --username admin --prompt-password

# Output results in JSON format
fortios-audit --ip 192.168.1.1 --username admin --prompt-password --format json

# Save report to a file
fortios-audit --ip 192.168.1.1 --username admin --prompt-password --output-file report.json --format json

# Full options list
fortios-audit --help
```

## Project Structure

```
fortios_hardening_validator/
├── fortios_hardening_validator/  # Main package
│   ├── __init__.py
│   ├── cli.py                   # CLI entrypoint
│   ├── ssh_connector.py         # SSH connection handling
│   ├── config_fetcher.py        # Configuration retrieval
│   ├── hardening_checks.py      # Security validation logic
│   └── report_generator.py      # Report formatting
├── README.md                    # Documentation
├── pyproject.toml               # Project metadata
└── requirements.txt             # Dependencies
```

## Programmatic Usage

You can also use the package programmatically in your own Python scripts:

```python
from fortios_hardening_validator.fortios_hardening_validator.ssh_connector import SSHConnector
from fortios_hardening_validator.fortios_hardening_validator.config_fetcher import ConfigFetcher
from fortios_hardening_validator.fortios_hardening_validator.hardening_checks import HardeningChecker
from fortios_hardening_validator.fortios_hardening_validator.report_generator import ReportGenerator

# Connect to the device
with SSHConnector("192.168.1.1", "admin", "password") as connector:
    # Fetch and parse configuration
    config_fetcher = ConfigFetcher(connector)
    config_fetcher.fetch_config()
    config_fetcher.parse_config()
    
    # Run hardening checks
    checker = HardeningChecker(config_fetcher)
    results = checker.run_all_checks()
    
    # Generate reports
    device_info = {
        "ip": "192.168.1.1",
        "hostname": "FortiGate-VM",
        "version": "v7.0.0",
    }
    report_generator = ReportGenerator(results, device_info)
    report_generator.generate_cli_report()  # Print to console
    json_report = report_generator.generate_json_report()  # Get JSON string
```

## Security Considerations

- Always use the `--prompt-password` option instead of providing passwords on the command line
- Ensure you have proper authorization before auditing devices
- Consider using a dedicated read-only account for auditing purposes
- Review the JSON output files for sensitive information before sharing 