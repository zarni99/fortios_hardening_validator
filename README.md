# FortiOS Hardening Validator

A comprehensive security audit tool for FortiGate devices - created by Zarni (Neo).

This tool connects to a FortiGate device via SSH and performs security configuration checks based on industry best practices and hardening guidelines. It identifies security misconfigurations, weak settings, and potential vulnerabilities in the FortiGate configuration.

## Features

- Securely connects to FortiGate devices using SSH
- Fetches full configuration and parses it intelligently
- Validates configuration against security best practices
- Detects multiple admin users and analyzes their security settings
- Generates detailed reports in CLI or JSON format
- Validates results to ensure detection accuracy
- Configurable connection options and report formats

## Security Checks

| ID | Name | Description | Severity |
|---|---|---|---|
| F-PW-01 | Password Policy | Ensures password policy is enabled | FAIL |
| F-PROT-01 | Insecure Protocols | Checks if HTTP and Telnet are disabled on all interfaces | FAIL |
| F-CERT-01 | Admin Server Certificate | Validates HTTPS admin access uses proper certificates | WARNING |
| F-ADMIN-01 | Trusted Hosts | Verifies trusted hosts are configured for admin users | FAIL |
| F-ADMIN-02 | Two-Factor Authentication | Checks if 2FA is enabled for admin accounts | FAIL |
| F-CIPH-01 | Strong Ciphers | Validates only strong ciphers are in use (no RC4, MD5) | FAIL |
| F-LOG-01 | Logging | Confirms logging is enabled to FortiAnalyzer or syslog | FAIL |
| F-VPN-01 | SSL VPN Certificate | Checks if SSL VPN uses a valid certificate | WARNING |
| F-SESS-01 | Session Timeout | Verifies session timeout is configured and reasonably low | FAIL/WARNING |

## Installation

### Install dependencies

```bash
# Clone the repository
git clone https://github.com/zarni99/fortios_hardening_validator.git
cd fortios_hardening_validator

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Example

```bash
# Basic usage with interactive password prompt (recommended)
python fortios-audit.py audit --ip 192.168.1.1 --username admin --prompt-password
```

### Comprehensive Examples

```bash
# Basic audit with interactive password prompt:
python fortios-audit.py audit --ip 192.168.1.1 --username admin --prompt-password

# Full audit with validation and debug information:
python fortios-audit.py audit --ip 192.168.1.1 --username admin --password mypassword --validate --show-debug

# Save audit results to a file:
python fortios-audit.py audit --ip 192.168.1.1 --username admin --password mypassword --output-file report.txt

# Generate JSON output:
python fortios-audit.py audit --ip 192.168.1.1 --username admin --password mypassword --format json
```

### Get Help and Version Information

```bash
# Show comprehensive help information
python fortios-audit.py --help

# Show detailed help for the audit command
python fortios-audit.py audit --help

# Show tool version information
python fortios-audit.py --version
```

Note: For security reasons, using `--prompt-password` instead of providing the password directly in the command line is recommended.

## Understanding the Output

The audit report includes several sections:

1. **Device Information**: Basic details about the audited device, including IP, hostname, and FortiOS version.
   
2. **Summary**: Count of issues by severity:
   - PASS: The check was successful
   - FAIL: A critical security issue was found
   - WARNING: A potential security concern was identified
   - INFO: Informational messages about the configuration

3. **Hardening Check Results**: Detailed findings for each security check, including:
   - ID: Unique identifier for the check
   - Name: Short name describing the check
   - Status: PASS, FAIL, WARNING, or INFO
   - Details: Information about what was found
   - Recommendation: Suggested steps to fix the issue

4. **Validation Results** (if `--validate` is used): Additional checks to verify the accuracy of the audit process.

## Validation Levels

The tool supports different validation levels to verify audit accuracy:

- **basic** (default): Performs minimal validation checks
- **thorough**: Performs more detailed validation with more comprehensive checks
- **paranoid**: Performs extensive validation with higher sensitivity (may produce false positives)

## Output Formats

1. **CLI** (default): Rich formatted output with colors and styling for terminal viewing
2. **JSON**: Structured data format for programmatic processing or integration with other tools

## Testing

![image](https://github.com/user-attachments/assets/0a1d2044-7b87-4a27-a693-d993ee64219d)

## Project Structure

```
fortios_hardening_validator/
├── fortios_hardening_validator/  # Main package
│   ├── __init__.py
│   ├── cli.py                   # CLI entrypoint
│   ├── ssh_connector.py         # SSH connection handling
│   ├── config_fetcher.py        # Configuration retrieval
│   ├── hardening_checks.py      # Security validation logic
│   ├── validator.py             # Result validation logic
│   └── report_generator.py      # Report formatting
├── fortios-audit.py             # Direct Python script entry point
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
connector = SSHConnector("192.168.1.1", "admin", "password")
connector.connect()

try:
    # Fetch and parse configuration
    config_fetcher = ConfigFetcher(connector)
    config_fetcher.fetch_config()
    config_fetcher.parse_config()
    
    # Run hardening checks
    checker = HardeningChecker(config_fetcher, show_debug=False)
    results = checker.run_all_checks()
    
    # Generate reports
    device_info = {
        "ip": "192.168.1.1",
        "hostname": "FortiGate-VM",
        "version": "v7.0.0",
    }
    report_generator = ReportGenerator(results, device_info)
    
    # Generate different report formats
    report_generator.generate_cli_report()  # Print to console
    json_report = report_generator.generate_json_report()  # Get JSON string
finally:
    # Ensure connection is closed
    connector.disconnect()
```

## Security Considerations

- Always use the `--prompt-password` option instead of providing passwords on the command line
- Ensure you have proper authorization before auditing devices
- Consider using a dedicated read-only account for auditing purposes
- Review the JSON output files for sensitive information before sharing
- Log connections appropriately according to your security policies

## About the Creator

FortiOS Hardening Validator was created by Zarni (Neo) to help security professionals validate FortiGate configurations against industry best practices.
