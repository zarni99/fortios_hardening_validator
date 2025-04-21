"""CLI module for FortiOS Hardening Validator."""

import sys
import re
from typing import Optional, Dict, Any

import typer
from rich.console import Console
from getpass import getpass

from .ssh_connector import SSHConnector
from .config_fetcher import ConfigFetcher
from .hardening_checks import HardeningChecker
from .report_generator import ReportGenerator
from .validator import ResultValidator

app = typer.Typer(help="Validate FortiOS hardening best practices.")
console = Console()

# List of valid output formats
VALID_FORMATS = ["cli", "json"]
# Validation levels
VALID_VALIDATION_LEVELS = ["basic", "thorough", "paranoid"]


@app.command("audit")
def audit(
    ip: str = typer.Option(..., help="IP address of the FortiGate device"),
    username: str = typer.Option(..., help="SSH username"),
    password: Optional[str] = typer.Option(None, help="SSH password (not recommended, use --prompt-password instead)"),
    port: int = typer.Option(22, help="SSH port"),
    timeout: int = typer.Option(60, help="Connection timeout in seconds"),
    format: str = typer.Option("cli", help=f"Output format ({', '.join(VALID_FORMATS)})"),
    prompt_password: bool = typer.Option(False, help="Prompt for password"),
    output_file: Optional[str] = typer.Option(None, help="Save report to a file"),
    validate: bool = typer.Option(False, help="Validate check results for accuracy"),
    validation_level: str = typer.Option("basic", help=f"Validation level ({', '.join(VALID_VALIDATION_LEVELS)})"),
    show_debug: bool = typer.Option(False, help="Show debug information in check results"),
):
    """Audit a FortiGate device against hardening best practices."""
    if prompt_password:
        password = getpass("Enter SSH password: ")
    
    if not password:
        console.print("[bold red]Error: Password is required.[/bold red]")
        sys.exit(1)
        
    # Validate format
    if format.lower() not in VALID_FORMATS:
        console.print(f"[bold red]Error: Invalid format. Valid formats are: {', '.join(VALID_FORMATS)}[/bold red]")
        sys.exit(1)
    
    # Validate validation level
    if validation_level.lower() not in VALID_VALIDATION_LEVELS:
        console.print(f"[bold red]Error: Invalid validation level. Valid levels are: {', '.join(VALID_VALIDATION_LEVELS)}[/bold red]")
        sys.exit(1)

    try:
        # Connect to device
        console.print(f"[bold]Connecting to {ip}...[/bold]")
        connector = SSHConnector(ip, username, password, port, timeout)
        connector.connect()

        # Fetch device information
        console.print("[bold]Fetching device information...[/bold]")
        
        # Get system status information
        system_status = connector.execute_command("get system status")
        
        # Parse hostname
        hostname = ""
        hostname_match = re.search(r"Hostname:\s+(.+)", system_status)
        if hostname_match:
            hostname = hostname_match.group(1).strip()
        
        # Parse version
        version = ""
        version_match = re.search(r"Version:\s+(.+)", system_status)
        if version_match:
            version = version_match.group(1).strip()
            
        # Parse version info (like GA, Beta, etc.)
        version_info = ""
        version_info_match = re.search(r"Release Version Information:\s+(.+)", system_status)
        if version_info_match:
            version_info = version_info_match.group(1).strip()
        
        device_info: Dict[str, Any] = {
            "ip": ip,
            "hostname": hostname,
            "version": version,
            "version_info": version_info
        }

        # Fetch and parse configuration
        console.print("[bold]Fetching device configuration...[/bold]")
        config_fetcher = ConfigFetcher(connector)
        config_fetcher.fetch_config()
        config_fetcher.parse_config()

        # Run hardening checks
        console.print("[bold]Running hardening checks...[/bold]")
        checker = HardeningChecker(config_fetcher, show_debug=show_debug)
        results = checker.run_all_checks()
        
        # Run result validation if requested
        if validate:
            console.print(f"[bold]Validating results with {validation_level} level...[/bold]")
            validator = ResultValidator(config_fetcher, checker)
            validation_results = validator.validate_all(level=validation_level)
            
            # Add validation results to main results
            results.extend(validation_results)
            
            # Show warning if any validation issues found
            validation_warnings = [r for r in validation_results if r.status == CheckStatus.WARNING]
            if validation_warnings:
                console.print(f"[bold yellow]⚠️ Found {len(validation_warnings)} validation warnings![/bold yellow]")

        # Generate report
        console.print("[bold]Generating report...[/bold]")
        report_generator = ReportGenerator(results, device_info)
        report = report_generator.generate_report(format)

        # Save report to file if requested
        if output_file:
            console.print(f"[bold]Saving report to {output_file}...[/bold]")
            with open(output_file, "w") as f:
                if format.lower() == "json":
                    f.write(report)
                else:
                    # Capture console output for CLI format
                    from rich.console import Console
                    from io import StringIO
                    
                    str_io = StringIO()
                    file_console = Console(file=str_io)
                    
                    # Create a new report generator with the file console
                    file_report_generator = ReportGenerator(results, device_info)
                    file_report_generator.console = file_console
                    file_report_generator.generate_cli_report()
                    
                    f.write(str_io.getvalue())
        
        # Disconnect
        connector.disconnect()
        
        # Print report to console for JSON format when not saving to file
        if format.lower() == "json" and not output_file:
            console.print(report)

    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    app() 