"""CLI module for FortiOS Hardening Validator."""

import sys
from typing import Optional, List

import typer
from rich.console import Console
from getpass import getpass

from .ssh_connector import SSHConnector
from .config_fetcher import ConfigFetcher
from .hardening_checks import HardeningChecker
from .report_generator import ReportGenerator

app = typer.Typer(help="Validate FortiOS hardening best practices.")
console = Console()

# List of valid output formats
VALID_FORMATS = ["cli", "json", "txt"]


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

    try:
        # Connect to device
        console.print(f"[bold]Connecting to {ip}...[/bold]")
        connector = SSHConnector(ip, username, password, port, timeout)
        connector.connect()

        # Fetch device information
        console.print("[bold]Fetching device information...[/bold]")
        hostname = connector.execute_command("get system status | grep Hostname").strip()
        if ":" in hostname:
            hostname = hostname.split(":", 1)[1].strip()
        
        version = connector.execute_command("get system status | grep Version").strip()
        if ":" in version:
            version = version.split(":", 1)[1].strip()
        
        device_info = {
            "ip": ip,
            "hostname": hostname,
            "version": version,
        }

        # Fetch and parse configuration
        console.print("[bold]Fetching device configuration...[/bold]")
        config_fetcher = ConfigFetcher(connector)
        config_fetcher.fetch_config()
        config_fetcher.parse_config()

        # Run hardening checks
        console.print("[bold]Running hardening checks...[/bold]")
        checker = HardeningChecker(config_fetcher)
        results = checker.run_all_checks()

        # Generate report
        console.print("[bold]Generating report...[/bold]")
        report_generator = ReportGenerator(results, device_info)
        report = report_generator.generate_report(format)

        # Save report to file if requested
        if output_file:
            console.print(f"[bold]Saving report to {output_file}...[/bold]")
            with open(output_file, "w") as f:
                if format.lower() in ["json", "txt"]:
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
        
        # Print report to console for JSON and TXT formats when not saving to file
        if format.lower() in ["json", "txt"] and not output_file:
            console.print(report)

    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    app() 