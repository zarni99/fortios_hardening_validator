"""Report generator module for FortiOS Hardening Validator."""

import json
from datetime import datetime
from typing import Dict, List, Any

from rich.console import Console
from rich.table import Table

from .hardening_checks import CheckResult, CheckStatus


class ReportGenerator:
    """Generates reports from hardening check results."""

    def __init__(self, results: List[CheckResult], device_info: Dict[str, Any]):
        """Initialize the report generator.

        Args:
            results: List of CheckResult objects
            device_info: Dictionary with device information
        """
        self.results = results
        self.device_info = device_info
        self.console = Console()

    def _count_results_by_status(self) -> Dict[str, int]:
        """Count the number of results by status.

        Returns:
            Dict[str, int]: Count of results by status
        """
        counts = {
            CheckStatus.PASS.value: 0,
            CheckStatus.FAIL.value: 0,
            CheckStatus.WARNING.value: 0,
            CheckStatus.INFO.value: 0,
        }

        for result in self.results:
            counts[result.status.value] += 1

        return counts

    def generate_cli_report(self) -> None:
        """Generate a CLI report."""
        # Print the header
        self.console.print()
        self.console.print(f"[bold cyan]FortiOS Hardening Validator Report[/bold cyan]")
        self.console.print(f"[cyan]Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/cyan]")
        self.console.print()

        # Print device information
        self.console.print("[bold]Device Information[/bold]")
        self.console.print(f"IP Address: {self.device_info.get('ip', 'N/A')}")
        self.console.print(f"Hostname: {self.device_info.get('hostname', 'N/A')}")
        self.console.print(f"FortiOS Version: {self.device_info.get('version', 'N/A')}")
        self.console.print()

        # Print summary
        counts = self._count_results_by_status()
        self.console.print("[bold]Summary[/bold]")
        self.console.print(f"Total checks: {len(self.results)}")
        self.console.print(f"[green]PASS: {counts[CheckStatus.PASS.value]}[/green]")
        self.console.print(f"[red]FAIL: {counts[CheckStatus.FAIL.value]}[/red]")
        self.console.print(f"[yellow]WARNING: {counts[CheckStatus.WARNING.value]}[/yellow]")
        self.console.print(f"[blue]INFO: {counts[CheckStatus.INFO.value]}[/blue]")
        self.console.print()

        # Create table for detailed results
        table = Table(title="Hardening Check Results")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="cyan")
        table.add_column("Status", style="cyan")
        table.add_column("Details", style="cyan")
        table.add_column("Recommendation", style="cyan")

        # Add rows to the table
        for result in self.results:
            status_style = {
                CheckStatus.PASS: "green",
                CheckStatus.FAIL: "red",
                CheckStatus.WARNING: "yellow",
                CheckStatus.INFO: "blue",
            }[result.status]

            table.add_row(
                result.id,
                result.name,
                f"[{status_style}]{result.status.value}[/{status_style}]",
                result.details or "",
                result.recommendation or "",
            )

        # Print the table
        self.console.print(table)
        self.console.print()

    def generate_json_report(self) -> str:
        """Generate a JSON report.

        Returns:
            str: JSON report
        """
        counts = self._count_results_by_status()
        
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "device": self.device_info,
            },
            "summary": {
                "total": len(self.results),
                "pass": counts[CheckStatus.PASS.value],
                "fail": counts[CheckStatus.FAIL.value],
                "warning": counts[CheckStatus.WARNING.value],
                "info": counts[CheckStatus.INFO.value],
            },
            "results": [
                {
                    "id": result.id,
                    "name": result.name,
                    "status": result.status.value,
                    "description": result.description,
                    "details": result.details,
                    "recommendation": result.recommendation,
                }
                for result in self.results
            ],
        }
        
        return json.dumps(report, indent=2)

    def generate_report(self, format: str = "cli") -> str:
        """Generate a report in the specified format.

        Args:
            format: Report format ("cli" or "json")

        Returns:
            str: Report as a string for JSON format, empty string for CLI format
        """
        if format.lower() == "json":
            return self.generate_json_report()
        else:
            self.generate_cli_report()
            return "" 