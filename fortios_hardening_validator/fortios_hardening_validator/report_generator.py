"""Report generator module for FortiOS Hardening Validator."""

import json
import io
from datetime import datetime
from typing import Dict, List, Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

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
        header_text = Text("FortiOS Hardening Validator Report", style="bold white on blue")
        timestamp = Text(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style="cyan")
        header_panel = Panel(
            Text.assemble(header_text, "\n", timestamp),
            border_style="blue",
            expand=False,
            padding=(1, 2)
        )
        self.console.print(header_panel)
        self.console.print()

        # Print device information in a panel
        device_info_content = [
            Text("DEVICE INFORMATION", style="bold white"),
            Text.assemble(Text("IP Address: ", style="cyan"), Text(self.device_info.get("ip", "N/A"), style="white")),
            Text.assemble(Text("Hostname: ", style="cyan"), Text(self.device_info.get("hostname", "N/A"), style="white")),
            Text.assemble(Text("FortiOS Version: ", style="cyan"), Text(self.device_info.get("version", "N/A"), style="white")),
        ]
        device_panel = Panel(
            "\n".join(str(line) for line in device_info_content),
            border_style="cyan",
            expand=False,
            padding=(1, 2)
        )
        self.console.print(device_panel)
        self.console.print()

        # Print summary
        counts = self._count_results_by_status()
        summary_text = [
            Text("SUMMARY", style="bold white"),
            Text.assemble(Text("Total checks: ", style="white"), Text(str(len(self.results)), style="bold white")),
            Text.assemble(Text("PASS: ", style="white"), Text(str(counts[CheckStatus.PASS.value]), style="bold green")),
            Text.assemble(Text("FAIL: ", style="white"), Text(str(counts[CheckStatus.FAIL.value]), style="bold red")),
            Text.assemble(Text("WARNING: ", style="white"), Text(str(counts[CheckStatus.WARNING.value]), style="bold yellow")),
            Text.assemble(Text("INFO: ", style="white"), Text(str(counts[CheckStatus.INFO.value]), style="bold blue")),
        ]
        summary_panel = Panel(
            "\n".join(str(line) for line in summary_text),
            border_style="white",
            expand=False,
            padding=(1, 2)
        )
        self.console.print(summary_panel)
        self.console.print()

        # Create detailed table with proper styling
        table = Table(
            title="Hardening Check Results",
            box=box.ROUNDED,
            border_style="white",
            header_style="bold white",
            pad_edge=False,
            expand=True
        )
        
        table.add_column("ID", style="dim", width=12)
        table.add_column("Name", style="white", width=22)
        table.add_column("Status", width=10, justify="center")
        table.add_column("Details", width=30)
        table.add_column("Recommendation", width=38)

        # Status styles
        status_styles = {
            CheckStatus.PASS: "bold green",
            CheckStatus.FAIL: "bold red",
            CheckStatus.WARNING: "bold yellow",
            CheckStatus.INFO: "bold blue",
        }

        # Add rows with better styling
        for result in self.results:
            status_style = status_styles[result.status]
            
            # Add row with colored status and better formatting
            table.add_row(
                Text(result.id, style="cyan"),
                Text(result.name, style="white"),
                Text(result.status.value, style=status_style),
                Text(result.details or "", style="dim white"),
                Text(result.recommendation or "", style="dim white"),
            )

        # Print the table
        self.console.print(table)
        self.console.print()
        
        # Print footer with improvement suggestions
        if counts[CheckStatus.FAIL.value] > 0 or counts[CheckStatus.WARNING.value] > 0:
            recommendations_panel = Panel(
                Text("Please address the FAIL and WARNING items to improve your FortiGate security posture.", style="bold white"),
                border_style="yellow",
                expand=False,
                padding=(1, 2)
            )
            self.console.print(recommendations_panel)
        else:
            success_panel = Panel(
                Text("Congratulations! Your FortiGate device meets all hardening requirements.", style="bold white"),
                border_style="green",
                expand=False,
                padding=(1, 2)
            )
            self.console.print(success_panel)
            
        self.console.print()

    def generate_text_report(self) -> str:
        """Generate a plain text report.

        Returns:
            str: Plain text report suitable for .txt files
        """
        output = []
        counts = self._count_results_by_status()
        
        # Header
        output.append("=" * 80)
        output.append("                     FORTIOS HARDENING VALIDATOR REPORT")
        output.append("=" * 80)
        output.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output.append("")
        
        # Device information
        output.append("-" * 80)
        output.append("DEVICE INFORMATION")
        output.append("-" * 80)
        output.append(f"IP Address:      {self.device_info.get('ip', 'N/A')}")
        output.append(f"Hostname:        {self.device_info.get('hostname', 'N/A')}")
        output.append(f"FortiOS Version: {self.device_info.get('version', 'N/A')}")
        output.append("")
        
        # Summary
        output.append("-" * 80)
        output.append("SUMMARY")
        output.append("-" * 80)
        output.append(f"Total checks: {len(self.results)}")
        output.append(f"PASS:         {counts[CheckStatus.PASS.value]}")
        output.append(f"FAIL:         {counts[CheckStatus.FAIL.value]}")
        output.append(f"WARNING:      {counts[CheckStatus.WARNING.value]}")
        output.append(f"INFO:         {counts[CheckStatus.INFO.value]}")
        output.append("")
        
        # Detailed results
        output.append("-" * 80)
        output.append("HARDENING CHECK RESULTS")
        output.append("-" * 80)
        
        # Table headers with fixed width formatting
        output.append(f"{'ID':<12} {'Name':<25} {'Status':<10} {'Details':<35} {'Recommendation':<35}")
        output.append("-" * 120)
        
        # Table rows
        for result in self.results:
            # Format each column with appropriate width and wrapping
            id_col = f"{result.id:<12}"
            name_col = f"{result.name:<25}"
            status_col = f"{result.status.value:<10}"
            
            # Handle potential wrapping for long text
            details = result.details or ""
            recommendation = result.recommendation or ""
            
            # Add the row
            output.append(f"{id_col} {name_col} {status_col} {details:<35} {recommendation:<35}")
        
        output.append("")
        output.append("-" * 80)
        
        # Conclusion
        if counts[CheckStatus.FAIL.value] > 0 or counts[CheckStatus.WARNING.value] > 0:
            output.append("RECOMMENDATION: Please address the FAIL and WARNING items to improve your FortiGate security posture.")
        else:
            output.append("CONCLUSION: Congratulations! Your FortiGate device meets all hardening requirements.")
        
        output.append("-" * 80)
        output.append("")
        
        return "\n".join(output)

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
            format: Report format ("cli", "json", or "txt")

        Returns:
            str: Report as a string for JSON or TXT format, empty string for CLI format
        """
        format = format.lower()
        if format == "json":
            return self.generate_json_report()
        elif format == "txt":
            return self.generate_text_report()
        else:
            self.generate_cli_report()
            return "" 