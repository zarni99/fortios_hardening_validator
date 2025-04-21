"""Report generator module for FortiOS Hardening Validator."""

import json
import textwrap
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

        # Separate regular checks from validation checks
        regular_checks = [r for r in self.results if not r.id.startswith("VALIDATE-") and not r.id.startswith("DEBUG-")]
        validation_checks = [r for r in self.results if r.id.startswith("VALIDATE-") or r.id.startswith("DEBUG-")]
        
        # Create detailed table with proper styling for regular checks
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
        table.add_column("Recommendation", width=26)

        # Status styles
        status_styles = {
            CheckStatus.PASS: "bold green",
            CheckStatus.FAIL: "bold red",
            CheckStatus.WARNING: "bold yellow",
            CheckStatus.INFO: "bold blue",
        }

        # Add rows with better styling for regular checks
        for result in regular_checks:
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
        
        # If there are validation checks, show them in a separate table
        if validation_checks:
            validation_table = Table(
                title="Validation Results",
                box=box.ROUNDED,
                border_style="blue",
                header_style="bold white",
                pad_edge=False,
                expand=True
            )
            
            validation_table.add_column("ID", style="dim", width=12)
            validation_table.add_column("Validation", style="white", width=22)
            validation_table.add_column("Result", width=10, justify="center")
            validation_table.add_column("Details", width=68)
            
            for result in validation_checks:
                status_style = status_styles[result.status]
                
                # Format details to preserve line breaks
                details = result.details or ""
                formatted_details = "\n".join(details.split("\n")[:3])
                if len(details.split("\n")) > 3:
                    formatted_details += "\n... (more details omitted)"
                
                validation_table.add_row(
                    Text(result.id, style="cyan"),
                    Text(result.name, style="white"),
                    Text(result.status.value, style=status_style),
                    Text(formatted_details, style="dim white"),
                )
            
            self.console.print(validation_table)
            self.console.print()
            
            # Add explanation about validation
            self.console.print(Panel(
                Text("Validation checks verify the accuracy of the audit results. Any WARNING indicates a potential issue with the parsing or validation.", style="white"),
                title="About Validation",
                title_align="left",
                border_style="blue"
            ))
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
        """Generate a text report.

        Returns:
            str: Text report
        """
        # Separate regular checks from validation checks
        regular_checks = [r for r in self.results if not r.id.startswith("VALIDATE-") and not r.id.startswith("DEBUG-")]
        validation_checks = [r for r in self.results if r.id.startswith("VALIDATE-") or r.id.startswith("DEBUG-")]
        
        counts = self._count_results_by_status()
        line_length = 100
        sep_line = "=" * line_length
        sub_sep = "-" * line_length

        # Header
        report = []
        report.append(sep_line)
        report.append("FortiOS Hardening Validator Report".center(line_length))
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(line_length))
        report.append(sep_line)
        report.append("")

        # Device info
        report.append("DEVICE INFORMATION:")
        report.append(f"IP Address: {self.device_info.get('ip', 'N/A')}")
        report.append(f"Hostname: {self.device_info.get('hostname', 'N/A')}")
        report.append(f"FortiOS Version: {self.device_info.get('version', 'N/A')}")
        report.append("")
        report.append(sub_sep)
        report.append("")

        # Summary
        report.append("SUMMARY:")
        report.append(f"Total checks: {len(regular_checks)}")
        report.append(f"PASS: {len([r for r in regular_checks if r.status == CheckStatus.PASS])}")
        report.append(f"FAIL: {len([r for r in regular_checks if r.status == CheckStatus.FAIL])}")
        report.append(f"WARNING: {len([r for r in regular_checks if r.status == CheckStatus.WARNING])}")
        report.append(f"INFO: {len([r for r in regular_checks if r.status == CheckStatus.INFO])}")
        report.append("")
        report.append(sub_sep)
        report.append("")

        # Detailed results
        report.append("HARDENING CHECK RESULTS:")
        report.append("")
        
        # Format column headers
        id_col_width = 12
        name_col_width = 22
        status_col_width = 10
        details_col_width = 30
        recommendation_col_width = 26  # Reduced from 38 to fit better on one line
        
        # Create header row with fixed widths to prevent wrapping
        header = (
            "ID".ljust(id_col_width) +
            "Name".ljust(name_col_width) +
            "Status".center(status_col_width) +
            "Details".ljust(details_col_width) +
            "Recommendation".ljust(recommendation_col_width)
        )
        report.append(header)
        report.append("-" * len(header))
        
        # Add results rows
        for result in regular_checks:
            # Format each field to fixed width
            id_field = result.id[:id_col_width].ljust(id_col_width)
            
            # Truncate name if too long and add ellipsis
            name = result.name
            if len(name) > name_col_width - 3:
                name = name[:name_col_width-3] + "..."
            name_field = name.ljust(name_col_width)
            
            status_field = result.status.value.center(status_col_width)
            
            # Format details with word wrapping
            details = result.details or ""
            details_lines = textwrap.wrap(details, width=details_col_width)
            details_field = (details_lines[0] if details_lines else "").ljust(details_col_width)
            
            # Format recommendation with word wrapping
            recommendation = result.recommendation or ""
            recommendation_lines = textwrap.wrap(recommendation, width=recommendation_col_width)
            recommendation_field = (recommendation_lines[0] if recommendation_lines else "").ljust(recommendation_col_width)
            
            # First line with all columns
            report.append(id_field + name_field + status_field + details_field + recommendation_field)
            
            # Additional lines for wrapped text
            max_lines = max(
                len(details_lines) if details_lines else 0,
                len(recommendation_lines) if recommendation_lines else 0
            )
            
            for i in range(1, max_lines):
                details_line = details_lines[i].ljust(details_col_width) if i < len(details_lines) else " " * details_col_width
                recommendation_line = recommendation_lines[i].ljust(recommendation_col_width) if i < len(recommendation_lines) else " " * recommendation_col_width
                report.append(" " * (id_col_width + name_col_width + status_col_width) + details_line + recommendation_line)
            
            # Add space between checks
            report.append("")
            
        report.append(sub_sep)
        report.append("")
        
        # Add validation results if present
        if validation_checks:
            report.append("VALIDATION RESULTS:")
            report.append("")
            
            # Format column headers for validation table
            id_col_width = 12
            name_col_width = 22
            status_col_width = 10
            details_col_width = 68
            
            # Create header row with fixed widths
            val_header = (
                "ID".ljust(id_col_width) +
                "Validation".ljust(name_col_width) +
                "Result".center(status_col_width) +
                "Details".ljust(details_col_width)
            )
            report.append(val_header)
            report.append("-" * len(val_header))
            
            # Add validation results rows
            for result in validation_checks:
                # Format each field to fixed width
                id_field = result.id[:id_col_width].ljust(id_col_width)
                
                # Truncate name if too long and add ellipsis
                name = result.name
                if len(name) > name_col_width - 3:
                    name = name[:name_col_width-3] + "..."
                name_field = name.ljust(name_col_width)
                
                status_field = result.status.value.center(status_col_width)
                
                # Format details with word wrapping
                details = result.details or ""
                details_lines = textwrap.wrap(details, width=details_col_width)
                details_field = (details_lines[0] if details_lines else "").ljust(details_col_width)
                
                # First line with all columns
                report.append(id_field + name_field + status_field + details_field)
                
                # Additional lines for wrapped text
                for i in range(1, min(5, len(details_lines))):  # Limit to 5 lines for details
                    report.append(" " * (id_col_width + name_col_width + status_col_width) + details_lines[i].ljust(details_col_width))
                
                # If more lines were truncated, indicate this
                if len(details_lines) > 5:
                    report.append(" " * (id_col_width + name_col_width + status_col_width) + "... (more details omitted)".ljust(details_col_width))
                
                # Add space between checks
                report.append("")
            
            report.append(sub_sep)
            report.append("")
            report.append("About Validation:")
            report.append("Validation checks verify the accuracy of the audit results.")
            report.append("Any WARNING indicates a potential issue with the parsing or validation.")
            report.append("")
            report.append(sub_sep)
            report.append("")

        # End recommendations
        if counts[CheckStatus.FAIL.value] > 0 or counts[CheckStatus.WARNING.value] > 0:
            report.append("Please address the FAIL and WARNING items to improve your FortiGate security posture.")
        else:
            report.append("Congratulations! Your FortiGate device meets all hardening requirements.")

        return "\n".join(report)

    def generate_json_report(self) -> str:
        """Generate a JSON report.

        Returns:
            str: JSON report
        """
        counts = self._count_results_by_status()
        
        # Separate regular checks from validation checks
        regular_checks = [r for r in self.results if not r.id.startswith("VALIDATE-") and not r.id.startswith("DEBUG-")]
        validation_checks = [r for r in self.results if r.id.startswith("VALIDATE-") or r.id.startswith("DEBUG-")]
        
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "device": self.device_info,
            },
            "summary": {
                "total": len(regular_checks),
                "pass": len([r for r in regular_checks if r.status == CheckStatus.PASS]),
                "fail": len([r for r in regular_checks if r.status == CheckStatus.FAIL]),
                "warning": len([r for r in regular_checks if r.status == CheckStatus.WARNING]),
                "info": len([r for r in regular_checks if r.status == CheckStatus.INFO]),
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
                for result in regular_checks
            ],
        }
        
        # Add validation results if present
        if validation_checks:
            report["validation"] = {
                "summary": {
                    "total": len(validation_checks),
                    "pass": len([r for r in validation_checks if r.status == CheckStatus.PASS]),
                    "warning": len([r for r in validation_checks if r.status == CheckStatus.WARNING]),
                    "info": len([r for r in validation_checks if r.status == CheckStatus.INFO]),
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
                    for result in validation_checks
                ]
            }
        
        return json.dumps(report, indent=2)

    def generate_report(self, report_type="cli", output_path=None):
        """Generate a report of the given type.

        Args:
            report_type (str, optional): Report type ('cli', 'text', 'json'). Defaults to "cli".
            output_path (str, optional): Path to save the report to. Defaults to None.

        Returns:
            str: The report content
        """
        if report_type == "cli":
            report = self.generate_cli_report()
        elif report_type == "text":
            report = self.generate_text_report()
        elif report_type == "json":
            report = self.generate_json_report()
        else:
            raise ValueError(f"Unknown report type: {report_type}")

        if output_path:
            with open(output_path, "w") as f:
                f.write(report)

        return report 