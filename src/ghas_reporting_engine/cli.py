"""
CLI interface for GHAS Reporting Engine.

This module provides the main command-line interface for generating compliance reports
from GitHub Advanced Security findings.
"""

import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .api.github_client import GitHubClient
from .config import Config
from .processors.data_analyzer import DataAnalyzer
from .reports.json_reporter import JSONReporter
from .reports.csv_reporter import CSVReporter
from .reports.html_reporter import HTMLReporter
from .utils.logger import setup_logging


console = Console()


@click.command()
@click.option(
    "--token",
    envvar="GITHUB_TOKEN",
    required=True,
    help="GitHub token for API access (can be set via GITHUB_TOKEN env var)",
)
@click.option(
    "--organization",
    "--org",
    help="GitHub organization name (mutually exclusive with --enterprise)",
)
@click.option(
    "--enterprise",
    "--ent",
    help="GitHub enterprise name (mutually exclusive with --organization)",
)
@click.option(
    "--report-types",
    default="owasp,sans,mitre",
    help="Comma-separated list of report types (owasp,sans,mitre)",
)
@click.option(
    "--report-formats",
    default="json,html",
    help="Comma-separated list of report formats (json,csv,html)",
)
@click.option(
    "--days-back",
    default=30,
    type=int,
    help="Number of days to look back for alerts (default: 30)",
)
@click.option(
    "--output-dir",
    default="./reports",
    type=click.Path(path_type=Path),
    help="Output directory for reports (default: ./reports)",
)
@click.option(
    "--log-level",
    default="INFO",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    help="Logging level (default: INFO)",
)
@click.option(
    "--include-dismissed",
    is_flag=True,
    help="Include dismissed alerts in the report",
)
@click.option(
    "--severity-filter",
    help="Filter alerts by severity (critical,high,medium,low)",
)
@click.version_option()
def cli(
    token: str,
    organization: Optional[str],
    enterprise: Optional[str],
    report_types: str,
    report_formats: str,
    days_back: int,
    output_dir: Path,
    log_level: str,
    include_dismissed: bool,
    severity_filter: Optional[str],
) -> None:
    """Generate compliance reports from GitHub Advanced Security findings."""
    
    # Set up logging
    setup_logging(log_level)
    
    # Validate inputs
    if not organization and not enterprise:
        console.print("[red]Error: Either --organization or --enterprise must be specified[/red]")
        sys.exit(1)
    
    if organization and enterprise:
        console.print("[red]Error: --organization and --enterprise are mutually exclusive[/red]")
        sys.exit(1)
    
    # Parse report types and formats
    requested_types = [t.strip().lower() for t in report_types.split(",")]
    requested_formats = [f.strip().lower() for f in report_formats.split(",")]
    
    # Validate report types
    valid_types = {"owasp", "sans", "mitre"}
    invalid_types = set(requested_types) - valid_types
    if invalid_types:
        console.print(f"[red]Error: Invalid report types: {', '.join(invalid_types)}[/red]")
        console.print(f"Valid types: {', '.join(valid_types)}")
        sys.exit(1)
    
    # Validate report formats
    valid_formats = {"json", "csv", "html"}
    invalid_formats = set(requested_formats) - valid_formats
    if invalid_formats:
        console.print(f"[red]Error: Invalid report formats: {', '.join(invalid_formats)}[/red]")
        console.print(f"Valid formats: {', '.join(valid_formats)}")
        sys.exit(1)
    
    # Parse severity filter
    severity_filters = None
    if severity_filter:
        severity_filters = [s.strip().lower() for s in severity_filter.split(",")]
        valid_severities = {"critical", "high", "medium", "low"}
        invalid_severities = set(severity_filters) - valid_severities
        if invalid_severities:
            console.print(f"[red]Error: Invalid severities: {', '.join(invalid_severities)}[/red]")
            console.print(f"Valid severities: {', '.join(valid_severities)}")
            sys.exit(1)
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Configure the application
    config = Config(
        github_token=token,
        organization=organization,
        enterprise=enterprise,
        report_types=requested_types,
        report_formats=requested_formats,
        days_back=days_back,
        output_dir=output_dir,
        include_dismissed=include_dismissed,
        severity_filters=severity_filters,
    )
    
    # Display configuration
    console.print("[bold blue]GHAS Reporting Engine[/bold blue]")
    console.print("=" * 50)
    
    table = Table(show_header=False, show_edge=False, pad_edge=False)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Target", organization or enterprise)
    table.add_row("Type", "Organization" if organization else "Enterprise")
    table.add_row("Report Types", ", ".join(requested_types))
    table.add_row("Report Formats", ", ".join(requested_formats))
    table.add_row("Days Back", str(days_back))
    table.add_row("Output Directory", str(output_dir))
    table.add_row("Include Dismissed", "Yes" if include_dismissed else "No")
    if severity_filters:
        table.add_row("Severity Filter", ", ".join(severity_filters))
    
    console.print(table)
    console.print()
    
    try:
        # Initialize GitHub client
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            # Step 1: Initialize GitHub client
            task = progress.add_task("Initializing GitHub client...", total=None)
            github_client = GitHubClient(config)
            progress.update(task, description="✓ GitHub client initialized")
            
            # Step 2: Fetch alerts
            progress.update(task, description="Fetching GHAS alerts...")
            alerts = github_client.fetch_alerts()
            progress.update(task, description=f"✓ Fetched {len(alerts)} alerts")
            
            if not alerts:
                console.print("[yellow]Warning: No alerts found for the specified criteria[/yellow]")
                console.print("This could be due to:")
                console.print("• No GHAS alerts in the specified time period")
                console.print("• Insufficient permissions to access alerts")
                console.print("• All alerts were filtered out by severity criteria")
                return
            
            # Step 3: Analyze data
            progress.update(task, description="Analyzing alert data...")
            analyzer = DataAnalyzer(config)
            analysis_results = analyzer.analyze(alerts)
            progress.update(task, description="✓ Data analysis complete")
            
            # Step 4: Generate reports
            progress.update(task, description="Generating reports...")
            
            reports_generated = []
            
            # Generate reports for each requested format
            for fmt in requested_formats:
                if fmt == "json":
                    reporter = JSONReporter(config)
                elif fmt == "csv":
                    reporter = CSVReporter(config)
                elif fmt == "html":
                    reporter = HTMLReporter(config)
                
                report_paths = reporter.generate_reports(analysis_results)
                reports_generated.extend(report_paths)
            
            progress.update(task, description="✓ All reports generated")
        
        # Display results
        console.print()
        console.print("[bold green]Reports generated successfully![/bold green]")
        console.print()
        
        # Summary table
        summary_table = Table(title="Report Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="white")
        
        summary_table.add_row("Total Alerts", str(len(alerts)))
        summary_table.add_row("Reports Generated", str(len(reports_generated)))
        summary_table.add_row("Output Directory", str(output_dir))
        
        console.print(summary_table)
        console.print()
        
        # List generated reports
        console.print("[bold]Generated Reports:[/bold]")
        for report_path in reports_generated:
            console.print(f"  📄 {report_path}")
        
        console.print()
        console.print("[dim]Tip: Use --log-level DEBUG for more detailed output[/dim]")
        
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        if log_level == "DEBUG":
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    cli()