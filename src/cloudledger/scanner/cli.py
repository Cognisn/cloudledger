"""
Command-line interface for CloudLedger.

This module provides the CLI for running AWS scans.
Uses Australian English in all documentation and comments.
"""

import click
import sys
import uuid
from datetime import datetime, UTC
from pathlib import Path
from typing import Optional, List
import logging
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ..database.schema import DatabaseSchema
from ..database.operations import DatabaseOperations
from ..database.models import ScanMetadata
from ..config.context import create_app_context, resolve_database_path
from .credential_manager import CredentialManager, AccountConfig
from .csv_input import CSVAccountReader, CSVInputError
from .aws_collector import AWSCollector
from .prowler_integration import ProwlerRunner

console = Console()
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(package_name="cloudledger", prog_name="cloudledger")
def cli():
    """CloudLedger - Comprehensive AWS security and infrastructure scanning tool."""
    pass


@cli.command()
@click.option(
    "--database",
    default=None,
    type=click.Path(),
    help="Path to SQLite database file (default: configured or platform data location)",
)
@click.option(
    "--csv",
    type=click.Path(exists=True),
    help="Path to CSV file with account credentials (optional)",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default=None,
    help="Logging level (overrides the configured level)",
)
@click.option(
    "--regions",
    type=str,
    help="Comma-separated list of regions to scan (default: all regions)",
)
def scan(database: str, csv: Optional[str], log_level: str, regions: Optional[str]):
    """
    Run AWS infrastructure and security scan.

    This command scans one or more AWS accounts, collecting infrastructure
    information and optionally running Prowler security assessments.

    \b
    Examples:
        # Interactive mode (prompts for credentials)
        cloudledger scan --database /path/to/scanner.db

        # CSV batch mode
        cloudledger scan --database /path/to/scanner.db --csv accounts.csv

        # Specific regions only
        cloudledger scan --database /path/to/scanner.db --regions us-east-1,us-west-2
    """
    with create_app_context(console_output="none", log_level=log_level) as ctx:
        database = str(resolve_database_path(database, ctx.settings))
        _run_scan(database, csv, regions)


def _run_scan(database: str, csv: Optional[str], regions: Optional[str]) -> None:
    console.print("\n[bold blue]CloudLedger[/bold blue]", style="bold")
    console.print("=" * 60)

    # Initialise database
    try:
        db_schema = DatabaseSchema(database)
        db_schema.initialise_database()
        db_ops = DatabaseOperations(database)
        console.print(f"[green]✓[/green] Database initialised: {database}")
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to initialise database: {e}")
        logger.error(f"Database initialisation failed: {e}", exc_info=True)
        sys.exit(1)

    # Parse regions
    region_list = None
    if regions:
        region_list = [r.strip() for r in regions.split(",")]
        console.print(
            f"[green]✓[/green] Scanning specific regions: {', '.join(region_list)}"
        )

    # Get account configurations
    accounts: List[AccountConfig] = []

    if csv:
        # CSV mode
        try:
            reader = CSVAccountReader(csv)
            accounts = reader.read_accounts()
            console.print(f"[green]✓[/green] Loaded {len(accounts)} accounts from CSV")
        except CSVInputError as e:
            console.print(f"[red]✗[/red] CSV error: {e}")
            logger.error(f"CSV parsing failed: {e}")
            sys.exit(1)
    else:
        # Interactive mode
        console.print("\n[yellow]Interactive Mode[/yellow]")
        console.print(
            "You will be prompted to enter AWS credentials for each account.\n"
        )

        while True:
            try:
                account_config = CredentialManager.prompt_for_account_config()
                accounts.append(account_config)

                another = input("\nScan another account? (y/n): ").strip().lower()
                if another != "y":
                    break
            except (ValueError, KeyboardInterrupt) as e:
                if isinstance(e, KeyboardInterrupt):
                    console.print("\n[yellow]Scan cancelled by user[/yellow]")
                    sys.exit(0)
                console.print(f"[red]Error:[/red] {e}")
                continue

    if not accounts:
        console.print("[yellow]No accounts to scan. Exiting.[/yellow]")
        sys.exit(0)

    # Scan each account
    console.print(f"\n[bold]Starting scan of {len(accounts)} account(s)[/bold]\n")

    for idx, account in enumerate(accounts, 1):
        console.print(
            f"\n[bold cyan]Account {idx}/{len(accounts)}: {account.account_name}[/bold cyan]"
        )
        console.print(f"Account Number: {account.account_number}")

        try:
            _scan_account(account, db_ops, region_list)
            console.print(
                f"[green]✓[/green] Scan completed for {account.account_name}\n"
            )
        except Exception as e:
            console.print(f"[red]✗[/red] Scan failed for {account.account_name}: {e}\n")
            logger.error(
                f"Account scan failed for {account.account_name}: {e}", exc_info=True
            )
            continue

    console.print("\n[bold green]All scans completed![/bold green]")


def _scan_account(
    account: AccountConfig, db_ops: DatabaseOperations, regions: Optional[List[str]]
) -> None:
    """
    Scan a single AWS account.

    Args:
        account: Account configuration
        db_ops: Database operations instance
        regions: Optional list of specific regions to scan
    """
    scan_id = str(uuid.uuid4())
    start_time = datetime.now(UTC)

    # Create credential manager and session
    cred_manager = CredentialManager()

    try:
        session = cred_manager.create_session(account.credentials)
    except ValueError as e:
        console.print(f"[red]Invalid credentials:[/red] {e}")
        raise

    # Verify account number matches
    if not cred_manager.verify_account_number(session, account.account_number):
        raise ValueError(
            f"Credentials do not match account number {account.account_number}"
        )

    # Create scan metadata
    metadata = ScanMetadata(
        scan_id=scan_id,
        account_name=account.account_name,
        account_number=account.account_number,
        scan_timestamp=start_time,
        prowler_level=account.prowler_level,
        regions_scanned=regions or [],
        scan_status="in_progress",
    )

    db_ops.insert_scan_metadata(metadata)
    logger.info(f"Started scan {scan_id} for account {account.account_name}")

    try:
        # Collect AWS resources
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Collecting AWS resources...", total=None)

            collector = AWSCollector(session, scan_id, regions)
            resources = collector.collect_all_resources()

            progress.update(
                task, description="[green]✓[/green] Resource collection complete"
            )

        # Save resources to database
        console.print("Saving resources to database...")
        db_ops.insert_ec2_instances(resources["ec2_instances"])
        db_ops.insert_vpcs(resources["vpcs"])
        db_ops.insert_subnets(resources["subnets"])
        db_ops.insert_security_groups(resources["security_groups"])
        db_ops.insert_load_balancers(resources["load_balancers"])
        db_ops.insert_nat_gateways(resources["nat_gateways"])
        db_ops.insert_internet_gateways(resources["internet_gateways"])
        db_ops.insert_route_tables(resources["route_tables"])
        db_ops.insert_auto_scaling_groups(resources["auto_scaling_groups"])
        db_ops.insert_network_interfaces(resources["network_interfaces"])
        db_ops.insert_workspaces(resources["workspaces"])
        db_ops.insert_lambda_functions(resources["lambda_functions"])
        db_ops.insert_vpc_flow_logs(resources["vpc_flow_logs"])
        db_ops.insert_s3_buckets(resources["s3_buckets"])
        db_ops.insert_iam_users(resources["iam_users"])
        db_ops.insert_iam_roles(resources["iam_roles"])
        db_ops.insert_route53_hosted_zones(resources["route53_hosted_zones"])
        db_ops.insert_route53_record_sets(resources["route53_record_sets"])
        db_ops.insert_cost_data(resources["cost_data"])
        db_ops.insert_ebs_volumes(resources["ebs_volumes"])
        db_ops.insert_ebs_snapshots(resources["ebs_snapshots"])
        db_ops.insert_rds_instances(resources["rds_instances"])
        db_ops.insert_iam_policies(resources["iam_policies"])
        db_ops.insert_kms_keys(resources["kms_keys"])
        db_ops.insert_elastic_ips(resources["elastic_ips"])
        # Phase 2: Containers & Application Services
        db_ops.insert_ecs_clusters(resources["ecs_clusters"])
        db_ops.insert_ecs_services(resources["ecs_services"])
        db_ops.insert_ecs_task_definitions(resources["ecs_task_definitions"])
        db_ops.insert_eks_clusters(resources["eks_clusters"])
        db_ops.insert_eks_node_groups(resources["eks_node_groups"])
        db_ops.insert_ecr_repositories(resources["ecr_repositories"])
        db_ops.insert_ecr_images(resources["ecr_images"])
        db_ops.insert_api_gateway_rest_apis(resources["api_gateway_rest_apis"])
        db_ops.insert_api_gateway_http_apis(resources["api_gateway_http_apis"])
        db_ops.insert_api_gateway_stages(resources["api_gateway_stages"])
        db_ops.insert_cloudfront_distributions(resources["cloudfront_distributions"])
        # Phase 3: Governance, Logging & Advanced Services
        db_ops.insert_organizations(resources["organizations"])
        db_ops.insert_organizational_units(resources["organizational_units"])
        db_ops.insert_organization_accounts(resources["organization_accounts"])
        db_ops.insert_sso_permission_sets(resources["sso_permission_sets"])
        db_ops.insert_sso_assignments(resources["sso_assignments"])
        db_ops.insert_cloudtrail_trails(resources["cloudtrail_trails"])
        db_ops.insert_cloudwatch_log_groups(resources["cloudwatch_log_groups"])
        db_ops.insert_config_recorders(resources["config_recorders"])
        db_ops.insert_config_rules(resources["config_rules"])
        db_ops.insert_bedrock_models(resources["bedrock_models"])
        db_ops.insert_bedrock_guardrails(resources["bedrock_guardrails"])
        db_ops.insert_bedrock_knowledge_bases(resources["bedrock_knowledge_bases"])
        db_ops.insert_bedrock_agents(resources["bedrock_agents"])
        db_ops.insert_directory_services(resources["directory_services"])
        db_ops.insert_transit_gateways(resources["transit_gateways"])
        db_ops.insert_vpn_connections(resources["vpn_connections"])
        db_ops.insert_direct_connect_connections(
            resources["direct_connect_connections"]
        )
        db_ops.insert_elasticache_clusters(resources["elasticache_clusters"])
        db_ops.insert_opensearch_domains(resources["opensearch_domains"])
        db_ops.insert_msk_clusters(resources["msk_clusters"])
        db_ops.insert_dynamodb_tables(resources["dynamodb_tables"])
        db_ops.insert_account_security_posture(resources["account_security_posture"])
        db_ops.insert_iam_credential_report(resources["iam_credential_report"])
        db_ops.insert_region_security_services(resources["region_security_services"])
        db_ops.insert_lambda_exposure(resources["lambda_exposure"])
        db_ops.insert_s3_public_access(resources["s3_public_access"])

        # Display summary
        _display_resource_summary(resources)

        # Run Prowler if requested
        if account.prowler_level:
            console.print(
                f"\n[bold]Running Prowler security scan (Level {account.prowler_level})[/bold]"
            )

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("Running security checks...", total=None)

                prowler_runner = ProwlerRunner(session, scan_id)
                findings, stats = prowler_runner.run_scan(account.prowler_level)

                progress.update(
                    task, description="[green]✓[/green] Security scan complete"
                )

            # Save Prowler findings
            db_ops.insert_prowler_findings(findings)

            # Display Prowler summary
            _display_prowler_summary(stats)
        else:
            console.print("\n[yellow]Prowler scan skipped[/yellow]")

        # Update scan status
        end_time = datetime.now(UTC)
        duration = (end_time - start_time).total_seconds()

        db_ops.update_scan_status(scan_id, "completed", duration=duration)
        logger.info(f"Scan {scan_id} completed successfully in {duration:.2f}s")

    except Exception as e:
        # Update scan status to failed
        db_ops.update_scan_status(scan_id, "failed", error_message=str(e))
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        raise


def _display_resource_summary(resources: dict) -> None:
    """Display summary of collected resources."""
    table = Table(title="Resource Collection Summary")
    table.add_column("Resource Type", style="cyan")
    table.add_column("Count", justify="right", style="green")

    resource_names = {
        "ec2_instances": "EC2 Instances",
        "vpcs": "VPCs",
        "subnets": "Subnets",
        "security_groups": "Security Groups",
        "s3_buckets": "S3 Buckets",
        "iam_users": "IAM Users",
        "iam_roles": "IAM Roles",
        "route53_hosted_zones": "Route53 Hosted Zones",
        "route53_record_sets": "Route53 Record Sets",
    }

    for key, name in resource_names.items():
        count = len(resources.get(key, []))
        if count > 0:
            table.add_row(name, str(count))

    console.print(table)


def _display_prowler_summary(stats: dict) -> None:
    """Display Prowler scan summary."""
    table = Table(title="Prowler Security Scan Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right", style="green")

    table.add_row("Total Checks", str(stats.get("total_checks", 0)))
    table.add_row("Passed", f"[green]{stats.get('passed', 0)}[/green]")
    table.add_row("Failed", f"[red]{stats.get('failed', 0)}[/red]")
    table.add_row("Warnings", f"[yellow]{stats.get('warnings', 0)}[/yellow]")

    if stats.get("critical", 0) > 0:
        table.add_row("Critical", f"[bold red]{stats['critical']}[/bold red]")
    if stats.get("high", 0) > 0:
        table.add_row("High", f"[red]{stats['high']}[/red]")
    if stats.get("medium", 0) > 0:
        table.add_row("Medium", f"[yellow]{stats['medium']}[/yellow]")

    console.print(table)


@cli.command()
@click.option(
    "--output",
    type=click.Path(),
    default="example_accounts.csv",
    help="Output path for example CSV file",
)
def create_example_csv(output: str):
    """
    Create an example CSV file with the required format.

    This command generates a template CSV file that can be used as a reference
    for batch scanning multiple accounts.
    """
    from .csv_input import CSVAccountReader

    try:
        CSVAccountReader.create_example_csv(output)
        console.print(f"[green]✓[/green] Example CSV created: {output}")
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to create example CSV: {e}")
        sys.exit(1)


@cli.command()
@click.option(
    "--database",
    required=False,
    default=None,
    type=click.Path(),
    help="Path to SQLite database file (default: configured or platform data location)",
)
@click.option(
    "--scan-id",
    type=str,
    help="Scan ID to delete (optional - will prompt if not provided)",
)
def delete_scan(database: str, scan_id: Optional[str]):
    """
    Delete a scan and all its associated data from the database.

    If --scan-id is not provided, displays a list of scans and prompts for selection.
    This operation cannot be undone, so use with caution.
    """
    with create_app_context(console_output="none") as ctx:
        database = str(resolve_database_path(database, ctx.settings))
        if not Path(database).exists():
            console.print(f"[red]✗[/red] Database not found: {database}")
            sys.exit(1)

        # Initialise database
        db_schema = DatabaseSchema(database)
        db_schema.initialise_database()
        db_ops = DatabaseOperations(database)

        # Get all scans
        scans = db_ops.get_all_scans()

        if not scans:
            console.print("[yellow]No scans found in database.[/yellow]")
            return

        # If scan_id not provided, display list and prompt for selection
        if not scan_id:
            console.print("\n[bold]Available Scans:[/bold]\n")

            # Create table of scans
            table = Table(title="Scans in Database")
            table.add_column("#", style="cyan", justify="right")
            table.add_column("Scan ID", style="yellow")
            table.add_column("Account Name", style="green")
            table.add_column("Account Number", style="blue")
            table.add_column("Timestamp", style="magenta")
            table.add_column("Status", style="white")

            for idx, scan in enumerate(scans, 1):
                table.add_row(
                    str(idx),
                    scan["scan_id"][:8] + "...",  # Show abbreviated scan ID
                    scan.get("account_name", "N/A"),
                    scan.get("account_number", "N/A"),
                    scan.get("scan_timestamp", "N/A"),
                    scan.get("status", "N/A"),
                )

            console.print(table)

            # Prompt for selection
            console.print(
                "\n[bold]Enter the number of the scan to delete, or 'q' to quit:[/bold]"
            )
            selection = input("Selection: ").strip()

            if selection.lower() == "q":
                console.print("[yellow]Cancelled.[/yellow]")
                return

            try:
                selection_idx = int(selection) - 1
                if selection_idx < 0 or selection_idx >= len(scans):
                    console.print(
                        f"[red]✗[/red] Invalid selection. Must be between 1 and {len(scans)}"
                    )
                    sys.exit(1)

                scan_id = scans[selection_idx]["scan_id"]
            except ValueError:
                console.print(
                    "[red]✗[/red] Invalid input. Please enter a number or 'q'."
                )
                sys.exit(1)

        # Verify the scan exists and get details
        scan_details = None
        for scan in scans:
            if scan["scan_id"] == scan_id:
                scan_details = scan
                break

        if not scan_details:
            console.print(f"[red]✗[/red] Scan ID '{scan_id}' not found in database.")
            sys.exit(1)

        # Display scan details and confirm deletion
        console.print(
            "\n[bold red]WARNING: This will permanently delete the following scan:[/bold red]\n"
        )

        info_table = Table(show_header=False, box=None)
        info_table.add_column("Field", style="cyan")
        info_table.add_column("Value", style="white")

        info_table.add_row("Scan ID", scan_details["scan_id"])
        info_table.add_row("Account Name", scan_details.get("account_name", "N/A"))
        info_table.add_row("Account Number", scan_details.get("account_number", "N/A"))
        info_table.add_row("Scan Timestamp", scan_details.get("scan_timestamp", "N/A"))
        info_table.add_row("Status", scan_details.get("status", "N/A"))

        console.print(info_table)

        console.print("\n[yellow]This will delete:[/yellow]")
        console.print("  • Scan metadata")
        console.print("  • All resources collected during this scan")
        console.print("  • Prowler security findings")
        console.print("  • Cost data")
        console.print("  • All other associated data")

        console.print("\n[bold red]This operation cannot be undone![/bold red]")

        # Confirm deletion
        confirmation = input("\nType 'DELETE' to confirm: ").strip()

        if confirmation != "DELETE":
            console.print("[yellow]Deletion cancelled.[/yellow]")
            return

        # Perform deletion
        try:
            console.print(f"\n[bold]Deleting scan {scan_id}...[/bold]")

            deleted_counts = db_ops.delete_scan(scan_id)

            # Display deletion summary
            console.print("\n[green]✓[/green] Scan deleted successfully!\n")

            summary_table = Table(title="Deletion Summary")
            summary_table.add_column("Table", style="cyan")
            summary_table.add_column("Records Deleted", justify="right", style="green")

            total_deleted = 0
            for table, count in sorted(deleted_counts.items()):
                summary_table.add_row(table, str(count))
                total_deleted += count

            console.print(summary_table)
            console.print(f"\n[bold]Total records deleted:[/bold] {total_deleted}")

        except ValueError as e:
            console.print(f"[red]✗[/red] Error: {e}")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to delete scan: {e}")
            logger.error(f"Failed to delete scan {scan_id}: {e}", exc_info=True)
            sys.exit(1)


if __name__ == "__main__":
    cli()
