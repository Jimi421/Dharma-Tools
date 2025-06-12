#!/usr/bin/env python3
"""
Dharma-Tools Central CLI
Full-featured, Rich-powered, interactive command center for recon → NSE → exploit
"""
import argparse
import subprocess
import sys
import os
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm
import questionary

__version__ = "0.1.0"

# Initialize console
console = Console()

# Default directories
DEFAULT_LOOT_DIR = Path.cwd() / "loot"
DEFAULT_PAYLOAD_DIR = Path.cwd() / "payloads"


def run_recon(args):
    console.print(Panel(f"[bold green]Recon Phase[/bold green]\nTarget: [cyan]{args.target}[/cyan]", title="🔍 Recon", expand=False))
    services = questionary.checkbox(
        "Select services to recon:",
        choices=["ftp", "smb", "http"],
        default=args.services
    ).ask()
    if not services:
        console.print("[red]No services selected, aborting recon.[/red]")
        return

    with Progress(
        SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TimeElapsedColumn(), transient=True
    ) as progress:
        task = progress.add_task("Running recon...", total=len(services))
        for svc in services:
            script = f"utils/recon/{svc}_recon.py"
            description = f"Recon: {svc.upper()}"
            progress.update(task, description=description)
            subprocess.run([sys.executable, script, "--target", args.target, "--loot-dir", str(args.loot_dir)], check=False)
            progress.advance(task)
    console.print("[bold green]✅ Recon completed![/bold green]\n")


def run_auto_nse(args):
    console.print(Panel(f"[bold magenta]Auto-NSE Phase[/bold magenta]\nTarget: [cyan]{args.target}[/cyan]", title="🧪 NSE", expand=False))
    confirm = Confirm.ask("Run NSE scripts based on collected loot?", default=True)
    if not confirm:
        console.print("[yellow]Skipping NSE phase.[/yellow]\n")
        return
    # Example: call auto-nse engine
    subprocess.run([sys.executable, "utils/auto-nse.py", "--target", args.target, "--loot-dir", str(args.loot_dir)], check=False)
    console.print("[bold magenta]✅ NSE phase complete![/bold magenta]\n")


def run_auto_exploit(args):
    console.print(Panel(f"[bold red]Exploit Phase[/bold red]\nTarget: [cyan]{args.target}[/cyan]", title="💥 Exploit", expand=False))
    confirm = Confirm.ask("Proceed with exploit modules? (requires human confirmation)", default=False)
    if not confirm:
        console.print("[yellow]Skipping exploit phase.[/yellow]\n")
        return
    subprocess.run([sys.executable, "utils/auto-exploit.py", "--target", args.target, "--loot-dir", str(args.loot_dir), "--payload-dir", str(args.payload_dir)], check=False)
    console.print("[bold red]✅ Exploit phase complete![/bold red]\n")


def run_loot(args):
    console.print(Panel("[bold blue]Loot Files[/bold blue]", title="📂 Loot", expand=False))
    files = list(Path(args.loot_dir).glob("*.json"))
    table = Table(title="Collected Loot Files")
    table.add_column("Filename", style="cyan")
    table.add_column("Size (bytes)", justify="right")
    for f in files:
        table.add_row(f.name, str(f.stat().st_size))
    console.print(table)


def run_payload(args):
    console.print(Panel("[bold yellow]Payload Directory[/bold yellow]", title="🧰 Payloads", expand=False))
    files = list(Path(args.payload_dir).glob("**/*"))
    table = Table(title="Available Payloads")
    table.add_column("Path", style="magenta")
    for f in files:
        if f.is_file():
            table.add_row(str(f.relative_to(args.payload_dir)))
    console.print(table)


def main():
    parser = argparse.ArgumentParser(
        prog="dharma.py", description="Dharma-Tools Central CLI"
    )
    parser.add_argument("--version", action="version", version=f'%(prog)s {__version__}')
    parser.add_argument("--quiet", action="store_true", help="Suppress console output")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--loot-dir", type=Path, default=DEFAULT_LOOT_DIR, help="Directory for loot JSON files")
    parser.add_argument("--payload-dir", type=Path, default=DEFAULT_PAYLOAD_DIR, help="Directory for payload scripts")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Recon
    recon_parser = subparsers.add_parser("recon", help="Run reconnaissance modules")
    recon_parser.add_argument("--target", required=True, help="Target IP or URL")
    recon_parser.add_argument("--services", nargs="+", choices=["ftp", "smb", "http"], default=["ftp", "smb", "http"], help="Services to recon")
    recon_parser.set_defaults(func=run_recon)

    # Auto-NSE
    nse_parser = subparsers.add_parser("auto-nse", help="Run NSE scripts based on loot")
    nse_parser.add_argument("--target", required=True, help="Target IP or URL")
    nse_parser.set_defaults(func=run_auto_nse)

    # Exploit
    exploit_parser = subparsers.add_parser("auto-exploit", help="Run exploit modules based on loot")
    exploit_parser.add_argument("--target", required=True, help="Target IP or URL")
    exploit_parser.set_defaults(func=run_auto_exploit)

    # Loot listing
    loot_parser = subparsers.add_parser("loot", help="List collected loot files")
    loot_parser.set_defaults(func=run_loot)

    # Payload listing
    payload_parser = subparsers.add_parser("payload", help="List available payloads")
    payload_parser.set_defaults(func=run_payload)

    args = parser.parse_args()

    if args.verbose:
        console.log(f"Arguments: {args}")
    elif args.quiet:
        console = Console(stderr=True, quiet=True)

    # Ensure directories exist
    args.loot_dir.mkdir(parents=True, exist_ok=True)
    args.payload_dir.mkdir(parents=True, exist_ok=True)

    # Dispatch
    try:
        args.func(args)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
