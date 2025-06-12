#!/usr/bin/env python3
"""
Dharma-Tools Central CLI
Full-featured, colorized, logging-enabled command center for recon → NSE → exploit
"""
import argparse
import logging
import subprocess
import sys
import os
from colorama import init as colorama_init, Fore, Style

__version__ = "0.1.0"

# Initialize colorama
colorama_init(autoreset=True)

# Default directories (can be overridden)
DEFAULT_LOOT_DIR = os.path.join(os.getcwd(), "loot")
DEFAULT_PAYLOAD_DIR = os.path.join(os.getcwd(), "payloads")

# Configure logging
logger = logging.getLogger("dharma")


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format=f"%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def run_command(cmd_list):
    logger.debug(f"Running command: {' '.join(cmd_list)}")
    try:
        subprocess.run(cmd_list, check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e}")
        sys.exit(1)


# Subcommand implementations

def cmd_recon(args):
    targets = args.target.split(',')
    services = args.services.split(',')
    print(Fore.CYAN + "[+] Starting recon..." + Style.RESET_ALL)
    for target in targets:
        logger.info(f"Recon on {target} for: {services}")
        for svc in services:
            script = f"recon/{svc}_recon.py"
            if not os.path.isfile(script):
                logger.warning(f"No recon script for service: {svc}")
                continue
            run_command(["python3", script, "--target", target])
    print(Fore.GREEN + "[+] Recon completed." + Style.RESET_ALL)


def cmd_auto_nse(args):
    print(Fore.CYAN + "[+] Running NSE modules..." + Style.RESET_ALL)
    run_command(["python3", "auto-nse.py", "--target", args.target])
    print(Fore.GREEN + "[+] NSE automation completed." + Style.RESET_ALL)


def cmd_auto_exploit(args):
    print(Fore.CYAN + "[+] Launching automated exploits..." + Style.RESET_ALL)
    run_command(["python3", "auto-exploit.py", "--target", args.target])
    print(Fore.GREEN + "[+] Exploitation completed." + Style.RESET_ALL)


def cmd_loot_list(args):
    print(Fore.CYAN + "[+] Available loot files:" + Style.RESET_ALL)
    loot_dir = args.loot_dir or DEFAULT_LOOT_DIR
    if not os.path.isdir(loot_dir):
        logger.error(f"Loot directory not found: {loot_dir}")
        sys.exit(1)
    for fname in sorted(os.listdir(loot_dir)):
        print(f" - {fname}")


def cmd_payload_list(args):
    print(Fore.CYAN + "[+] Available payloads:" + Style.RESET_ALL)
    pdir = args.payload_dir or DEFAULT_PAYLOAD_DIR
    if not os.path.isdir(pdir):
        logger.error(f"Payload directory not found: {pdir}")
        sys.exit(1)
    for fname in sorted(os.listdir(pdir)):
        print(f" - {fname}")


def main():
    parser = argparse.ArgumentParser(
        prog="dharma",
        description="Dharma-Tools Unified CLI",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Recon
    p_recon = subparsers.add_parser(
        "recon", help="Run service-specific recon scripts"
    )
    p_recon.add_argument("--target", required=True, help="Target IP or FQDN (comma-separated)")
    p_recon.add_argument(
        "--services",
        default="ftp,http,smb",
        help="Comma-separated list: ftp,http,smb (default: ftp,http,smb)",
    )
    p_recon.set_defaults(func=cmd_recon)

    # Auto NSE
    p_nse = subparsers.add_parser(
        "auto-nse", help="Automatically run matching NSE scripts"
    )
    p_nse.add_argument("--target", required=True, help="Target IP or FQDN")
    p_nse.set_defaults(func=cmd_auto_nse)

    # Auto Exploit
    p_exploit = subparsers.add_parser(
        "auto-exploit", help="Automatically launch payloads based on recon loot"
    )
    p_exploit.add_argument("--target", required=True, help="Target IP or FQDN")
    p_exploit.set_defaults(func=cmd_auto_exploit)

    # Loot List
    p_loot = subparsers.add_parser("loot", help="List loot files")
    p_loot.add_argument("--loot-dir", help="Custom loot directory")
    p_loot.set_defaults(func=cmd_loot_list)

    # Payload List
    p_payload = subparsers.add_parser("payload", help="List available payloads")
    p_payload.add_argument("--payload-dir", help="Custom payload directory")
    p_payload.set_defaults(func=cmd_payload_list)

    # Parse & run
    args = parser.parse_args()
    setup_logging(args.verbose)
    try:
        args.func(args)
    except AttributeError:
        parser.error("No command specified. Use --help for available commands.")

if __name__ == "__main__":
    main()

