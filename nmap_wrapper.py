#!/usr/bin/env python3
"""
nmap_wrapper.py -- NmapTUI v1.0
An interactive terminal UI wrapper for Nmap.

Author : Stan V
License: MIT
GitHub : https://github.com/stanv21/nmap-tui
"""

# -----------------------------------------------------------------------------
# Standard-library imports
# -----------------------------------------------------------------------------
import os
import re
import sys
import shutil
import subprocess
import datetime
from pathlib import Path

# -----------------------------------------------------------------------------
# Third-party imports  (InquirerPy + rich for pretty output)
# -----------------------------------------------------------------------------
try:
    from InquirerPy import inquirer
    from InquirerPy.base.control import Choice
    from InquirerPy.separator import Separator
except ImportError:
    print("[ERROR] InquirerPy is not installed.")
    print("        Run:  pip install InquirerPy")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
except ImportError:
    print("[ERROR] rich is not installed.")
    print("        Run:  pip install rich")
    sys.exit(1)


# -----------------------------------------------------------------------------
# Global console (rich) -- single instance used throughout the app
# -----------------------------------------------------------------------------
console = Console()


# =============================================================================
# SECTION 1 -- Startup checks
# =============================================================================

def check_nmap_installed() -> None:
    """
    Verify that `nmap` is present on the system PATH.
    If it is not found, print a helpful error and exit immediately so the
    user never reaches a scan selection they cannot actually run.
    """
    if shutil.which("nmap") is None:
        console.print(
            Panel(
                "[bold red]nmap is not installed or not found in PATH.[/]\n\n"
                "Install it with:\n"
                "  [bold cyan]sudo apt update && sudo apt install nmap[/]",
                title="[red]Dependency Missing[/]",
                border_style="red",
            )
        )
        sys.exit(1)


def check_root_privileges() -> bool:
    """
    Return True if the script is being run as root (UID 0), False otherwise.
    On non-POSIX systems (Windows) this always returns False.
    """
    try:
        return os.getuid() == 0
    except AttributeError:
        return False


# =============================================================================
# SECTION 2 -- Scan profile catalogue
# =============================================================================

# Each profile is a dict with:
#   name          -- human-readable label shown in the menu
#   flags         -- list of nmap flag strings
#   requires_root -- whether the scan needs elevated privileges
#   description   -- one-line educational explanation shown before the scan
#
# Keeping profiles as plain data (not hard-coded inside a function) makes
# it trivial to add new profiles in future versions.

SCAN_PROFILES: list[dict] = [
    {
        "name": "Quick Scan",
        "flags": ["-T4", "-F"],
        "requires_root": False,
        "description": (
            "Scans the 100 most common ports at high speed (Timing template T4, "
            "Fast mode -F). Good for a rapid first look."
        ),
    },
    {
        "name": "Standard SYN Scan  [root required]",
        "flags": ["-sS", "-v"],
        "requires_root": True,
        "description": (
            "TCP SYN (half-open) scan. Never completes the three-way handshake, "
            "so it is stealthier than a full-connect scan. Requires root."
        ),
    },
    {
        "name": "Full Port Scan  (all 65535 ports)",
        "flags": ["-p-", "-v"],
        "requires_root": False,
        "description": (
            "Scans every TCP port (1-65535). Thorough but slow -- use on a single "
            "host rather than a subnet."
        ),
    },
    {
        "name": "Aggressive / All-in-one  [root required]",
        "flags": ["-A", "-T4"],
        "requires_root": True,
        "description": (
            "Enables OS detection (-O), version detection (-sV), script scanning "
            "(-sC), and traceroute. Very noisy -- do NOT use against systems you "
            "do not own."
        ),
    },
    {
        "name": "Service and Version Detection",
        "flags": ["-sV", "-v"],
        "requires_root": False,
        "description": (
            "Probes open ports to determine service name and version number. "
            "Useful for inventorying what software is exposed."
        ),
    },
    {
        "name": "OS Detection  [root required]",
        "flags": ["-O", "-v"],
        "requires_root": True,
        "description": (
            "Attempts to determine the target's operating system via TCP/IP "
            "fingerprinting. Requires at least one open and one closed port."
        ),
    },
    {
        "name": "Vulnerability Scan  (NSE vuln scripts)",
        "flags": ["-sV", "--script", "vuln"],
        "requires_root": False,
        "description": (
            "Combines service detection with the 'vuln' NSE script category to "
            "check for common, publicly-known vulnerabilities."
        ),
    },
    {
        "name": "Ping Sweep  (host discovery only)",
        "flags": ["-sn"],
        "requires_root": False,
        "description": (
            "Discovers live hosts in a range without port-scanning them. "
            "Fast and low-noise. Ideal for mapping a subnet first."
        ),
    },
    {
        "name": "UDP Scan  [root required]",
        "flags": ["-sU", "-v"],
        "requires_root": True,
        "description": (
            "Scans UDP ports. Much slower than TCP scans because UDP gives no "
            "guaranteed response. Requires root."
        ),
    },
    {
        "name": "Stealth + Version + Scripts  [root required]",
        "flags": ["-sS", "-sV", "-sC", "-v"],
        "requires_root": True,
        "description": (
            "Combines a SYN scan with version detection and default NSE scripts "
            "for a well-rounded, relatively stealthy reconnaissance scan."
        ),
    },
]


# =============================================================================
# SECTION 3 -- Input validation helpers
# =============================================================================

_IPV4_RE   = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_CIDR_RE   = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
_RANGE_RE  = re.compile(r"^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$")
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def is_valid_target(target: str) -> bool:
    """
    Return True if target looks like a valid nmap target:
      - IPv4 address       (e.g. 192.168.1.1)
      - CIDR subnet        (e.g. 192.168.1.0/24)
      - Hyphen range       (e.g. 192.168.1.1-50)
      - Hostname / domain  (e.g. scanme.nmap.org)
    Shell meta-characters are rejected as a belt-and-braces safety measure.
    subprocess with a list already prevents shell injection, but being
    explicit here is good defensive practice.
    """
    target = target.strip()
    if not target:
        return False

    forbidden = set(';|&`$(){}\\\'\"<>')
    if any(ch in forbidden for ch in target):
        return False

    return bool(
        _IPV4_RE.match(target)
        or _CIDR_RE.match(target)
        or _RANGE_RE.match(target)
        or _DOMAIN_RE.match(target)
    )


# =============================================================================
# SECTION 4 -- UI helpers
# =============================================================================

def print_banner() -> None:
    """Print the application welcome banner."""
    banner_text = Text()
    banner_text.append("  _   _ __  __    _    ____    _____ _   _ ___ \n", style="bold cyan")
    banner_text.append(" | \\ | |  \\/  |  / \\  |  _ \\  |_   _| | | |_ _|\n", style="bold cyan")
    banner_text.append(" |  \\| | |\\/| | / _ \\ | |_) |   | | | | | || | \n", style="bold cyan")
    banner_text.append(" | |\\  | |  | |/ ___ \\|  __/    | | | |_| || | \n", style="bold cyan")
    banner_text.append(" |_| \\_|_|  |_/_/   \\_\\_|       |_|  \\___/|___|\n", style="bold cyan")
    banner_text.append("\n  Interactive Nmap Wrapper  v1.0  MIT License\n", style="dim")
    console.print(Panel(banner_text, border_style="cyan", box=box.DOUBLE_EDGE))


def print_info(message: str) -> None:
    console.print(f"[bold cyan][INFO][/] {message}")

def print_warning(message: str) -> None:
    console.print(f"[bold yellow][WARN][/] {message}")

def print_error(message: str) -> None:
    console.print(f"[bold red][ERR ][/] {message}")

def print_success(message: str) -> None:
    console.print(f"[bold green][OK  ][/] {message}")


def print_command(command: list[str]) -> None:
    """
    Display the exact nmap command about to run.
    This is the educational core of the app -- users learn real flags.
    """
    cmd_str = " ".join(command)
    console.print(
        Panel(
            f"[bold white]{cmd_str}[/]",
            title="[bold yellow]Running Command[/]",
            border_style="yellow",
            subtitle="[dim]Copy this into your terminal to run it manually[/]",
        )
    )


# =============================================================================
# SECTION 5 -- Target selection
# =============================================================================

def prompt_for_target() -> str:
    """
    Interactively ask the user for a scan target and loop until a valid
    value is entered. Returns the validated target string.
    """
    console.print()
    console.rule("[bold cyan]Step 1 -- Enter Target[/]")
    console.print(
        "  Accepted formats: [cyan]192.168.1.1[/]  |  [cyan]192.168.1.0/24[/]  "
        "|  [cyan]192.168.1.1-50[/]  |  [cyan]scanme.nmap.org[/]\n"
    )

    while True:
        target = inquirer.text(
            message="Target (IP / subnet / hostname):",
            validate=lambda t: is_valid_target(t),
            invalid_message="Invalid target. Enter an IP, CIDR range, or hostname.",
        ).execute()

        target = target.strip()
        if is_valid_target(target):
            return target


# =============================================================================
# SECTION 6 -- Scan profile selection menu
# =============================================================================

def build_scan_choices(is_root: bool) -> list:
    """
    Build the InquirerPy choice list from SCAN_PROFILES.
    Root-only profiles are hidden when running as a non-root user.
    """
    choices = []
    for idx, profile in enumerate(SCAN_PROFILES):
        if profile["requires_root"] and not is_root:
            continue
        choices.append(Choice(value=idx, name=profile["name"]))

    choices.append(Separator())
    choices.append(Choice(value="exit", name="Exit"))
    return choices


def prompt_for_scan_profile(is_root: bool) -> dict | None:
    """
    Show the interactive scan-profile menu.
    Returns the selected profile dict, or None if the user chose to exit.
    """
    console.print()
    console.rule("[bold cyan]Step 2 -- Choose Scan Type[/]")

    if not is_root:
        print_warning(
            "Running WITHOUT root. Root-only scans are hidden.\n"
            "         Re-run with [bold]sudo python3 nmap_wrapper.py[/] to unlock all scans."
        )
        console.print()

    choices = build_scan_choices(is_root)

    selected_value = inquirer.select(
        message="Select a scan profile:",
        choices=choices,
        default=None,
        pointer=">",
        instruction="(Use up/down arrows, Enter to select)",
    ).execute()

    if selected_value == "exit":
        return None

    return SCAN_PROFILES[selected_value]


# =============================================================================
# SECTION 7 -- Command builder
# =============================================================================

def build_nmap_command(target: str, profile: dict) -> list[str]:
    """
    Assemble the nmap command as a list of strings.
    Using a list (not a single string) prevents shell-injection attacks
    and handles arguments correctly without needing shell=True.
    """
    return ["nmap"] + profile["flags"] + [target]


# =============================================================================
# SECTION 8 -- Scan execution with live-streaming output
# =============================================================================

def run_scan(command: list[str]) -> str:
    """
    Execute the nmap command and stream each line of output to the terminal
    in real time. Returns the full captured output as a string for saving.
    """
    console.print()
    console.rule("[bold green]Scan Output[/]")

    output_lines: list[str] = []
    process = None

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # merge stderr into stdout
            text=True,                  # auto-decode bytes to str
            bufsize=1,                  # line-buffered for real-time streaming
        )

        for line in process.stdout:
            stripped = line.rstrip("\n")
            console.print(stripped)
            output_lines.append(stripped)

        process.wait()

        console.print()
        if process.returncode == 0:
            print_success(f"Scan completed (exit code {process.returncode}).")
        else:
            print_warning(f"nmap exited with code {process.returncode}.")

    except KeyboardInterrupt:
        console.print()
        print_warning("Scan interrupted by user (Ctrl-C).")
        if process and process.poll() is None:
            process.terminate()

    except FileNotFoundError:
        print_error("nmap binary not found. Is it installed?")

    return "\n".join(output_lines)


# =============================================================================
# SECTION 9 -- Report saving
# =============================================================================

def prompt_save_report(scan_output: str, target: str, profile: dict) -> None:
    """
    Ask whether to save the scan output, and in which format:
      Normal text  -- written directly from our captured buffer
      XML          -- nmap re-run with -oX (nmap writes structured XML)
      Grepable     -- nmap re-run with -oG (easy to process with grep/awk)
    """
    console.print()
    console.rule("[bold cyan]Step 3 -- Save Report[/]")

    save = inquirer.confirm(
        message="Would you like to save the scan output to a file?",
        default=False,
    ).execute()

    if not save:
        print_info("Report not saved.")
        return

    fmt_choice = inquirer.select(
        message="Choose output format:",
        choices=[
            Choice(value="normal",   name="Normal text  (.txt)  -- same as terminal output"),
            Choice(value="xml",      name="XML          (.xml)  -- machine-readable"),
            Choice(value="grepable", name="Grepable     (.gnmap) -- easy to grep/awk"),
            Choice(value="all",      name="All three formats at once"),
        ],
        pointer=">",
    ).execute()

    timestamp   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^\w.\-]", "_", target)
    base_name   = f"nmap_{safe_target}_{timestamp}"

    save_dir = Path.cwd() / "nmap_reports"
    save_dir.mkdir(exist_ok=True)

    saved_files: list[str] = []

    if fmt_choice in ("normal", "all"):
        txt_path = save_dir / f"{base_name}.txt"
        txt_path.write_text(scan_output, encoding="utf-8")
        saved_files.append(str(txt_path))

    if fmt_choice in ("xml", "all"):
        xml_path = save_dir / f"{base_name}.xml"
        _rerun_nmap_with_output_flag(target, profile, "-oX", str(xml_path))
        saved_files.append(str(xml_path))

    if fmt_choice in ("grepable", "all"):
        gnmap_path = save_dir / f"{base_name}.gnmap"
        _rerun_nmap_with_output_flag(target, profile, "-oG", str(gnmap_path))
        saved_files.append(str(gnmap_path))

    console.print()
    for fp in saved_files:
        print_success(f"Saved: [bold]{fp}[/]")


def _rerun_nmap_with_output_flag(
    target: str, profile: dict, flag: str, filepath: str
) -> None:
    """
    Re-run nmap silently with an output flag so nmap itself writes a
    correctly structured file (XML/Grepable formats).
    """
    command = ["nmap"] + profile["flags"] + [flag, filepath, target]
    print_info(f"Writing {flag} output to: {filepath}")
    try:
        subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception as exc:
        print_error(f"Failed to generate {flag} output: {exc}")


# =============================================================================
# SECTION 10 -- Main application loop
# =============================================================================

def main() -> None:
    """
    Application entry point.

    Flow:
      1. Banner + dependency / privilege checks + legal disclaimer
      2. Target selection (with validation)
      3. Scan profile menu (root-gated options)
      4. Educational command preview
      5. User confirmation
      6. Live-streaming scan execution
      7. Optional report saving
      8. Continue / new target / exit prompt
    """
    print_banner()
    check_nmap_installed()

    is_root = check_root_privileges()
    if is_root:
        print_success("Running as [bold]root[/] -- all scan types are available.")
    else:
        print_warning("Running as non-root -- some advanced scans require sudo.")

    console.print(
        Panel(
            "[bold yellow]Legal and Ethical Reminder[/]\n\n"
            "Only scan hosts and networks that you [bold]own[/] or have "
            "[bold]explicit written permission[/] to test.\n"
            "Unauthorised port scanning may be illegal in your jurisdiction.",
            border_style="yellow",
        )
    )

    while True:
        target = prompt_for_target()

        while True:
            profile = prompt_for_scan_profile(is_root)

            if profile is None:
                console.print()
                print_info("Goodbye! Stay ethical.")
                sys.exit(0)

            console.print()
            console.rule("[bold cyan]Scan Info[/]")
            console.print(
                Panel(
                    profile["description"],
                    title=f"[bold green]{profile['name']}[/]",
                    border_style="green",
                )
            )

            command = build_nmap_command(target, profile)
            print_command(command)

            confirmed = inquirer.confirm(
                message="Proceed with this scan?",
                default=True,
            ).execute()

            if not confirmed:
                print_info("Scan cancelled. Choose another profile.")
                continue

            scan_output = run_scan(command)
            prompt_save_report(scan_output, target, profile)

            console.print()
            next_action = inquirer.select(
                message="What would you like to do next?",
                choices=[
                    Choice(value="rescan",     name="Run another scan on the same target"),
                    Choice(value="new_target", name="Enter a new target"),
                    Choice(value="exit",       name="Exit"),
                ],
                pointer=">",
            ).execute()

            if next_action == "exit":
                console.print()
                print_info("Goodbye! Stay ethical.")
                sys.exit(0)
            elif next_action == "new_target":
                break   # break inner loop -- re-enter target
            # "rescan" -- continue inner loop with same target


if __name__ == "__main__":
    main()
