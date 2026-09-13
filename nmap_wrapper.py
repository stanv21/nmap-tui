#!/usr/bin/env python3
"""
nmap_wrapper.py -- Modular Pentesting Toolkit v2.0
An interactive terminal UI for common penetration testing tasks.

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
# Third-party imports  (InquirerPy + rich)
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
    from rich.table import Table
except ImportError:
    print("[ERROR] rich is not installed.")
    print("        Run:  pip install rich")
    sys.exit(1)

# -----------------------------------------------------------------------------
# Global rich console -- one instance used everywhere
# -----------------------------------------------------------------------------
console = Console()


# =============================================================================
# SECTION 1 -- Startup and dependency checks
# =============================================================================

def check_tool_installed(tool: str) -> bool:
    """
    Generic check: return True if `tool` exists on the system PATH.
    Used at startup (nmap) and lazily when a module is entered
    (hydra, gobuster, dirb), so users only fail when they actually
    need the missing tool.
    """
    return shutil.which(tool) is not None


def check_nmap_installed() -> None:
    """
    Hard-fail at startup if nmap is missing.
    The recon module cannot function without it.
    """
    if not check_tool_installed("nmap"):
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
    Return True when running as root (UID 0).
    Returns False on non-POSIX platforms (Windows).
    """
    try:
        return os.getuid() == 0
    except AttributeError:
        return False


# =============================================================================
# SECTION 2 -- Nmap scan profile catalogue
# =============================================================================

# Each profile dict contains:
#   name          -- label shown in the menu
#   flags         -- list of nmap argument strings
#   requires_root -- True if the scan needs raw-socket privileges
#   description   -- educational one-liner displayed before execution

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
            "Attempts to determine the target operating system via TCP/IP "
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
            "Scans UDP ports. Much slower than TCP because UDP gives no "
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
_URL_RE    = re.compile(r"^https?://[^\s]+$")


def is_valid_ip_or_host(target: str) -> bool:
    """
    Validate a target as an IPv4 address, CIDR subnet, hyphen range,
    or hostname.  Shell metacharacters are blocked defensively.
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


def is_valid_url(url: str) -> bool:
    """Return True if the string is a valid http/https URL."""
    return bool(_URL_RE.match(url.strip()))


def is_non_empty(value: str) -> bool:
    """Return True if value is not blank."""
    return bool(value.strip())


# =============================================================================
# SECTION 4 -- UI helpers
# =============================================================================

def print_banner() -> None:
    """Print the toolkit welcome banner."""
    t = Text()
    t.append("  ____  _____ _   _ _____ _____ ____ _____ ___ _   _  ____ \n",  style="bold cyan")
    t.append(" |  _ \\| ____| \\ | |_   _| ____/ ___|_   _|_ _| \\ | |/ ___|\n", style="bold cyan")
    t.append(" | |_) |  _| |  \\| | | | |  _| \\___ \\ | |  | ||  \\| | |  _\n",  style="bold cyan")
    t.append(" |  __/| |___| |\\  | | | | |___ ___) || |  | || |\\  | |_| |\n",  style="bold cyan")
    t.append(" |_|   |_____|_| \\_| |_| |_____|____/ |_| |___|_| \\_|\\____|\n",  style="bold cyan")
    t.append("  _____ ___   ___  _     _  ___ _____ \n",                         style="bold magenta")
    t.append(" |_   _/ _ \\ / _ \\| |   | |/ _ \\_   _|\n",                       style="bold magenta")
    t.append("   | || | | | | | | |   | | | | || |  \n",                         style="bold magenta")
    t.append("   | || |_| | |_| | |___| | |_| || |  \n",                         style="bold magenta")
    t.append("   |_| \\___/ \\___/|_____|_|\\___/ |_|  \n",                       style="bold magenta")
    t.append("\n  Modular Pentesting Toolkit  - All rights reserved\n",              style="dim")
    t.append("  github.com/stanv21/nmap-tui\n",                                  style="dim")
    console.print(Panel(t, border_style="cyan", box=box.DOUBLE_EDGE))


def print_section(title: str, color: str = "cyan") -> None:
    """Print a full-width section divider."""
    console.print()
    console.rule(f"[bold {color}]{title}[/]")
    console.print()


def print_info(msg: str)    -> None: console.print(f"[bold cyan][INFO][/] {msg}")
def print_warning(msg: str) -> None: console.print(f"[bold yellow][WARN][/] {msg}")
def print_error(msg: str)   -> None: console.print(f"[bold red][ERR ][/] {msg}")
def print_success(msg: str) -> None: console.print(f"[bold green][OK  ][/] {msg}")


def print_command(command: list[str]) -> None:
    """
    Display the exact command about to run.
    Educational core -- users see real tool syntax and flags.
    """
    console.print(
        Panel(
            f"[bold white]{' '.join(command)}[/]",
            title="[bold yellow]Running Command[/]",
            border_style="yellow",
            subtitle="[dim]Copy this into your terminal to run it manually[/]",
        )
    )


# =============================================================================
# SECTION 5 -- Shared subprocess execution (live-streaming)
# =============================================================================

def stream_command(command: list[str], tool_name: str = "process") -> str:
    """
    Execute any command and stream its output to the terminal line by line.

    Using subprocess.Popen with bufsize=1 (line-buffered) ensures output
    appears in real time rather than buffered until the process exits.

    Returns the full captured output as a string so it can be saved.
    """
    output_lines: list[str] = []
    process = None

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # merge stderr so warnings appear inline
            text=True,
            bufsize=1,                 # line-buffered for real-time output
        )

        for line in process.stdout:
            stripped = line.rstrip("\n")
            console.print(stripped)
            output_lines.append(stripped)

        process.wait()
        console.print()

        if process.returncode == 0:
            print_success(f"{tool_name} finished (exit code {process.returncode}).")
        else:
            print_warning(
                f"{tool_name} exited with code {process.returncode}. "
                "Check output above for details."
            )

    except KeyboardInterrupt:
        console.print()
        print_warning("Interrupted by user (Ctrl-C).")
        if process and process.poll() is None:
            process.terminate()

    except FileNotFoundError:
        print_error(f"'{tool_name}' binary not found. Is it installed?")

    return "\n".join(output_lines)


# =============================================================================
# SECTION 6 -- Report / output saving
# =============================================================================

def prompt_save_output(
    output: str,
    prefix: str,
    target_label: str,
    nmap_extra_formats: bool = False,
    nmap_profile: dict | None = None,
    nmap_target: str | None = None,
) -> None:
    """
    Ask the user whether to save captured output and in which format.

    For Nmap output, extra format options (XML, Grepable) are offered
    because nmap can write these natively in a structured way.
    All reports are saved under pentest_reports/ in the cwd.
    """
    console.print()
    console.rule("[bold cyan]Save Output[/]")

    save = inquirer.confirm(
        message="Would you like to save the output to a file?",
        default=False,
    ).execute()

    if not save:
        print_info("Output not saved.")
        return

    # Build format choices -- XML/Grepable only shown for nmap
    format_choices = [Choice(value="txt", name="Plain text  (.txt)")]
    if nmap_extra_formats:
        format_choices += [
            Choice(value="xml",   name="XML         (.xml)   -- machine-readable"),
            Choice(value="gnmap", name="Grepable    (.gnmap)  -- easy to grep/awk"),
            Choice(value="all",   name="All three formats at once"),
        ]

    fmt = (
        inquirer.select(
            message="Choose output format:",
            choices=format_choices,
            pointer=">",
        ).execute()
        if len(format_choices) > 1
        else "txt"
    )

    timestamp  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_label = re.sub(r"[^\w.\-]", "_", target_label)
    base_name  = f"{prefix}_{safe_label}_{timestamp}"

    save_dir = Path.cwd() / "pentest_reports"
    save_dir.mkdir(exist_ok=True)

    saved_files: list[str] = []

    if fmt in ("txt", "all"):
        p = save_dir / f"{base_name}.txt"
        p.write_text(output, encoding="utf-8")
        saved_files.append(str(p))

    if fmt in ("xml", "all") and nmap_profile and nmap_target:
        p = save_dir / f"{base_name}.xml"
        _rerun_nmap_with_flag(nmap_target, nmap_profile, "-oX", str(p))
        saved_files.append(str(p))

    if fmt in ("gnmap", "all") and nmap_profile and nmap_target:
        p = save_dir / f"{base_name}.gnmap"
        _rerun_nmap_with_flag(nmap_target, nmap_profile, "-oG", str(p))
        saved_files.append(str(p))

    console.print()
    for fp in saved_files:
        print_success(f"Saved: [bold]{fp}[/]")


def _rerun_nmap_with_flag(
    target: str, profile: dict, flag: str, filepath: str
) -> None:
    """
    Re-run nmap silently with an output-format flag (-oX / -oG).
    nmap writes these formats natively; we cannot produce them from
    the plain-text buffer we already captured.
    """
    command = ["nmap"] + profile["flags"] + [flag, filepath, target]
    print_info(f"Writing {flag} file to: {filepath}")
    try:
        subprocess.run(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
        )
    except Exception as exc:
        print_error(f"Failed to write {flag} output: {exc}")


# =============================================================================
# SECTION 7 -- Recon and Scanning module (Nmap)
# =============================================================================

def get_local_subnet() -> str | None:
    """
    Detect the local machine's active IPv4 subnet in CIDR notation
    (e.g. '192.168.1.0/24') by parsing the output of `ip route`.

    We look for the line that contains 'src' and a private RFC-1918
    address, which is the route nmap would use for LAN scanning.
    Falls back to the first non-loopback network route if no 'src'
    line is found.

    Returns the CIDR string on success, or None on any failure.
    """
    try:
        result = subprocess.run(
            ["ip", "route"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return None

        # Strategy 1 -- look for the default route's 'src' address.
        # `ip route` output looks like:
        #   default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.42 ...
        # We can also find lines like:
        #   192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.42
        # We prefer the latter because it already gives us the subnet CIDR.
        for line in result.stdout.splitlines():
            parts = line.split()
            # A line that starts with a CIDR and contains 'src' is perfect --
            # it gives us the subnet directly without any arithmetic.
            if (
                parts
                and "/" in parts[0]
                and "src" in parts
                and not parts[0].startswith("default")
            ):
                cidr = parts[0]
                # Quick sanity-check: must look like a private IPv4 CIDR
                if _CIDR_RE.match(cidr):
                    return cidr

        # Strategy 2 -- derive the subnet from the 'src' IP on the default route.
        # We find the src IP, then look for a matching route line to get prefix len.
        src_ip = None
        for line in result.stdout.splitlines():
            parts = line.split()
            if "src" in parts:
                idx = parts.index("src")
                if idx + 1 < len(parts):
                    candidate = parts[idx + 1]
                    if _IPV4_RE.match(candidate) and not candidate.startswith("127."):
                        src_ip = candidate
                        break

        if src_ip is None:
            return None

        # Find the network CIDR whose range contains src_ip
        src_octets = list(map(int, src_ip.split(".")))
        for line in result.stdout.splitlines():
            parts = line.split()
            if not parts or "/" not in parts[0]:
                continue
            try:
                net, prefix_str = parts[0].split("/")
                prefix = int(prefix_str)
                net_octets = list(map(int, net.split(".")))
                # Check if src_ip belongs to this network via bitmask
                mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                net_int = sum(o << (24 - 8 * i) for i, o in enumerate(net_octets))
                src_int = sum(o << (24 - 8 * i) for i, o in enumerate(src_octets))
                if (src_int & mask) == (net_int & mask):
                    return f"{net}/{prefix}"
            except (ValueError, IndexError):
                continue

        return None

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # `ip` not found (e.g. running on Windows) or timed out
        return None


def _prompt_nmap_target() -> str:
    """
    Present the user with two target-input options:
      1. Auto-detect and use the local network CIDR  (quality-of-life shortcut)
      2. Enter a custom target manually

    If auto-detection fails, falls through silently to manual input.
    """
    detected_subnet = get_local_subnet()

    # Build the choice list dynamically based on whether detection succeeded
    target_choices = []
    if detected_subnet:
        target_choices.append(
            Choice(
                value="auto",
                name=f"Auto-detect local network  (detected: {detected_subnet})",
            )
        )
    target_choices.append(
        Choice(value="manual", name="Enter a custom target  (IP, range, domain)")
    )

    if detected_subnet is None:
        print_warning(
            "Could not auto-detect the local subnet "
            "(is the network interface up?). Falling back to manual input."
        )

    # If auto-detect succeeded, show the choice menu; otherwise skip straight
    # to manual input (no point showing a one-item menu).
    if detected_subnet:
        input_mode = inquirer.select(
            message="How would you like to specify the target?",
            choices=target_choices,
            pointer=">",
            instruction="(Use up/down arrows, Enter to select)",
        ).execute()
    else:
        input_mode = "manual"

    if input_mode == "auto":
        print_success(f"Target set to local network: [bold]{detected_subnet}[/]")
        return detected_subnet

    # Manual input path -- same validated loop as before
    console.print(
        "\n  Accepted formats: [cyan]192.168.1.1[/]  |  [cyan]192.168.1.0/24[/]  "
        "|  [cyan]192.168.1.1-50[/]  |  [cyan]scanme.nmap.org[/]\n"
    )
    while True:
        target = inquirer.text(
            message="Target (IP / subnet / hostname):",
            validate=lambda t: is_valid_ip_or_host(t),
            invalid_message="Invalid. Enter a valid IP, CIDR range, or hostname.",
        ).execute().strip()
        if is_valid_ip_or_host(target):
            return target


def _build_nmap_choices(is_root: bool) -> list:
    """
    Build the scan-profile choice list.
    Root-required profiles are hidden when the user is not root.
    """
    choices = []
    for idx, profile in enumerate(SCAN_PROFILES):
        if profile["requires_root"] and not is_root:
            continue
        choices.append(Choice(value=idx, name=profile["name"]))
    choices.append(Separator())
    choices.append(Choice(value="back", name="Back to Main Menu"))
    return choices


def run_nmap_module(is_root: bool) -> None:
    """
    Recon and Scanning module entry point.

    Handles the full Nmap workflow:
      - Target input and validation
      - Scan-profile selection (root-gated where needed)
      - Educational command preview
      - Live-streamed execution
      - Optional report saving
    Returns when the user navigates back to the main menu.
    """
    console.print(
        Panel(
            "[bold cyan]Recon and Scanning Module[/]\n\n"
            "Use Nmap to discover hosts, open ports, running services,\n"
            "operating systems, and known vulnerabilities.\n\n"
            "Every command is displayed before execution so you learn the flags.",
            border_style="cyan",
        )
    )

    if not is_root:
        print_warning(
            "Running WITHOUT root. Root-only profiles are hidden.\n"
            "         Re-run with [bold]sudo python3 nmap_wrapper.py[/] to unlock them."
        )

    # Outer loop: lets the user scan a new target without going to main menu
    while True:
        print_section("Step 1 -- Select Target", color="cyan")
        target = _prompt_nmap_target()

        # Inner loop: multiple scans against the same target
        while True:
            print_section("Step 2 -- Choose Scan Type", color="cyan")

            selected = inquirer.select(
                message="Select a scan profile:",
                choices=_build_nmap_choices(is_root),
                default=None,
                pointer=">",
                instruction="(Use up/down arrows, Enter to select)",
            ).execute()

            if selected == "back":
                return  # exit module -- back to main menu

            profile = SCAN_PROFILES[selected]

            # Educational description panel
            console.print()
            console.print(
                Panel(
                    profile["description"],
                    title=f"[bold green]{profile['name']}[/]",
                    border_style="green",
                )
            )

            command = ["nmap"] + profile["flags"] + [target]
            print_command(command)

            if not inquirer.confirm(
                message="Proceed with this scan?", default=True
            ).execute():
                print_info("Scan cancelled. Choose another profile.")
                continue

            print_section("Scan Output", color="green")
            output = stream_command(command, tool_name="nmap")

            prompt_save_output(
                output=output,
                prefix="nmap",
                target_label=target,
                nmap_extra_formats=True,
                nmap_profile=profile,
                nmap_target=target,
            )

            # Post-scan navigation
            console.print()
            next_action = inquirer.select(
                message="What would you like to do next?",
                choices=[
                    Choice(value="rescan",     name="Run another scan on the same target"),
                    Choice(value="new_target", name="Scan a different target"),
                    Choice(value="menu",       name="Return to Main Menu"),
                    Choice(value="exit",       name="Exit"),
                ],
                pointer=">",
            ).execute()

            if next_action == "exit":
                _goodbye()
            elif next_action == "menu":
                return
            elif next_action == "new_target":
                break       # break inner loop -- re-enter target above
            # "rescan" -- continue inner loop with same target


# =============================================================================
# SECTION 8 -- Attacks and Exploitation module
# =============================================================================

def _run_hydra_ssh() -> None:
    """
    SSH Brute Force sub-module using Hydra.

    Prompts for target IP, port, username (single or list), and a
    password wordlist.  Assembles and streams the hydra command.

    Command structure:
      hydra -l <user> -P <wordlist> -s <port> ssh://<target>
      hydra -L <userlist> -P <wordlist> -s <port> ssh://<target>
    """
    if not check_tool_installed("hydra"):
        console.print(
            Panel(
                "[bold red]hydra is not installed or not found in PATH.[/]\n\n"
                "Install it with:\n"
                "  [bold cyan]sudo apt update && sudo apt install hydra[/]",
                title="[red]Dependency Missing[/]",
                border_style="red",
            )
        )
        return

    print_section("SSH Brute Force -- hydra Configuration", color="red")

    # Target
    target = inquirer.text(
        message="Target IP or hostname:",
        validate=lambda t: is_valid_ip_or_host(t),
        invalid_message="Enter a valid IP address or hostname.",
    ).execute().strip()

    # SSH port
    port = inquirer.text(
        message="SSH port (default 22):",
        default="22",
        validate=lambda p: p.strip().isdigit() and 1 <= int(p.strip()) <= 65535,
        invalid_message="Enter a valid port number (1-65535).",
    ).execute().strip()

    # Username source
    user_mode = inquirer.select(
        message="Username input method:",
        choices=[
            Choice(value="single", name="Single username"),
            Choice(value="list",   name="Username list file"),
        ],
        pointer=">",
    ).execute()

    if user_mode == "single":
        username = inquirer.text(
            message="Username:",
            validate=is_non_empty,
            invalid_message="Username cannot be blank.",
        ).execute().strip()
        user_flag = ["-l", username]
    else:
        user_file = inquirer.text(
            message="Path to username list:",
            validate=lambda p: Path(p.strip()).is_file(),
            invalid_message="File not found. Enter a valid path.",
        ).execute().strip()
        user_flag = ["-L", user_file]

    # Password wordlist
    wordlist = inquirer.text(
        message="Path to password wordlist:",
        default="/usr/share/wordlists/rockyou.txt",
        validate=lambda p: Path(p.strip()).is_file(),
        invalid_message="File not found. Enter a valid path.",
    ).execute().strip()

    command = ["hydra"] + user_flag + ["-P", wordlist, "-s", port, f"ssh://{target}"]
    print_command(command)

    if not inquirer.confirm(
        message="Proceed with this brute force attack?", default=True
    ).execute():
        print_info("Attack cancelled.")
        return

    print_section("Hydra Output", color="red")
    output = stream_command(command, tool_name="hydra")
    prompt_save_output(output=output, prefix="hydra_ssh", target_label=target)


def _run_dir_bruteforce() -> None:
    """
    Web Directory Bruteforce sub-module.

    Prefers gobuster (more actively maintained); falls back to dirb
    when gobuster is not installed.  Prompts for a target URL and
    wordlist, then streams the output.

    gobuster command: gobuster dir -u <url> -w <wordlist>
    dirb    command: dirb <url> <wordlist>
    """
    # Tool selection with automatic fallback
    if check_tool_installed("gobuster"):
        tool = "gobuster"
    elif check_tool_installed("dirb"):
        tool = "dirb"
    else:
        console.print(
            Panel(
                "[bold red]Neither gobuster nor dirb is installed.[/]\n\n"
                "Install one with:\n"
                "  [bold cyan]sudo apt install gobuster[/]\n"
                "  [bold cyan]sudo apt install dirb[/]",
                title="[red]Dependency Missing[/]",
                border_style="red",
            )
        )
        return

    print_section(f"Directory Bruteforce -- {tool} Configuration", color="red")
    console.print(
        f"  [dim]Using tool: [bold]{tool}[/bold]. "
        "Install gobuster for richer output.[/]\n"
    )

    # Target URL
    url = inquirer.text(
        message="Target URL (include http:// or https://):",
        validate=lambda u: is_valid_url(u),
        invalid_message="Enter a valid URL starting with http:// or https://",
    ).execute().strip()

    # Wordlist
    wordlist = inquirer.text(
        message="Path to wordlist:",
        default="/usr/share/wordlists/dirb/common.txt",
        validate=lambda p: Path(p.strip()).is_file(),
        invalid_message="File not found. Enter a valid path.",
    ).execute().strip()

    # Build the tool-appropriate command
    if tool == "gobuster":
        command = ["gobuster", "dir", "-u", url, "-w", wordlist]
    else:
        command = ["dirb", url, wordlist]

    print_command(command)

    if not inquirer.confirm(
        message="Proceed with this directory bruteforce?", default=True
    ).execute():
        print_info("Attack cancelled.")
        return

    print_section("Bruteforce Output", color="red")
    output = stream_command(command, tool_name=tool)
    safe_url = re.sub(r"[^\w.\-]", "_", url)
    prompt_save_output(output=output, prefix=f"{tool}_dir", target_label=safe_url)


def run_attack_module() -> None:
    """
    Attacks and Exploitation module entry point.

    Shows a sub-menu of available attack tools.  Loops until the user
    chooses to return to the main menu or exit.
    """
    console.print(
        Panel(
            "[bold red]Attacks and Exploitation Module[/]\n\n"
            "[bold yellow]WARNING:[/] Only use these tools against systems you\n"
            "own or have [bold]explicit written permission[/] to test.\n\n"
            "Available attacks:\n"
            "  [1] SSH Brute Force via Hydra\n"
            "  [2] Web Directory Bruteforce via Gobuster / Dirb",
            border_style="red",
        )
    )

    while True:
        print_section("Attack Selection", color="red")

        choice = inquirer.select(
            message="Choose an attack:",
            choices=[
                Choice(value="ssh_bf", name="[1] SSH Brute Force  (hydra)"),
                Choice(value="dir_bf", name="[2] Directory Bruteforce  (gobuster / dirb)"),
                Separator(),
                Choice(value="back",   name="Back to Main Menu"),
            ],
            pointer=">",
            instruction="(Use up/down arrows, Enter to select)",
        ).execute()

        if choice == "back":
            return

        if choice == "ssh_bf":
            _run_hydra_ssh()
        elif choice == "dir_bf":
            _run_dir_bruteforce()

        # Post-attack navigation
        console.print()
        follow_up = inquirer.select(
            message="What would you like to do next?",
            choices=[
                Choice(value="another", name="Run another attack"),
                Choice(value="menu",    name="Return to Main Menu"),
                Choice(value="exit",    name="Exit"),
            ],
            pointer=">",
        ).execute()

        if follow_up == "exit":
            _goodbye()
        elif follow_up == "menu":
            return
        # "another" -- continue loop and show attack sub-menu again


# =============================================================================
# SECTION 9 -- Main menu and application entry point
# =============================================================================

def _goodbye() -> None:
    """Print exit message and terminate."""
    console.print()
    print_info("Goodbye! Stay ethical.")
    sys.exit(0)


def show_main_menu() -> str:
    """
    Display the root-level main menu with a live tool-availability table.
    Returns the user's choice key: 'nmap', 'attack', or 'exit'.
    """
    console.print()
    console.rule("[bold cyan]Main Menu[/]")
    console.print()

    # Quick status table -- shows which tools are available at a glance
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column(style="bold dim")
    table.add_column()
    for tool, label in [
        ("nmap",     "Recon module"),
        ("hydra",    "SSH brute force"),
        ("gobuster", "Dir bruteforce (preferred)"),
        ("dirb",     "Dir bruteforce (fallback)"),
    ]:
        status = (
            "[green]installed[/]"
            if check_tool_installed(tool)
            else "[yellow]not found[/]"
        )
        table.add_row(f"{tool} ({label})", status)

    console.print(table)
    console.print()

    return inquirer.select(
        message="Choose a module:",
        choices=[
            Choice(value="nmap",   name="[1] Recon and Scanning      (Nmap)"),
            Choice(value="attack", name="[2] Attacks and Exploitation  (Hydra / Gobuster)"),
            Separator(),
            Choice(value="exit",   name="Exit"),
        ],
        pointer=">",
        instruction="(Use up/down arrows, Enter to select)",
    ).execute()


def main() -> None:
    """
    Application entry point.

    Startup flow:
      1. Print toolkit banner
      2. Hard dependency check for nmap
      3. Root privilege check (gates certain scan types)
      4. Legal disclaimer
      5. Main menu loop -- delegates to module functions
         run_nmap_module()   for Recon and Scanning
         run_attack_module() for Attacks and Exploitation
    """
    print_banner()
    check_nmap_installed()

    is_root = check_root_privileges()
    if is_root:
        print_success("Running as [bold]root[/] -- all features available.")
    else:
        print_warning(
            "Running as non-root. Some Nmap scans may require sudo."
        )

    console.print(
        Panel(
            "[bold yellow]Legal and Ethical Reminder[/]\n\n"
            "Only scan and test hosts and networks that you [bold]own[/] or have\n"
            "[bold]explicit written permission[/] to test.\n"
            "Unauthorised access or port scanning may be illegal in your jurisdiction.",
            border_style="yellow",
        )
    )

    # Main event loop -- returns here after every module finishes
    while True:
        choice = show_main_menu()

        if choice == "nmap":
            run_nmap_module(is_root)

        elif choice == "attack":
            run_attack_module()

        elif choice == "exit":
            _goodbye()


if __name__ == "__main__":
    main()
