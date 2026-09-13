# NmapTUI

An interactive, educational terminal UI wrapper for Nmap -- scan networks without memorising flags.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-purple?logo=linux)

---

```
+----------------------------------------------------------+
|   _   _ __  __    _    ____    _____ _   _ ___          |
|  | \ | |  \/  |  / \  |  _ \  |_   _| | | |_ _|        |
|  |  \| | |\/| | / _ \ | |_) |   | | | | | || |         |
|  | |\  | |  | |/ ___ \|  __/    | | | |_| || |         |
|  |_| \_|_|  |_/_/   \_\_|       |_|  \___/|___|        |
|                                                          |
|    Interactive Nmap Wrapper  v1.0  MIT License           |
+----------------------------------------------------------+
```

---

## What is NmapTUI?

**NmapTUI** is a Python-based terminal UI that wraps the powerful `nmap` network scanner behind an
easy-to-navigate menu. Instead of memorising complex flags, you pick a scan profile and the tool
builds the command for you -- then shows you exactly what it ran so you can learn.

### Key Features

| Feature | Description |
|---------|-------------|
| **10 Scan Profiles** | Quick, SYN, Full-port, Aggressive, Vuln, OS, UDP and more |
| **Educational Mode** | Displays the exact `nmap` command before each scan |
| **Privilege Awareness** | Hides root-only scans unless run with `sudo` |
| **Live Streaming** | Output streams to the terminal in real time |
| **Report Saving** | Save results as Normal (.txt), XML (.xml), or Grepable (.gnmap) |
| **Input Validation** | Validates IPs, CIDR ranges, and hostnames before scanning |
| **Dependency Check** | Graceful error if `nmap` is not installed |

---

## Requirements

- **OS**: Kali Linux (or any Debian-based Linux)
- **Python**: 3.10 or higher
- **nmap**: Must be installed on the system

---

## Installation

### 1 - Clone the repository

```bash
git clone https://github.com/stanv21/nmap-tui.git
cd nmap-tui
```

### 2 - Install nmap (if not already installed)

```bash
sudo apt update && sudo apt install nmap -y
```

### 3 - Install Python dependencies

```bash
pip install -r requirements.txt
```

> **Tip**: Use a virtual environment to keep dependencies isolated:
> ```bash
> python3 -m venv .venv
> source .venv/bin/activate
> pip install -r requirements.txt
> ```

---

## Usage

### Run as a regular user (limited scans)

```bash
python3 nmap_wrapper.py
```

### Run as root (all scans unlocked)

```bash
sudo python3 nmap_wrapper.py
```

> Root is required for SYN scans (`-sS`), OS detection (`-O`), UDP scans (`-sU`),
> and other raw-socket scans.

---

## Scan Profiles

| Profile | Flags | Root Required |
|---------|-------|:---:|
| Quick Scan | `-T4 -F` | No |
| Standard SYN Scan | `-sS -v` | Yes |
| Full Port Scan | `-p- -v` | No |
| Aggressive / All-in-one | `-A -T4` | Yes |
| Service and Version Detection | `-sV -v` | No |
| OS Detection | `-O -v` | Yes |
| Vulnerability Scan | `-sV --script vuln` | No |
| Ping Sweep | `-sn` | No |
| UDP Scan | `-sU -v` | Yes |
| Stealth + Version + Scripts | `-sS -sV -sC -v` | Yes |

---

## Output / Reports

After each scan you will be asked whether you want to save the results.
Reports are saved in a `nmap_reports/` folder in the current working directory,
with a timestamped filename, e.g.:

```
nmap_reports/
  nmap_192.168.1.1_20260913_102500.txt
  nmap_192.168.1.1_20260913_102500.xml
  nmap_192.168.1.1_20260913_102500.gnmap
```

---

## Project Structure

```
nmap-tui/
  nmap_wrapper.py   # Main application (single-file v1.0)
  requirements.txt  # Python dependencies
  README.md         # This file
```

---

## Legal Disclaimer

> WARNING: Only scan hosts and networks that you own or have explicit written permission to test.
> Unauthorised port scanning may be illegal under computer-crime laws in your country.
> The authors accept no liability for misuse of this tool.


---

## Contributing

Pull requests are welcome. Please open an issue first to discuss major changes.

1. Fork the repo
2. Create a branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a pull request

---

## License

**All Rights Reserved.** 
This software is provided for personal, educational use only. You may not modify, distribute, or use this code for commercial purposes without explicit permission from the author.
