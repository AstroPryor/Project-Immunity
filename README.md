# Project Immunity

A Python-based antivirus system that detects, quarantines, and mitigates ransomware and macro-based malware attacks in real time. Built as a capstone project at the University of North Texas.

**Team:** Capstone Bros — Astro Pryor, Bakr Alkhalidi, Jay Hernandez, Elli Gould, Grant Stautzenberger

---

## Features

- **Ransomware detection** — real-time file system monitoring using Shannon entropy analysis (measures file randomness; encrypted files score near 8.0), suspicious extensions matching, AES pattern scanning, ransom note detection, and Watchdog handlers
- **Ransomware mitigation** — automatic process termination via `psutil`, file quarantine, and pre-quarantine backup
- **Macrovirus detection** — monitors for mass file creation events triggered by malicious Office macro documents
- **Macrovirus mitigation** — terminates `WINWORD.EXE`, quarantines malicious files, and writes structured JSON event logs
- **Unified GUI** — real-time dual log panel showing both antivirus engines running simultaneously
- **Multithreaded architecture** — ransomware and macrovirus engines run independently without blocking each other or the GUI

---

## Project Structure

```
project_immunity/
│
├── run_ui.py                            # Entry point — loads config, launches GUI
├── config.yaml                          # Runtime configuration
├── logging_setup.py                     # Centralized logging setup for GUI
│
├── services/
│   └── runner.py                        # Coordinator — spawns both antivirus engines
│
├── ui/
│   └── main_window.py                   # tkinter/ttkbootstrap GUI
│
├── ransomware_antivirus.py              # Core ransomware detection + mitigation engine
├── monitor.py                           # Macrovirus detection engine
├── mitigation.py                        # Macrovirus mitigation engine
│
├── ransomware_simulator.py           # Test threat — AES file encryptor (non-malicious)
├── macro_attack.txt                     # Test threat — VBA macro spam script
│
├── ransomware_antivirus_logs.log        # Runtime output (auto-generated)
├── ransomware_antivirus_quarantine/     # Isolated malicious files
├── ransomware_antivirus_backup/         # Pre-quarantine backup copies of affected files
├── macro_defense_security_log.jsonl     # Runtime output (auto-generated)
├── macro_defense_quarantine/            # Isolated macro-related files
└── macro_defense_quarantine.db          # SQLite database of quarantine metadata
```

---

## Requirements

- Python 3.14.0
- Windows 10/11 (tested on Windows 11 on a dedicated dummy laptop)

Install dependencies:

```bash
pip install watchdog==6.0.0 psutil==7.1.3 ttkbootstrap==1.20.2 cryptography==46.0.3 PyYAML==6.0.3 python-json-logger==4.0.0
```

---

## Setup & Deployment

### 1. Clone the repository

```bash
git clone https://github.com/BakrA2/Project-Immunity.git
cd Project-Immunity
```

### 2. Set up a dedicated test environment

> ⚠️ All testing should be performed on a dedicated dummy laptop isolated from production systems. Never run the ransomware simulator on a primary machine.

- OS: Windows 11
- Machine: dedicated dummy laptop for exclusive testing
- Install Python 3.14.0
- Install all dependencies listed above

### 3. Prepare a test directory

Create a folder with sample files for the ransomware simulator to target:

```
C:\Users\Capstone\Documents\test_dir\
```

Populate it with a few `.txt` or `.docx` files.

### 4. Launch the GUI

```bash
python run_ui.py
```

### 5. Start the antivirus

Click **Start Antivirus** in the Project Immunity GUI. Both engines will start simultaneously:

- Ransomware antivirus begins monitoring `Downloads/` and `Documents/`
- Macrovirus antivirus begins monitoring `Desktop/`, `Documents/`, and `Pictures/`

### 6. Run a test threat (optional)

**Ransomware simulator:**

Open a separate PowerShell window and run the simulator targeting only the test directory:

```bash
python ransomware_simulator.py --directory "C:\Users\Capstone\Documents\test_dir"
```

Watch the **Ransomware Antivirus Logs** panel in the GUI for detection alerts and quarantine confirmations.

To decrypt files afterward:

```bash
python ransomware_simulator.py --decrypt --directory "C:\Users\Capstone\Documents\test_dir"
```

**Macro attack:**

1. Open a blank Word document
2. Open `macro_attack.txt`
3. Paste the VBA code into the Word macro editor (`Alt+F11`)
4. Save as `.docm` and open the document
5. Watch the **Macrovirus Antivirus Logs** panel for detection alerts

---

## How It Works

### Ransomware engine

```
File system event (watchdog)
    → Shannon entropy check (> 7.5)
    → Suspicious extension check (.encrypted, .locked, .crypt…)
    → Malware pattern scan (AES imports, ransom strings, os.walk…)
    → Threshold check (≥ 3 changes in 5 s window)
    → CRITICAL alert logged
    → psutil terminates malicious process (by PID)
    → shutil.copy2 → ransomware_antivirus_backup/
    → file moved → ransomware_antivirus_quarantine/YYYYMMDD_HHMMSS/
```

### Macrovirus engine

```
File system event (watchdog)
    → AggregatorThread collects events
    → DispatcherThread routes to ScorerThread
    → ScorerThread scores suspicious file creation burst
    → MitigationThread terminates WINWORD.EXE
    → files moved → macro_defense_quarantine/
    → auto_mitigation_completed written to macro_defense_security_log.jsonl
```

---

## Testing

> ⚠️ All testing uses non-malicious artifacts on a dedicated dummy laptop. No real malware is used at any point.

**Ransomware simulator** (`ransomware_simulator.py`) — encrypts files in a target directory using AES-CBC, creates ransom notes, and supports `--decrypt` and `--cleanup` flags to restore the environment after testing.

**Macro attack** (`macro_attack.txt`) — VBA script that creates mass `.txt` files across Desktop, Documents, and Pictures when executed via a Word document.

---

## Security Notes

- The ransomware simulator and macro attack scripts are **non-malicious test artifacts** — they do not exfiltrate data, connect to external servers, or cause permanent damage
- All detection and response logic was tested on a dedicated dummy laptop isolated from production systems
- Safe paths have been included in the ransomware antivirus whitelist to prevent false positives

---

## License

For academic use only — University of North Texas Capstone, Spring 2026.
