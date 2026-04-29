# Project-Immunity

A Python-based antivirus system that detects, quarantines, and mitigates ransomware and macro-based malware attacks in real time. Built as a capstone project at the University of North Texas.

Team
  Capstone Bros - Astro Pryor, Bakr Alkhalidi, Jay Hernandez, Elli Gould, Grant Stautzenberger

Features
  Ransomware detection - real-time file system monitoring using Shannon entropy analysis (measures file randomness; encrypted files score near 8.0), suspicious   extensions matching, AES pattern scanning, ransom note detection, and Watchdog handlers
  Ransomware mitigation - automatic process termination via psutil, file quarantine, and pre-quarantine backup
  Macrovirus detection - monitors for mass file creation events triggered by malicious Office macro documents
  Macrovirus mitigation - terminates WINWORD.EXE, quarantines malicious files, and write structured JSON event logs
  Unified GUI - real- time dual log panel showing both antivirus engines running simultaneously
  Multithreaded architecture - ransomware and macrovirus engines run independently without blocking each other or the GUI

Project Structure
project_immunity/
│
├── run_ui.py                          # Entry point — loads config, launches GUI
├── config.yaml                          # Runtime configuration
├── logging_setup.py                     # Centralized logging setup for GUI
│
├── services/
│   └── runner.py                      # Coordinator — spawns both antivirus engines
│
├── ui/
│   └── main_window.py                 # tkinter/ttkbootstrap GUI
│
├── ransomware_antivirus.py              # Core ransomware detection + mitigation engine
├── monitor.py                           # Macrovirus detection engine
├── mitigation.py                        # Macrovirus mitigation engine
│
├── ransomware_simulator_v4.py           # Test threat — AES file encryptor (non-malicious)
├── macro_attack.txt                     # Test threat — VBA macro spam script
│
├── ransomware_antivirus_logs.log        # Runtime output (auto-generated)
├── ransomware_antivirus_quarantine/   # Isolated malicious files
├──  ransomware_antivirus_backup/       # Pre-quarantine backup copies of affected files
├── macro_defense_security_log.jsonl   # Runtime output (auto-generated)
├── macro_defense_quarantine/             # Isolated macro-related files
└── macro_defense_quarantine.db         # SQLite database of quarantine metadata

Requirements
Python 3.14.0
Windows 10/11 (tested on Windows 11 on a dedicated dummy laptop)
Install dependencies:
pip install watchdog==6.0.0 psutil==7.1.3 ttkbootstrap==1.20.2 cryptography==46.0.3 PyYAML==6.0.3

Setup and Deployment
  Clone the repository
    git clone https://github.com/your-repo/project-immunity.git
    cd project-immunity
  Set up a dedicated test environment
    OS: Windows 11
    Machine: dummy laptop for exclusive testing
    Install Python 3.14.0
    Install dependencies above
    Prepare a test directory
  Create a folder with sample files for the ransomware simulator to target
    e.g C:\Users\Capstone\Documents\test_dir\
    Populate with a few .txt files or .docx files
  Launch the GUI
    python run_ui.py
  Start the antivirus
    Click “Start Antivirus” in the Project Immunity GUI. Both engines will start simultaneously
      Ransomware antivirus begins monitoring Downloads/ and Documents/
      Macrovirus antivirus begins monitoring Desktop/, Documents/, and Pictures/
  Run a test threat (optional)
    Open a separate Command Prompt or Powershell window and run the ransomware simulator that targets ONLY the test directory made above
      python ransomware_simulator.py -- directory {path_to_test_dir}
      Watch Ransomware Antivirus Logs panel in GUI for detection alerts and quarantine confirmations
      To decrypt, run this line
        python ransomware_simulator.py -- decrypt -- directory {path_to_test_dir}
    Open a blank Word Document
      Open macro_attack.txt
      Paste the VBA code into a Word document's macro editor (Alt+F11)
      Save as .docm and open the document
      Watch Macrovirus Antivirus Logs panel for detection alerts

How It Works
Ransomware antivirus engine
  Shannon entropy check (> 7.5)
  Suspicious extension check (.encrypted, .locked, .crypt…)
  Malware pattern scan (AES imports, ransom strings, os.walk…)
  Threshold check (>= 3 changes in 5 second window)
  Critical alert logged
  Psutil terminates malicious process by PID
  shutil.copy2 -> ransomware_antivirus_backup/
  File moved -> ransomware_antivirus_quarantine/YYYYMMDD_HHMMSS/
Macrovirus antivirus engine
  AggregatorThread collects events
  DispatcherThread routes to ScorerThread
  ScorerThread scores suspicious file creation burst
  MitigationThread terminates WINWORD.exe
  Files moved -> macro_defense_quarantine/
  auto_mitigation_completed written to macro_defense_security_log.jsonl
Testing
  Ransomware simulator encrypts files in a target directory using AES-CBC, creates ransom notes, and supports decryption and clean up flags to restore the     environment after testing.
  Macro attack is a VBA script that creates mass .txt files across Desktop, Documents, and Pictures when executed via a Word document

Security Notes
  The ransomware simulator and macro attacks scripts are non-malicious test artifacts; they do not extract data, connect to external servers, or cause permanent damage
  All detection and response logic was tested on a dedicated dummy laptop isolated from production systems
  Safe paths have been included in the ransomware antivirus whitelist to prevent false positives

License
  For academic use only - University of North Texas Capstone, Spring 2026

