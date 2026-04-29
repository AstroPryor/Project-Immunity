#!/usr/bin/env python3
import os
import math
import time
import shutil
import argparse
import logging
import threading
from pathlib import Path
from collections import defaultdict
from datetime import datetime
try: 
    import psutil # process monitoring
except ImportError:
    psutil = None
from watchdog.observers import Observer # system monitoring
from watchdog.events import FileSystemEventHandler # file system event handling

# logging setup; logs to file with INFO level, console shows only CRITICAL alerts to keep it clean

root_logger = logging.getLogger()
if not root_logger.hasHandlers(): # configure logging only if it hasn't been configured yet
    logging.basicConfig( # configure basic logging to file
        level=logging.INFO,  # set logging level to INFO
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler('ransomware_antivirus_logs.log')]
    )

    console_handler = logging.StreamHandler() # console handler; keeps console clean
    console_handler.setLevel(logging.CRITICAL)  # shows only critical alerts
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')) # logging format
    root_logger.addHandler(console_handler) # add console handler to root logger

# main ransomware detection class with multiple detection methods, real-time monitoring using watchdog, response functions for quarantining and killing, and threading support for GUI integration

class RansomwareDetector:
    # class-level constants for detection criteria and safe paths
    
    SUSPICIOUS_EXT = ['.encrypted', '.locked', '.crypt', '.enc', '.crypto', '.locky', '.cerber'] # common ransomware file extensions

    RANSOM_NOTES = ['readme.txt', 'decrypt_instructions.txt', 'README_SIMULATION.txt', 'how_to_decrypt.txt', 'restore_files.txt', '_readme.txt'] # common ransom note filenames

    SAFE_PATHS = [
        # safe Python directories
        'site-packages', 'venv', 'env', '.venv','python3.', 'pip', 'distlib', 'pygments',
        # safe ransomware antivirus directories
        'ransomware_antivirus_quarantine', 'ransomware_antivirus_backup', 'ransomware_antivirus_logs.log', 'ransomware_antivirus.py',
        # safe teammate antivirus directories
        'macro_defense_mitigation_report', 'macro_defense_quarantine', 'macro_defense_security_log'
        ]

    MALWARE_PATTERNS = [ # encryption patterns to detect ransomware scripts
        # AES imports and usage
        b'from Crypto.Cipher import AES', b'from cryptography.hazmat', # common AES imports from popular libraries
        b'AES.new(', b'AES.MODE_CBC', b'AES.MODE_GCM', b'AES.MODE_CTR', b'AES.MODE_EAX', # common AES usage patterns for creating cipher objects and specifying modes
        b'cipher.encrypt(', b'cipher.decrypt(', # common AES encryption/decryption method calls
        b'get_random_bytes(', b'os.urandom(',   # key/IV generation
        b'base64.b64encode(', b'base64.b64decode(', # common encoding/decoding patterns for encrypted data
        # general ransomware patterns
        b'encrypt', b'ransom', b'decrypt_key', # encryption operations, ransom-related code, decryption keys
        b'bitcoin', b'payment', b'.encrypted', # payment instructions,creating encrypted files
        b'readme.txt', b'recursive', b'os.walk', # creating ransom note, recursive file operations, mass file traversal
        b'shutil', b'[::-1]', # file manipulation, string/byte reversal
    ]
    
    def __init__(self, watch_paths, time_window=5, threshold=3, quarantine_dir="./ransomware_antivirus_quarantine", backup_dir="./ransomware_antivirus_backup"): # initialize detector with monitoring parameters

        self.watch_paths = [p for p in watch_paths if os.path.exists(p)] # valid paths only
        if not self.watch_paths:
            raise ValueError("No valid paths to monitor")
        
        self.time_window = max(3, time_window) # set minimum time window to 3 seconds to avoid false positives; can change to suit environment
        self.threshold = max(3, threshold) # set minimum threshold to 3 to avoid false positives; can threshold change to suit environment

        self.quarantine_dir = Path(quarantine_dir) # if quarantine directory doesn't exist, create it
        self.quarantine_dir.mkdir(parents=True, exist_ok=True) # quarantine directory for isolating malicious scripts
        self.backup_dir = Path(backup_dir) # if backup directory doesn't exist, create it
        self.backup_dir.mkdir(parents=True, exist_ok=True) # backup directory for safe copies of files before quarantine

        self.file_changes = defaultdict(list) # track file changes: {file_path: [timestamp1, timestamp2, ...]}
        self.flagged_files = [] # list of files flagged as suspicious
        self.killed_processes = [] # list of malware processes that were terminated
        self.detected_scripts = set() # set of detected malicious scripts found by initial scan

        self.observer = Observer() # watchdog observer for monitoring file system changes

        self.monitor_thread = None # thread for running in GUI; allows graceful shutdown
        self.running = False # flag to control thread execution in GUI

    # detection functions

    def calculate_entropy(self, data): # calculate Shannon entropy of data to assess randomness; helper method for is_high_entropy; returns entropy value (higher means more random, which is common in encrypted files)
        if not data: # empty data has zero entropy
            return 0.0
        
        byte_counts = [0] * 256 # count occurrences of each byte value (0-255); think of indexes as byte values
        for byte in data: # count each byte in the data
            byte_counts[byte] += 1 # increment count for this byte value; i.e. byte value 65 (ASCII 'A') increments byte_counts[65]
        
        entropy = 0.0 # initialize entropy
        data_len = len(data) # total number of bytes
        for count in byte_counts: # loop through each byte count
            if count > 0: # only consider bytes that appear in the data
                probability = count / data_len  # calculate probability of this byte by dividing count by total bytes
                entropy -= probability * math.log2(probability) # Shannon entropy formula; sum of -p * log2(p) for each byte
        
        return entropy

    def is_suspicious_file(self, file_path): # combines extension and entropy checks to determine if a file is suspicious; returns True if file is likely encrypted or malicious
        file_path = Path(file_path)
        file_str = str(file_path)

        if str(self.backup_dir.resolve()) in str(Path(file_str).resolve()): # ignore files in backup directory
            return False
        if str(self.quarantine_dir.resolve()) in str(Path(file_str).resolve()): # ignore files in quarantine directory
            return False
        if not any(str(file_path).endswith(ext) for ext in self.SUSPICIOUS_EXT): # check 1: suspicious extension
            return False
        return self.is_high_entropy(file_path) # check 2: high entropy content
    
    def is_high_entropy(self, file_path): # check if file has high entropy; calls calculate_entropy on a sample of the file content; returns True if entropy exceeds threshold
        try:
            with open(file_path, 'rb') as f: # read first 8192 from any size file
                sample = f.read(8192)
            if not sample: # empty files are not suspicious
                return False
            return self.calculate_entropy(sample) > 7.5 # threshold for high entropy
        except (PermissionError, OSError, IOError): # if file can't be read, assume it's not suspicious to avoid false positive
            return False

    def check_for_ransom_note(self, directory): # check 3: check for known ransom note files in a directory
        directory = Path(directory)
        found_notes = []
        
        for note_name in self.RANSOM_NOTES: # checking against RANSOM_NOTES list
            note_path = directory / note_name
            if note_path.exists():
                found_notes.append(str(note_path))
        
        return found_notes

    def find_suspicious_scripts(self): # check 4: scan watched directories for Python scripts with malware-like patterns
        suspicious = []

        WHITELIST = ['ransomware_antivirus.py'] # known safe scripts to ignore

        for watch_path in self.watch_paths: # searching each watched path
            try:
                for py_file in Path(watch_path).rglob('*.py'): # look for .py files with rglob
                    if len(py_file.parts) - len(Path(watch_path).parts) > 4: # skip files more than 4 levels deep
                        continue
                    if py_file.name in WHITELIST: # skip whitelisted scripts
                        continue
                    if any(safe_path in str(py_file) for safe_path in self.SAFE_PATHS): # skip known safe paths
                        continue
                    try:
                        with open(py_file, 'rb') as f: # read file content in binary mode
                            content = f.read()

                        matches = sum(1 for pattern in self.MALWARE_PATTERNS if pattern in content) # count how many malware patterns are found in the script content

                        if matches >= 3: # threshold for suspicion
                            suspicious.append({'path': str(py_file), 'matches': matches}) # record suspicious script

                    except (PermissionError, OSError): # skip unreadable files
                        continue
            except (PermissionError, OSError): # skip unreadable directories
                continue
        
        return suspicious

    # response functions

    def quarantine_file(self, file_path): # move a malicious file to the quarantine directory
        try:
            file_path = Path(file_path) # ensure Path object
            if not file_path.exists():
                return False, "File not found"
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S") # timestamp for quarantine folder
            
            backup_subdir = self.backup_dir / timestamp # create unique subdirectory in backup
            backup_subdir.mkdir(parents=True, exist_ok=True)
            
            backup_dest = backup_subdir / (file_path.stem + "_backup" + file_path.suffix) # destination path in backup
            shutil.copy2(str(file_path), str(backup_dest)) # create backup copy of the file before quarantine
            logging.info(f"Backup created: {file_path} -> {backup_dest}") # log backup action

            quarantine_subdir = self.quarantine_dir / timestamp # create unique subdirectory in quarantine
            quarantine_subdir.mkdir(parents=True, exist_ok=True)
            
            dest = quarantine_subdir / file_path.name # destination path in quarantine
            shutil.move(str(file_path), str(dest)) # move the file to quarantine subdirectory
            
            logging.info(f"Quarantined: {file_path} -> {dest}") # log quarantine action
            print(f"  Quarantined: {file_path.name} -> {dest}") # print quarantine action to console

            return True, "Quarantined successfully"
        except Exception as e:
            return False, str(e)

    def quarantine_script(self, script_path): # backwards-compatible method for quarantining scripts; calls quarantine_file internally
        return self.quarantine_file(script_path)

    def find_and_kill_malware_process(self, script_path): # find and terminate processes running a specific malicious script
        if not psutil:
            return []  # psutil not available
        
        script_path = str(Path(script_path).resolve()) # absolute path of the script
        killed = [] # list of killed processes
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']): # iterate over all processes
                try:
                    cmdline = proc.info['cmdline'] # get command line arguments
                    if not cmdline: # some system processes may have empty cmdline
                        continue
                    

                    script_filename = Path(script_path).name # get script filename
                    if any(script_path in arg or script_filename in arg for arg in cmdline): # check if script is in command line or filename matches
                        proc.terminate() # send terminate signal
                        proc.wait(timeout=3)  # wait 3 seconds
                        
                        killed.append({'pid': proc.info['pid'], 'name': proc.info['name'], 'script': script_path}) # record killed process to dictionary
                        
                        logging.critical(f"Killed process: {proc.info['name']} (PID: {proc.info['pid']}) running {Path(script_path).name}") # log termination
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired): # process ended or access denied
                    continue
        except Exception as e: # catch-all for unexpected errors
            logging.error(f"Error killing malware processes: {e}")
        
        return killed

    def _kill_running_malware(self):
        if not psutil:
            return
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']): # iterate over all processes to find running malcious scripts
            try:
                cmdline = proc.info['cmdline']
                if not cmdline:
                    continue
                for arg in cmdline:
                    if not arg.endswith('.py'): # only check python scripts
                        continue
                    if any (safe_path in arg for safe_path in self.SAFE_PATHS): # skip known safe paths
                        continue
                    try:
                        with open(arg, 'rb')as f: # read script content
                            content = f.read()
                        matches = sum(1 for pattern in self.MALWARE_PATTERNS if pattern in content) # count malware patterns in script
                        
                        if matches >= 3: # if script is suspicious, kill the process
                            self.detected_scripts.add(arg) # add to detected scripts set
                            killed = self.find_and_kill_malware_process(arg) # kill the process running this script
                            if killed:
                                for proc in killed:
                                    logging.critical(f"Killed process: {proc['name']} (PID: {proc['pid']})")
                                    self.killed_processes.append(proc)
                            self.quarantine_script(arg) # quarantine the script after killing
                    except (PermissionError, OSError, FileNotFoundError): # if script can't be read, skip it
                        continue
            except (psutil.NoSuchProcess, psutil.AccessDenied): # if process ended or access denied, skip it
                continue

    # scanning function

    def initial_scan(self): # perform an initial scan of watched directories for threats; ensures nothing is missed
        ransom_notes_found = [] # list to store found ransom notes
        suspicious_files_found = [] # list to store found suspicious files
        
        print("\nScanning for threats")
        
        for watch_path in self.watch_paths: # scan each watched path for ransom notes and suspicious files
            watch_path = Path(watch_path) # ensure Path object
            ransom_notes = self.check_for_ransom_note(watch_path) # scan for ransom notes
            if ransom_notes: # if any ransom notes found, log them
                for note in ransom_notes:
                    ransom_notes_found.append(note)
                    logging.warning(f"Ransom Note Found: {note}")
            try: # scan for suspicious files
                for file_path in watch_path.rglob('*'): # rglob to find all files in directory
                    if any(safe_path in str(file_path) for safe_path in self.SAFE_PATHS): # skip safe paths
                        continue
                    if file_path.is_file(): # only check files
                        if self.is_suspicious_file(file_path): # check if file is suspicious
                            suspicious_files_found.append(str(file_path))
                            self.flagged_files.append(str(file_path))
                            logging.warning(f"Suspicious file: {file_path}")
                            self.quarantine_file(str(file_path)) # quarantine any suspicious files found during initial scan
            except (PermissionError, OSError):
                pass

        suspicious_scripts = self.find_suspicious_scripts() # scan for malicious scripts
        
        total = len(ransom_notes_found) + len(suspicious_files_found) + len(suspicious_scripts) # total threats found
        if total > 0:
            print(f"  Found {total} suspicious file(s)")
        else:
            print(f"  No threats found")
        
        return ransom_notes_found, suspicious_files_found, suspicious_scripts

    # Watchdog event handlers for real-time monitoring

    def on_modified(self, event): # callback for file modification events; watchdog detector
        if event.is_directory: # ignore directory modifications
            return 
        
        file_path = event.src_path # get modified file path
        if any(safe_path in file_path for safe_path in self.SAFE_PATHS): # skip known safe paths
            return
        
        current_time = time.time()
        
        self.file_changes[file_path].append(current_time) # record modification timestamp
        
        self.file_changes[file_path] = [ # keep only recent timestamps within time window
            t for t in self.file_changes[file_path]
            if current_time - t <= self.time_window
        ]
        
        if len(self.file_changes[file_path]) >= self.threshold: # if modifications exceed threshold within time window
            if file_path not in self.flagged_files:
                self.flagged_files.append(file_path)
                logging.critical(f"Alert: Rapid modifications detected on {file_path}")
                self.quarantine_file(file_path) # quarantine the file if rapid modifications detected
                
                for script_path in list(self.detected_scripts): # kill any already-detected scripts
                    killed = self.find_and_kill_malware_process(script_path)
                    if killed:
                        for proc in killed:
                            logging.critical(f"Killed process: {proc['name']} (PID: {proc['pid']})")
                            self.killed_processes.append(proc)
                        self.detected_scripts.discard(script_path) # remove from detected scripts since we took action

                suspicious = self.find_suspicious_scripts() # scan for new scripts not found yet and add to detected_scripts
                for script in suspicious:
                    self.detected_scripts.add(script['path'])
                    killed = self.find_and_kill_malware_process(script['path'])
                    if killed:
                        for proc in killed:
                            logging.critical(f"Killed process: {proc['name']} (PID: {proc['pid']})")
                            self.killed_processes.append(proc)
                    self.quarantine_script(script['path'])

            elif self.is_suspicious_file(Path(file_path)): # check if modified file is suspicious (encrypted)
                if file_path not in self.flagged_files:
                    self.flagged_files.append(file_path)
                    logging.warning(f"Suspicious file modified: {file_path}")
                    self.quarantine_file(file_path) # quarantine file if it becomes suspicious after modification
                    
                    for script_path in list(self.detected_scripts): # kill any already-detected scripts
                        killed = self.find_and_kill_malware_process(script_path)
                        if killed:
                            for proc in killed:
                                logging.critical(f"Killed process: {proc['name']} (PID: {proc['pid']})")
                                self.killed_processes.append(proc)
                            self.detected_scripts.discard(script_path) # remove from detected scripts since we took action

                    suspicious = self.find_suspicious_scripts() # scan for new scripts not found yet and add to detected_scripts
                    for script in suspicious:
                        self.detected_scripts.add(script['path'])
                        killed = self.find_and_kill_malware_process(script['path'])
                        if killed:
                            for proc in killed:
                                logging.critical(f"Killed process: {proc['name']} (PID: {proc['pid']})")
                                self.killed_processes.append(proc)
                        self.quarantine_script(script['path'])

    def on_created(self, event): # callback for file creation events; watchdog detector
        if event.is_directory: # ignore directory creations
            return
        
        file_path = Path(event.src_path) # get created file path
        
        if file_path.name in self.RANSOM_NOTES: # check if new file is a ransom note
            if any(safe_path in str(file_path) for safe_path in self.SAFE_PATHS): # skip known safe paths
                return
            logging.critical(f"Ransom note created: {file_path}")
            if str(file_path) not in self.flagged_files: # add to flagged files
                self.flagged_files.append(str(file_path))
            
            for script_path in list(self.detected_scripts): # kill any already-detected scripts
                killed = self.find_and_kill_malware_process(script_path)
                if killed:
                    for proc in killed:
                        logging.critical(f"Killed process: {proc['name']} (PID: {proc['pid']})")
                        self.killed_processes.append(proc)
                    self.detected_scripts.discard(script_path) # remove from detected scripts since we took action

            suspicious = self.find_suspicious_scripts() # scan for new scripts not found yet and add to detected_scripts
            for script in suspicious:
                self.detected_scripts.add(script['path'])
                killed = self.find_and_kill_malware_process(script['path'])
                if killed:
                    for proc in killed:
                        logging.critical(f"Killed process: {proc['name']} (PID: {proc['pid']})")
                        self.killed_processes.append(proc)
                self.quarantine_script(script['path'])
        
        if file_path.suffix == '.py': # check if new file is a Python script       
            if any(safe_path in str(file_path) for safe_path in self.SAFE_PATHS): # skip known safe paths
                return
            
            time.sleep(0.1)
            try: # read and analyze the script content
                with open(file_path, 'rb') as f: # read script content in bytes
                    content = f.read()
                
                matches = sum(1 for pattern in self.MALWARE_PATTERNS if pattern in content) # count matching malware patterns in the script content

                if matches >= 3:
                    logging.critical(f"Malicious script created: {file_path} ({matches} malware patterns)") # log malicious script creation with pattern match count
                    
                    killed = self.find_and_kill_malware_process(str(file_path)) # kill any process running this script
                    if killed: # if any processes were killed, log them
                        for proc in killed:
                            logging.critical(f"Killed process: {proc['name']} (PID: {proc['pid']})")
                            self.killed_processes.append(proc)
                    
                    success, msg = self.quarantine_script(str(file_path)) # after killing, quarantine the script
                    if success:
                        logging.critical(f"Quarantined: {file_path.name}")
                    else:
                        logging.error(f"Quarantine failed: {file_path.name} - {msg}")
            except Exception:
                pass
        
        if self.is_suspicious_file(file_path): # check if new file is encrypted or has suspicious extension
            logging.warning(f"Suspicious file created: {file_path}")
            if str(file_path) not in self.flagged_files: # add to flagged files
                self.flagged_files.append(str(file_path))
                self.quarantine_file(str(file_path)) # quarantine file if it is suspicious upon creation

    def on_moved(self, event): # callback for file rename/moved events; watchdog detector
        if event.is_directory: # ignore directory moves
            return
        
        dest_path = Path(event.dest_path) # get the new filename after rename/move

        if any(safe_path in str(dest_path) for safe_path in self.SAFE_PATHS): # ignore safe paths
            return

        logging.info(f"File renamed/moved: {event.src_path} -> {dest_path}")
        
        if self.is_suspicious_file(dest_path): # check if new file is encrypted or has suspicious extension
            logging.warning(f"Suspicious file renamed/moved: {dest_path}")
            if str(dest_path) not in self.flagged_files: # add to flagged files
                self.flagged_files.append(str(dest_path))
                self.quarantine_file(str(dest_path)) # quarantine file if it is suspicious upon rename/move
                
                for script_path in list(self.detected_scripts): # kill any already-detected scripts
                    killed = self.find_and_kill_malware_process(script_path)
                    if killed:
                        for proc in killed:
                            logging.critical(f"Killed process: {proc['name']} (PID: {proc['pid']})")
                            self.killed_processes.append(proc)
                        self.detected_scripts.discard(script_path) # remove from detected scripts since we took action

                suspicious = self.find_suspicious_scripts() # scan for new scripts not found yet and add to detected_scripts
                for script in suspicious:
                    self.detected_scripts.add(script['path'])
                    killed = self.find_and_kill_malware_process(script['path'])
                    if killed:
                        for proc in killed:
                            logging.critical(f"Killed process: {proc['name']} (PID: {proc['pid']})")
                            self.killed_processes.append(proc)
                    self.quarantine_script(script['path'])

    # threading functions for GUI integration

    def start_threaded(self): # start the antivirus via _run_monitoring in a separate daemon thread
        if self.running: # if already running, don't start another thread
            logging.warning("Antivirus is already running in a thread")
            return False
        
        self.monitor_thread = threading.Thread( # create a new thread to run the monitoring loop
            target=self._run_monitoring,
            daemon=True,
            name="RansomwareDetector-Thread"
        )
        
        self.running = True # set running flag to True before starting the thread; allows the monitoring loop to run
        self.monitor_thread.start()
        logging.info("Antivirus started in background thread")
        return True
    
    def _run_monitoring(self): # internal method that starts the watchdog observer and runs the initial scan concurrently
        try:
            self._kill_running_malware() # kill any running malware processes before starting the initial scan to ensure we can quarantine scripts without interference
            self.start() # start real-time monitoring with watchdog observer
            
            scan_thread = threading.Thread(# run initial scan concurrently in a separate thread
                target=self._run_initial_scan,
                daemon=True,
                name="InitialScanThread")
            scan_thread.start()

            while self.running: # keep the thread alive until stop is called
                time.sleep(0.1)
                
        except Exception as e: # catch-all for any unexpected errors in the monitoring thread
            logging.error(f"Error in monitoring thread: {e}")
            self.running = False
        finally:
            self.stop()

    def _run_initial_scan(self): # internal method to run initial_scan in a separate thread and populates detected_scripts
        try:
            ransom_notes_found, suspicious_files_found, suspicious_scripts = self.initial_scan() # run initial scan
            if suspicious_scripts:
                for script in suspicious_scripts:
                    self.detected_scripts.add(script['path']) # store path before quarantine for watchdog callbacks
                    killed = self.find_and_kill_malware_process(script['path'])
                    if killed:
                        for proc in killed:
                            self.killed_processes.append(proc)
                    self.quarantine_script(script['path'])
        except Exception as e:
            logging.error(f"Error in initial scan thread: {e}")

    def stop_threaded(self): # stop the antivirus thread gracefully
        if not self.running: # if not running, nothing to stop
            logging.warning("Antivirus is not running")
            return False
        
        self.running = False # signal the thread to stop; the monitoring loop will check this flag and exit gracefully
        self.stop()

        if self.monitor_thread and self.monitor_thread.is_alive(): # wait for the monitoring thread to finish
            self.monitor_thread.join(timeout=2.0)
        
        logging.info("Threaded antivirus stopped")
        return True
    
    def is_running(self): # check if the antivirus is currently running in a thread; returns True if running
        return self.running

    # Watchdog observer control functions

    def start(self): # start monitoring with watchdog observer
        event_handler = FileSystemEventHandler() # create event handler
        event_handler.on_modified = self.on_modified # assign callbacks
        event_handler.on_created = self.on_created # assign callbacks
        event_handler.on_moved = self.on_moved # assign callbacks
    
        for path in self.watch_paths: # schedule monitoring on each watched path
            self.observer.schedule(event_handler, path, recursive=True)
        
        self.observer.start() # start the observer thread
        logging.info(f"Monitoring started on: {', '.join(self.watch_paths)}")

    def stop(self): # stop monitoring and shut down observer thread
        self.observer.stop()
        self.observer.join()  # Wait for observer thread to finish
        logging.info("Monitoring stopped")

# CLI and main function

def main(): # main function to parse arguments and run the detector
    parser = argparse.ArgumentParser( # argument parser setup
        description='Ransomware Antivirus - Monitor and protect against ransomware' 
    )
    default_paths = [str(Path.home() / 'Downloads'), str(Path.home() / 'Documents')] # default paths to monitor: Downloads, Documents
    parser.add_argument('paths', nargs='*', default=default_paths,
                       help='Paths to monitor (default: Downloads, Documents)') # paths argument
    parser.add_argument('--window', type=int, default=5,
                       help='Time window in seconds (default: 5)') # --window argument
    parser.add_argument('--threshold', type=int, default=3,
                       help='Number of changes to trigger alert (default: 3)') # --threshold argument
    parser.add_argument('--quarantine', type=str, default='./ransomware_antivirus_quarantine',
                       help='Quarantine directory (default: ./ransomware_antivirus_quarantine)') # quarantine directory argument
    parser.add_argument('--scan-only', action='store_true',
                       help='Run initial scan only, then exit') # --scan-only argument
    
    args = parser.parse_args() # parse command-line arguments
    
    if args.scan_only: # scan-only mode: perform initial scan and exit (--scan-only)
        print("\nThreat Scan Mode")
        print(f"Scanning: {', '.join(args.paths)}\n") # print scanned paths
        
        for p in args.paths: # create watched directories if they don't exist (avoid errors)
            os.makedirs(p, exist_ok=True)
        
        detector = RansomwareDetector(args.paths, args.window, args.threshold, args.quarantine) # create detector instance
        ransom_notes_found, suspicious_files_found, suspicious_scripts = detector.initial_scan() # run initial scan
        
        encrypted_count = 0
        for path in args.paths: # count encrypted files found
            path_obj = Path(path)
            for ext in detector.SUSPICIOUS_EXT:
                encrypted_count += len(list(path_obj.rglob(f'*{ext}'))) # count files with suspicious extensions
            
        print("\nScan Report") # print report
        if suspicious_scripts: # if any suspicious scripts found, list them
            print(f"\nMalicious scripts found: {len(suspicious_scripts)}")
            for script in suspicious_scripts:
                print(f"  - {script['path']} ({script['matches']} malware patterns)")
        else:
            print("\nNo malicious scripts found")
        if encrypted_count > 0: # if any encrypted files found, list them
            print(f"\nEncrypted files found: {encrypted_count}")
        else:
            print("\nNo encrypted files found")
        if ransom_notes_found: # if any ransom notes found, list them
            print(f"\nRansom notes found: {len(ransom_notes_found)}")
        else:
            print("\nNo ransom notes found")
        if suspicious_files_found: # if any suspicious files found, list them
            print(f"\nSuspicious files found: {len(suspicious_files_found)}")
        else:
            print("\nNo suspicious files found")
        return

    for p in args.paths: # monitoring mode: watch specified directories for ransomware activity (default mode)
        os.makedirs(p, exist_ok=True)

    detector = RansomwareDetector(args.paths, args.window, args.threshold, args.quarantine) # create detector instance
    
    print("\nRansomware Antivirus")
    print(f"Monitoring: {', '.join(detector.watch_paths)}")
    print(f"Threshold: {args.threshold} files in {args.window}s")
    
    ransom_notes_found, suspicious_files_found, suspicious_scripts = detector.initial_scan() # run initial scan
    
    if suspicious_scripts: # if any suspicious scripts found, list them and take action
        print(f"\nMalicious scripts found: {len(suspicious_scripts)}")
        for script in suspicious_scripts:
            print(f"  - {script['path']} ({script['matches']} malware patterns)")

            killed = detector.find_and_kill_malware_process(script['path']) # kill any process running this script
            if killed:
                for proc in killed:
                    print(f"  Killed process: {proc['name']} (PID: {proc['pid']})")
                    detector.killed_processes.append(proc)
            
            success, msg = detector.quarantine_script(script['path']) # after killing, quarantine the script
            if not success:
                print(f"  Quarantine failed: {msg}")
    else:
        print("\nNo malicious scripts found")
    detector.start() # start real time monitoring
    print("\nPress Ctrl+C to stop\n")
    
    try: # start main loop; will monitor until interrupted
        while True:
            time.sleep(0.1)
            
    except KeyboardInterrupt: # handle Ctrl+C gracefully
        print("\n\nExiting Ransomware Antivirus")
        detector.stop()
        
        print(f"\nFlagged files: {len(detector.flagged_files)}") # print summary once killed
        print(f"Killed processes: {len(detector.killed_processes)}")

        if detector.killed_processes: # if any malware processes were killed, list them
            print("\nKilled malware processes:")
            for proc in detector.killed_processes:
                script_name = Path(proc['script']).name if proc['script'] else "unknown"
                print(f"  - {proc['name']} (PID: {proc['pid']}) -> {script_name}")

if __name__ == "__main__":
    main()