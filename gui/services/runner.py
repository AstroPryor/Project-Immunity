import subprocess
import sys
import time
import os
import logging
from pathlib import Path
from ransomware_antivirus import RansomwareDetector

class Runner:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.logger = logging.getLogger("immunity.runner")
        self.logger.propagate = False
        self.detector = None
        self.monitor_proc = None

    def start_antivirus(self):
        # ransomware antivirus start; watches current directory, Downloads, Documents
        watch_paths = [str(Path.home() / 'Downloads'), str(Path.home() / 'Documents')]
        self.detector = RansomwareDetector(watch_paths)
        self.detector.start_threaded()
        self.logger.info("Ransomware Antivirus Started")

        # macrovirus antivirus start
        monitor_path = os.path.join(os.getcwd(), "monitor.py")
        if os.path.exists(monitor_path):
            if os.name == "posix":
                creationflags = 0
                preexec_fn = os.setsid
            else:
                creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
                preexec_fn = None
            
            self.monitor_proc = subprocess.Popen(
                [sys.executable, monitor_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=creationflags,
                preexec_fn=preexec_fn
            )
            self.logger.info("Macrovirus Antivirus Started")
        else:
            self.logger.warning(f"Monitor script not found at {monitor_path}")
        return 0, "Started Antivirus", ""
    
    def stop(self):
        # stop ransomware antivirus
        if self.detector and self.detector.is_running():
            self.detector.stop_threaded()
            self.logger.info("Ransomware Antivirus Stopped")
        self.detector = None

        # stop macrovirus antivirus
        if self.monitor_proc:
            try:
                if os.name == "posix":
                    os.killpg(os.getpgid(self.monitor_proc.pid), 9)
                else:
                    self.monitor_proc.terminate()
                self.logger.info("Macrovirus Antivirus Stopped")
            except Exception:
                pass
            self.monitor_proc = None
