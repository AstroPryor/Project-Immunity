import os
import sys
import subprocess
import tkinter as tk
import ttkbootstrap as ttk
import threading

class MainWindow:
    def __init__(self, cfg, runner):
        self.cfg = cfg
        self.runner = runner

        self.root = ttk.Window(themename="darkly")
        self.root.title("Project Immunity")
        self.root.geometry("900x600")

        # track position in ransomware antivirus log
        self._last_ransomware_antivirus_log_position = 0
        self._last_macrovirus_antivirus_log_position = 0

        self._build_ui()

    def _build_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        left = ttk.Frame(main_frame)
        left.pack(side="left", fill="y", padx=10)

        right = ttk.Frame(main_frame)
        right.pack(side="right", fill="both", expand=True, padx=10)

        ttk.Label(right, text="Ransomware Antivirus Logs:").pack(anchor="w")
        self.log_text = tk.Text(right, wrap="word", height=15)
        self.log_text.pack(fill="both", expand=True, pady=(0, 5))

        ttk.Label(right, text="Macrovirus Antivirus Logs:").pack(anchor="w")
        self.macro_log_text = tk.Text(right, wrap="word", height=15)
        self.macro_log_text.pack(fill="both", expand=True)

        btn_start = ttk.Button(
            left,
            text="Start Antivirus",
            command=self._start_antivirus,
            width=20
        )
        btn_start.pack(pady=10)

        btn_stop = ttk.Button(
            left,
            text="Stop Current",
            command=self._stop_current,
            width=20
        )
        btn_stop.pack(pady=10)

        btn_ransomware_quarantine = ttk.Button(
            left,
            text="Open Ransomware Quarantine Folder",
            command=self._open_ransomware_quarantine,
            width=20
        )
        btn_ransomware_quarantine.pack(pady=10)

        btn_macrovirus_quarantine = ttk.Button(
            left,
            text="Open Macrovirus Quarantine Folder",
            command=self._open_macrovirus_quarantine,
            width=20
        )
        btn_macrovirus_quarantine.pack(pady=10)

        btn_ransomware_logs = ttk.Button(
            left,
            text="Open Ransomware Antivirus Logs",
            command=self._open_ransomware_antivirus_logs,
            width=20
        )
        btn_ransomware_logs.pack(pady=10)

        btn_macrovirus_logs = ttk.Button(
            left,
            text="Open Macrovirus Antivirus Logs",
            command=self._open_macrovirus_antivirus_logs,
            width=20
        )
        btn_macrovirus_logs.pack(pady=10)

        self.status_label = ttk.Label(left, text="Status: Idle")
        self.status_label.pack(pady=20)

    def run(self):
        self.root.mainloop()

    def _append_macrovirus_antivirus_log(self,text):
        self.macro_log_text.insert("end", text + "\n")
        self.macro_log_text.see("end")

    def _append_ransomware_antivirus_log(self, text):
        self.log_text.insert("end", text + "\n")
        self.log_text.see("end")

    def _start_antivirus(self):
        self.status_label.config(text="Status: Running")

        thread = threading.Thread(target=self._run_antivirus_task)
        thread.daemon = True
        thread.start()

    def _run_antivirus_task(self):
        try:
            rc, out, err = self.runner.start_antivirus()
            self._append_ransomware_antivirus_log(out)
            self.status_label.config(text="Status: Running")
            self.root.after(0, self._start_ransomware_antivirus_log_polling)
            self.root.after(0, self._start_macrovirus_antivirus_log_polling)
        except Exception as e:
            self._append_ransomware_antivirus_log(str(e))
            self.status_label.config(text="Error running antivirus")

    def _stop_current(self):
        try:
            self.runner.stop()
            self.status_label.config(text="Status: Stopped")
        except Exception as e:
            self._append_ransomware_antivirus_log(f"Error stopping antivirus: {e}")
            self._append_ransomware_antivirus_log("Stopped")

    def _open_ransomware_quarantine(self):
        path = os.path.join(os.getcwd(), "ransomware_antivirus_quarantine")
        os.makedirs(path, exist_ok=True)

        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            self._append_ransomware_antivirus_log(f"Failed to open folder: {e}")

    def _open_macrovirus_quarantine(self):
        path = os.path.join(os.getcwd(), "macro_defense_quarantine")
        os.makedirs(path, exist_ok=True)

        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            self._append_macrovirus_antivirus_log(f"Failed to open folder: {e}")

    def _open_ransomware_antivirus_logs(self):
        path = os.path.join(os.getcwd(), "ransomware_antivirus_logs.log")
        if not os.path.exists(path):
            self._append_ransomware_antivirus_log("Ransomware antivirus log not found")
            return
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            self._append_ransomware_antivirus_log(f"Failed to open log: {e}")

    def _open_macrovirus_antivirus_logs(self):
        path = os.path.join(os.getcwd(), "macro_defense_security_log.jsonl")
        if not os.path.exists(path):
            self._append_macrovirus_antivirus_log("Macrovirus antivirus log not found")
            return
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as e:
            self._append_macrovirus_antivirus_log(f"Failed to open log: {e}")

    def _start_ransomware_antivirus_log_polling(self):
        self._last_ransomware_antivirus_log_position = 0
        self._poll_ransomware_antivirus_log()
    
    def _poll_ransomware_antivirus_log(self):
        try:
            log_path = os.path.join(os.getcwd(), "ransomware_antivirus_logs.log")
            if os.path.exists(log_path):
                with open(log_path, "r") as f:
                    f.seek(self._last_ransomware_antivirus_log_position)
                    new_lines = f.read()
                    if new_lines:
                        self._append_ransomware_antivirus_log(new_lines.strip())
                    self._last_ransomware_antivirus_log_position = f.tell()
        except Exception as e:
            self._append_ransomware_antivirus_log(f"Log polling error: {e}")
        
        if self.runner.detector and self.runner.detector.is_running():
            self.root.after(1000, self._poll_ransomware_antivirus_log)

    def _start_macrovirus_antivirus_log_polling(self):
        self._last_macrovirus_antivirus_log_position = 0
        self._poll_macrovirus_antivirus_log()
    
    def _poll_macrovirus_antivirus_log(self):
        try:
            log_path = os.path.join(os.getcwd(), "macro_defense_security_log.jsonl")
            if os.path.exists(log_path):
                with open(log_path, "r") as f:
                    f.seek(self._last_macrovirus_antivirus_log_position)
                    new_lines = f.read()
                    if new_lines:
                        self._append_macrovirus_antivirus_log(new_lines.strip())
                    self._last_macrovirus_antivirus_log_position = f.tell()
        except Exception as e:
            self._append_macrovirus_antivirus_log(f"Log polling error: {e}")
        
        if self.runner.monitor_proc and self.runner.monitor_proc.poll() is None:
            self.root.after(1000, self._poll_macrovirus_antivirus_log)
