import os
import re
import json
import shutil
import sqlite3
import hashlib
import zipfile
from datetime import datetime

try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
except Exception:
    OLETOOLS_AVAILABLE = False

OFFICE_EXTENSIONS = {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm"}
MACRO_ENABLED_EXTENSIONS = {".docm", ".xlsm", ".pptm"}

SUSPICIOUS_MACRO_KEYWORDS = [
    "AutoOpen", "Document_Open", "Workbook_Open", "Auto_Close",
    "Shell", "CreateObject", "WScript.Shell", "powershell",
    "cmd.exe", "URLDownloadToFile", "WinExec", "Environ",
    "WriteText", "CreateTextFile", "Open ", "Kill ", "MkDir ",
    "FileCopy", "ADODB.Stream", "XMLHTTP", "MSXML2.XMLHTTP",
    "CreateFolder", "SaveAs", "Eval", "Execute"
]

QUARANTINE_DIR = "macro_defense_quarantine"
DB_FILE = "macro_defense_quarantine.db"
REPORT_FILE = "macro_defense_mitigation_report.txt"

EXCLUDED_DIR_NAMES = {
    QUARANTINE_DIR,
    "clean_backups",
    "__pycache__",
    ".git",
    ".idea",
    ".vscode"
}

EXCLUDED_FILE_NAMES = {
    DB_FILE,
    "macro_defense_security_log.jsonl",
    REPORT_FILE
}


def sha256_file(file_path, chunk_size=65536):
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def safe_now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def should_skip_path(path):
    normalized = os.path.normpath(path)
    parts = {part.lower() for part in normalized.split(os.sep) if part}
    if parts.intersection({x.lower() for x in EXCLUDED_DIR_NAMES}):
        return True
    return os.path.basename(normalized).lower() in {x.lower() for x in EXCLUDED_FILE_NAMES}


def is_macro_generated_folder(folder_name):
    if folder_name.lower() in {x.lower() for x in EXCLUDED_DIR_NAMES}:
        return False
    if re.match(r"^folder_\d{1,4}$", folder_name):
        return True

    suspicious_keywords = [
        "maze", "surprise", "mystery", "level", "oops", "whoops",
        "untitled", "backup", "archive", "temp", "data", "new folder",
        "downloads2", "documents2", "config", "cache", "inception"
    ]
    return any(keyword in folder_name.lower() for keyword in suspicious_keywords)


def is_macro_generated_file(file_name, file_path=None):
    if file_name.startswith("~$"):
        return False
    if file_name.lower() in {x.lower() for x in EXCLUDED_FILE_NAMES}:
        return False
    if file_path and should_skip_path(file_path):
        return False

    if re.match(r"^file_\d{1,4}\.txt$", file_name):
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    first_lines = f.read(500)
                    if (
                        "System File - Do Not Delete" in first_lines or
                        "Astro is awesome" in first_lines or
                        "Data File" in first_lines or
                        "test test test" in first_lines
                    ):
                        return True
            except Exception:
                return True
        return True

    if re.match(r"^file\d+\.txt$", file_name):
        if file_path:
            parent_folder = os.path.basename(os.path.dirname(file_path))
            if re.match(r"^folder_\d{1,4}$", parent_folder):
                return True
        return True

    suspicious_keywords = ["gotcha", "surprise", "readme_", "document_", "report_", "notes_", "temp_", "data_", "config_", "log_"]
    return any(keyword in file_name.lower() for keyword in suspicious_keywords)


def is_office_file(file_path):
    if should_skip_path(file_path):
        return False
    base_name = os.path.basename(file_path)
    if base_name.startswith("~$"):
        return False
    _, ext = os.path.splitext(file_path.lower())
    return ext in OFFICE_EXTENSIONS

#scan office files for macro
def scan_office_file(file_path):
    result = {"suspicious": False, "reasons": [], "details": {}}
    _, ext = os.path.splitext(file_path.lower())
    if ext not in OFFICE_EXTENSIONS:
        return result

    try:
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return result

        result["details"]["extension"] = ext

        if ext in MACRO_ENABLED_EXTENSIONS:
            result["reasons"].append("macro_enabled_extension")

        if ext in {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}:
            try:
                with zipfile.ZipFile(file_path, "r") as zf:
                    names = zf.namelist()
                    joined_names = " | ".join(names).lower()
                    if "vbaproject.bin" in joined_names:
                        result["reasons"].append("embedded_vba_project")
                    if "macrosheets" in joined_names:
                        result["reasons"].append("excel_macrosheets_present")
                    if "embeddings/" in joined_names or "oleobject" in joined_names:
                        result["reasons"].append("embedded_object_present")
            except Exception:
                result["reasons"].append("zip_structure_unreadable")

        try:
            with open(file_path, "rb") as f:
                sample = f.read(2 * 1024 * 1024)
            sample_text = sample.decode("latin-1", errors="ignore")
            for keyword in SUSPICIOUS_MACRO_KEYWORDS:
                if keyword.lower() in sample_text.lower():
                    result["reasons"].append(f"suspicious_keyword:{keyword}")
        except Exception:
            result["reasons"].append("raw_content_unreadable")

        if OLETOOLS_AVAILABLE:
            try:
                vbaparser = VBA_Parser(file_path)
                if vbaparser.detect_vba_macros():
                    result["reasons"].append("oletools_detected_vba")
                    for (_, _, _, vba_code) in vbaparser.extract_macros():
                        lowered = vba_code.lower()
                        for keyword in SUSPICIOUS_MACRO_KEYWORDS:
                            if keyword.lower() in lowered:
                                result["reasons"].append(f"oletools_keyword:{keyword}")
                    vbaparser.close()
            except Exception:
                result["reasons"].append("oletools_scan_error")

        unique_reasons = sorted(set(result["reasons"]))
        result["reasons"] = unique_reasons

        score = 0
        for reason in unique_reasons:
            if reason == "macro_enabled_extension":
                score += 2
            elif reason == "embedded_vba_project":
                score += 4
            elif reason.startswith("suspicious_keyword:"):
                score += 2
            elif reason.startswith("oletools_keyword:"):
                score += 3
            elif reason == "oletools_detected_vba":
                score += 4
            elif reason == "excel_macrosheets_present":
                score += 3
            elif reason == "embedded_object_present":
                score += 1

        result["details"]["score"] = score
        result["suspicious"] = score >= 4
        return result

    except Exception as e:
        result["reasons"].append(f"scan_error:{e}")
        return result

#database creation
class ThreatDatabase:
    def __init__(self, db_path=DB_FILE):
        self.db_path = db_path
        self._initialize()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _initialize(self):
        conn = self._connect()
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS quarantine_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT,
                quarantined_path TEXT,
                sha256 TEXT,
                reason TEXT,
                timestamp TEXT
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS clean_backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT,
                backup_path TEXT,
                sha256 TEXT,
                timestamp TEXT
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                target_path TEXT,
                details TEXT,
                timestamp TEXT
            )
        """)

        conn.commit()
        conn.close()

    def add_quarantine_item(self, original_path, quarantined_path, sha256_value, reason):
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO quarantine_items (original_path, quarantined_path, sha256, reason, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (original_path, quarantined_path, sha256_value, reason, safe_now()))
        conn.commit()
        conn.close()

    def add_backup(self, original_path, backup_path, sha256_value):
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO clean_backups (original_path, backup_path, sha256, timestamp)
            VALUES (?, ?, ?, ?)
        """, (original_path, backup_path, sha256_value, safe_now()))
        conn.commit()
        conn.close()

    def get_latest_backup(self, original_path):
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("""
            SELECT backup_path, sha256, timestamp
            FROM clean_backups
            WHERE original_path = ?
            ORDER BY id DESC
            LIMIT 1
        """, (original_path,))
        row = cur.fetchone()
        conn.close()
        return row

    def add_event(self, event_type, target_path, details):
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO security_events (event_type, target_path, details, timestamp)
            VALUES (?, ?, ?, ?)
        """, (event_type, target_path, json.dumps(details), safe_now()))
        conn.commit()
        conn.close()

#backup manager for safe backups if need be
class BackupManager:
    def __init__(self, db, backup_dir="clean_backups"):
        self.db = db
        self.backup_dir = backup_dir
        os.makedirs(self.backup_dir, exist_ok=True)

    def create_clean_backup(self, file_path):
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return None
        try:
            digest = sha256_file(file_path)
            _, ext = os.path.splitext(file_path)
            backup_name = f"{digest}{ext}.bak"
            backup_path = os.path.join(self.backup_dir, backup_name)
            if not os.path.exists(backup_path):
                shutil.copy2(file_path, backup_path)
            self.db.add_backup(file_path, backup_path, digest)
            self.db.add_event("backup_created", file_path, {"backup_path": backup_path, "sha256": digest})
            return backup_path
        except Exception:
            return None

    def restore_latest_backup(self, original_path):
        row = self.db.get_latest_backup(original_path)
        if not row:
            return None

        backup_path, sha256_value, timestamp = row
        if not os.path.exists(backup_path):
            return None

        try:
            parent = os.path.dirname(original_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            shutil.copy2(backup_path, original_path)
            self.db.add_event("backup_restored", original_path, {
                "backup_path": backup_path,
                "sha256": sha256_value,
                "backup_timestamp": timestamp
            })
            return original_path
        except Exception:
            return None


class QuarantineManager:
    def __init__(self, db, quarantine_dir=QUARANTINE_DIR):
        self.db = db
        self.quarantine_dir = quarantine_dir
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def quarantine_file(self, file_path, reason):
        if not os.path.exists(file_path):
            return None

        try:
            file_hash = sha256_file(file_path) if os.path.isfile(file_path) else "DIRECTORY"
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = os.path.basename(file_path)
            quarantined_name = f"{timestamp}__{base_name}"
            quarantined_path = os.path.join(self.quarantine_dir, quarantined_name)
            #!moves files in quarantine folder
            shutil.move(file_path, quarantined_path)
            self.db.add_quarantine_item(file_path, quarantined_path, file_hash, reason)
            self.db.add_event("file_quarantined", file_path, {
                "quarantined_path": quarantined_path,
                "reason": reason,
                "sha256": file_hash
            })
            return quarantined_path
        except Exception:
            return None

#maro mitigatior
class MacroMitigator:
    def __init__(self, target_paths):
        self.target_paths = target_paths if isinstance(target_paths, list) else [target_paths]
        self.db = ThreatDatabase()
        self.backup_manager = BackupManager(self.db)
        self.quarantine_manager = QuarantineManager(self.db)
        self.quarantined_files = []
        self.quarantined_folders = []
        self.restored_files = []

    def scan_for_threats(self):
        print("Scanning for macro attack artifacts and suspicious Office files...\n")
        threats = {
            "suspicious_folders": [],
            "suspicious_files": [],
            "suspicious_office_files": []
        }

        for target_path in self.target_paths:
            if not os.path.exists(target_path):
                print(f"Warning: Path does not exist: {target_path}")
                continue
            if should_skip_path(target_path):
                continue

            print(f"Scanning: {target_path}")
            self._scan_directory(target_path, threats)

        return threats

    def _scan_directory(self, path, threats):
        if should_skip_path(path):
            return

        try:
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if should_skip_path(item_path):
                    continue

                try:
                    if os.path.isdir(item_path):
                        if is_macro_generated_folder(item):
                            threats["suspicious_folders"].append(item_path)
                        self._scan_directory(item_path, threats)

                    elif os.path.isfile(item_path):
                        if is_macro_generated_file(item, item_path):
                            threats["suspicious_files"].append(item_path)
                        elif is_office_file(item_path):
                            office_result = scan_office_file(item_path)
                            if office_result["suspicious"]:
                                threats["suspicious_office_files"].append({
                                    "path": item_path,
                                    "reasons": office_result["reasons"],
                                    "score": office_result["details"].get("score", 0)
                                })
                except PermissionError:
                    continue
                except FileNotFoundError:
                    continue
        except PermissionError:
            print(f"Permission denied: {path}")
        except FileNotFoundError:
            return

    def display_threats(self, threats):
        total = (
            len(threats["suspicious_folders"]) +
            len(threats["suspicious_files"]) +
            len(threats["suspicious_office_files"])
        )

        if total == 0:
            print("\nNo threats detected.\n")
            return False

        print(f"\nALERT: Found {total} suspicious items:\n")

        if threats["suspicious_folders"]:
            print(f"Suspicious Folders ({len(threats['suspicious_folders'])}):")
            for folder in threats["suspicious_folders"][:10]:
                print(f"  - {folder}")

        if threats["suspicious_files"]:
            print(f"\nSuspicious Files ({len(threats['suspicious_files'])}):")
            for file_path in threats["suspicious_files"][:10]:
                print(f"  - {file_path}")

        if threats["suspicious_office_files"]:
            print(f"\nSuspicious Office Files ({len(threats['suspicious_office_files'])}):")
            for item in threats["suspicious_office_files"][:10]:
                print(f"  - {item['path']} | reasons={', '.join(item['reasons'])}")

        print()
        return True

    def quarantine_item(self, item_path, reason):
        if not os.path.exists(item_path):
            return False

        quarantined_path = self.quarantine_manager.quarantine_file(item_path, reason)
        if quarantined_path:
            if os.path.isdir(quarantined_path):
                self.quarantined_folders.append(quarantined_path)
            else:
                self.quarantined_files.append(quarantined_path)
            return True
        return False

    def mitigate(self):
        threats = self.scan_for_threats()
        if not self.display_threats(threats):
            return

        print("Starting mitigation (Quarantine + Restore if possible)...\n")

        for item in threats["suspicious_files"]:
            self.quarantine_item(item, "macro_artifact_file")

        for item in threats["suspicious_folders"]:
            self.quarantine_item(item, "macro_artifact_folder")

        for office_item in threats["suspicious_office_files"]:
            original_path = office_item["path"]
            reason = "suspicious_office_macro:" + ",".join(office_item["reasons"])
            moved = self.quarantine_item(original_path, reason)
            if moved:
                restored = self.backup_manager.restore_latest_backup(original_path)
                if restored:
                    self.restored_files.append(restored)

        self.generate_report()

    def mitigate_noninteractive(self):
        threats = self.scan_for_threats()
        total = (
            len(threats["suspicious_folders"]) +
            len(threats["suspicious_files"]) +
            len(threats["suspicious_office_files"])
        )
        if total == 0:
            return 0, 0, 0

        for item in threats["suspicious_files"]:
            self.quarantine_item(item, "macro_artifact_file")

        for item in threats["suspicious_folders"]:
            self.quarantine_item(item, "macro_artifact_folder")

        for office_item in threats["suspicious_office_files"]:
            original_path = office_item["path"]
            reason = "suspicious_office_macro:" + ",".join(office_item["reasons"])
            moved = self.quarantine_item(original_path, reason)
            if moved:
                restored = self.backup_manager.restore_latest_backup(original_path)
                if restored:
                    self.restored_files.append(restored)

        self.generate_report()
        return len(self.quarantined_files), len(self.quarantined_folders), len(self.restored_files)
    #report generatior for the report files
    def generate_report(self):
        print("\n" + "=" * 60)
        print("MITIGATION REPORT")
        print("=" * 60)
        print(f"Timestamp: {safe_now()}")
        print(f"Quarantined files: {len(self.quarantined_files)}")
        print(f"Quarantined folders: {len(self.quarantined_folders)}")
        print(f"Restored clean backups: {len(self.restored_files)}")
        print("Mitigation complete.")
        print("=" * 60 + "\n")

        with open(REPORT_FILE, "w", encoding="utf-8", errors="replace") as f:
            f.write(f"Mitigation Report - {safe_now()}\n")
            f.write("=" * 60 + "\n")
            f.write(f"Quarantined files: {len(self.quarantined_files)}\n")
            f.write(f"Quarantined folders: {len(self.quarantined_folders)}\n")
            f.write(f"Restored clean backups: {len(self.restored_files)}\n")
            f.write("\nQuarantined items:\n")
            for item in self.quarantined_files + self.quarantined_folders:
                f.write(f"  - {item}\n")
            f.write("\nRestored files:\n")
            for item in self.restored_files:
                f.write(f"  - {item}\n")

        print(f"Detailed report saved to: {REPORT_FILE}")


def get_target_paths():
    user_profile = os.environ.get("USERPROFILE", "")
    target_paths = [
        os.path.join(user_profile, "Desktop"),
        os.path.join(user_profile, "Documents"),
        os.path.join(user_profile, "Pictures"),
        os.path.join(user_profile, "OneDrive", "Desktop"),
        os.path.join(user_profile, "OneDrive", "Documents"),
        os.path.join(user_profile, "OneDrive", "Pictures"),
    ]
    return [path for path in target_paths if os.path.exists(path) and not should_skip_path(path)]


def main():
    print("=" * 60)
    print("MACRO ATTACK MITIGATION TOOL")
    print("=" * 60)
    print()

    target_paths = get_target_paths()
    if not target_paths:
        print("ERROR: Could not find any target directories.")
        return

    print("Will scan the following locations:")
    for path in target_paths:
        print(f"  - {path}")
    print()

    mitigator = MacroMitigator(target_paths)
    threats = mitigator.scan_for_threats()
    found_threats = mitigator.display_threats(threats)

    if not found_threats:
        return

    print("WARNING: Suspicious items will be quarantined.")
    print("If a clean backup exists, it will be restored for suspicious Office files.")
    print()

    confirm = input("Continue with quarantine? (yes/no): ").strip().lower()
    if confirm in ["yes", "y"]:
        mitigator.mitigate()
    else:
        print("Mitigation cancelled.")


if __name__ == "__main__":
    main()
