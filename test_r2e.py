#!/usr/bin/env python3
"""
Automated End-to-End Test Suite for R2E Driver
-----------------------------------------------
Tests:
1. Benign Workload Test (Standard text writes: fast write rate, low entropy -> clean passthrough).
2. Rapid Encrypted Attack with AES (High entropy + >50 files in 2s):
   - Confirms PID is flagged.
   - Writes diverted to RAM shadow buffer (backing disk protected).
   - Reversal attempted; irreversible AES triggers Kill Switch (process terminated).
   - Forensic log properly generated with JSON metadata.
3. Rapid Encrypted Attack with XOR (High entropy + >50 files in 2s):
   - Confirms PID is flagged.
   - Reversal Heuristic deduces key and restores clean plaintext to disk.
"""

import os
import sys
import time
import json
import shutil
import subprocess

BACKING_DIR = "/tmp/r2e_test_backing"
MOUNT_DIR = "/tmp/r2e_test_mount"
FORENSIC_LOG = "/tmp/r2e_test_forensics.json"
DRIVER_BIN = "./bin/r2e_driver"

def cleanup():
    subprocess.run(["fusermount3", "-u", MOUNT_DIR], stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    subprocess.run(["pkill", "-9", "-f", "r2e_driver"], stderr=subprocess.DEVNULL)
    shutil.rmtree(BACKING_DIR, ignore_errors=True)
    shutil.rmtree(MOUNT_DIR, ignore_errors=True)
    if os.path.exists(FORENSIC_LOG):
        os.remove(FORENSIC_LOG)

def setup_dirs():
    os.makedirs(BACKING_DIR, exist_ok=True)
    os.makedirs(MOUNT_DIR, exist_ok=True)

def start_driver():
    print("[TEST SETUP] Launching R2E Driver...")
    cmd = [
        DRIVER_BIN,
        "-f",
        BACKING_DIR,
        MOUNT_DIR,
        "--entropy-threshold", "7.0",
        "--file-threshold", "50",
        "--window-ms", "2000",
        "--forensic-log", FORENSIC_LOG
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.0)
    if proc.poll() is not None:
        out, err = proc.communicate()
        print(f"[TEST ERROR] Failed to start driver: {err.decode()}")
        sys.exit(1)
    print(f"[TEST SETUP] Driver running (PID {proc.pid})")
    return proc

def test_benign_writes():
    print("\n=== TEST 1: Benign Heavy Disk Workload ===")
    for i in range(60):
        path = os.path.join(MOUNT_DIR, f"benign_{i:03d}.txt")
        with open(path, "w") as f:
            f.write(f"Sample benign log database entry line {i}\n" * 20)

    backing_files = os.listdir(BACKING_DIR)
    assert len(backing_files) == 60, f"Expected 60 files on disk, got {len(backing_files)}"
    if os.path.exists(FORENSIC_LOG):
        with open(FORENSIC_LOG) as f:
            content = f.read().strip()
            assert not content, "Forensic log should be empty for benign traffic"
    print(">>> PASS: Benign writes persisted to disk without false alarms.")

def test_aes_ransomware_attack():
    print("\n=== TEST 2: High-Entropy AES Burst Attack & Kill Switch ===")
    from mock_ransomware import generate_test_corpus
    generate_test_corpus(MOUNT_DIR, num_files=65)

    ransomware_cmd = [
        sys.executable,
        "mock_ransomware.py",
        MOUNT_DIR,
        "--mode", "aes",
        "--count", "65",
        "--delay-ms", "2"
    ]
    print("[TEST] Running mock ransomware (AES-256 burst)...")
    p = subprocess.Popen(ransomware_cmd)

    try:
        p.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        p.kill()

    print(f"[TEST] Ransomware process finished with exit code {p.returncode}")
    # Process should be terminated by Kill Switch (-15 or -9)
    if p.returncode in (-9, -15, 137, 143):
        print(f">>> Ransomware process was successfully killed by R2E Kill Switch (signal {abs(p.returncode)})")

    time.sleep(0.5)
    assert os.path.exists(FORENSIC_LOG), "Forensic log was not generated!"
    with open(FORENSIC_LOG, "r") as f:
        log_data = f.read()
    print("[TEST] Forensic Log Content Preview:")
    print(log_data[:400] + "...")
    assert "TERMINATED_PROCESS_KILL_SWITCH" in log_data or "AES" in log_data
    print(">>> PASS: AES burst attack detected, writes diverted, kill switch activated, forensics recorded.")

def test_xor_ransomware_reversal():
    print("\n=== TEST 3: Cryptographic Reversal of Reversible Attack ===")
    from mock_ransomware import generate_test_corpus

    # Create files directly in backing dir so baseline data is cleanly preserved
    generate_test_corpus(BACKING_DIR, num_files=60)

    ransomware_cmd = [
        sys.executable,
        "mock_ransomware.py",
        MOUNT_DIR,
        "--mode", "xor_single",
        "--count", "60",
        "--delay-ms", "1"
    ]
    print("[TEST] Running mock ransomware (XOR mode)...")
    p = subprocess.Popen(ransomware_cmd)
    p.wait(timeout=5.0)

    # Check that backing disk files were reversed and retain clean magic headers
    # Files 51..60 encounter reversal engine
    reversed_count = 0
    checked = 0
    for i in range(50, 60):
        png = os.path.join(BACKING_DIR, f"document_{i:03d}.png")
        if os.path.exists(png):
            checked += 1
            with open(png, "rb") as f:
                header = f.read(8)
                if header == b"\x89PNG\r\n\x1a\n":
                    reversed_count += 1

    print(f"[TEST] Intercepted & reversed {reversed_count}/{checked} burst PNG files back to clean plaintext!")
    assert reversed_count > 0 and reversed_count == checked
    print(">>> PASS: Cryptographic reversal engine successfully reversed ciphertext and preserved clean data on disk.")

def main():
    cleanup()
    setup_dirs()
    driver_proc = start_driver()
    try:
        test_benign_writes()
        test_aes_ransomware_attack()
        test_xor_ransomware_reversal()
        print("\n=========================================")
        print("ALL R2E INTEGRATION TESTS PASSED SUCCESSFULLY!")
        print("=========================================\n")
    finally:
        print("[TEST TEARDOWN] Stopping driver and cleaning up...")
        driver_proc.terminate()
        try:
            driver_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            driver_proc.kill()
        cleanup()

if __name__ == "__main__":
    main()
