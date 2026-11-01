# Real-Time Cryptographic Reversal Engine (R2E)

The **Real-Time Cryptographic Reversal Engine (R2E)** is a defensive kernel-level / filesystem-interception prototype engineered to detect, isolate, and reverse ransomware operations in real time before encrypted blocks are committed to persistent disk storage.

---

## Architecture Overview

```
                                      +---------------------------------------------+
                                      |             User Applications               |
                                      |  (Benign Apps, Databases, Mock Ransomware)  |
                                      +---------------------------------------------+
                                                             |
                                                             | POSIX VFS Calls (read/write/open)
                                                             v
+-----------------------------------------------------------------------------------------------------------------------+
|                                        R2E Filesystem Interception Layer (FUSE3)                                     |
|                                                                                                                       |
|   1. Process Tracking & Rate Heuristic:                                                                               |
|      - Extracts calling PID via `fuse_get_context()->pid`.                                                            |
|      - Sliding window (2000 ms) tracks write rate and target files.                                                   |
|      - Shannon Entropy calculation: H(X) = -sum(p_i * log2(p_i)).                                                     |
|      - Trigger: >50 unique files written in <= 2.0s with high entropy (>= 7.0 bits/byte).                             |
|                                                                                                                       |
|   2. Interception & RAM Shadow Buffer:                                                                                |
|      - When flagged: writes are diverted to memory buffers. Backing disk remains untouched.                          |
|      - Return success to calling process so the malicious attacker believes files are being encrypted.               |
|                                                                                                                       |
|   3. Mathematical Cryptographic Reversal Engine:                                                                      |
|      - Analyzes header signatures (PNG, PDF, ELF, DOCX, ZIP, JPG) & known plaintexts.                                 |
|      - Derives keystream / XOR patterns: K = C ^ P. Tests periodicity and stream consistency.                         |
|      - If successful: Decrypts in RAM and writes clean plaintext to disk.                                             |
|                                                                                                                       |
|   4. Defensive Kill Switch & Forensics:                                                                               |
|      - If reversal fails (e.g. robust AES-256-CBC with asymmetric key isolation):                                     |
|        Immediately sends SIGTERM / SIGKILL to the rogue PID.                                                          |
|      - Emits structured forensic JSON report detailing PID, cmdline, entropy, affected files, and cipher fingerprint. |
+-----------------------------------------------------------------------------------------------------------------------+
                                        |                                           |
                         [Clean Plaintext Commits]                   [Diverted RAM Shadow Writes]
                                        v                                           v
                        +-------------------------------+           +-------------------------------+
                        |    Backing Disk File System   |           |    Isolated In-Memory Buffer  |
                        +-------------------------------+           +-------------------------------+
```

---

## Key Modules

- **Entropy Engine (`src/entropy.cpp`, `src/entropy.hpp`)**:
  Computes Shannon entropy $H(X)$ across 256 byte frequency bins. Plaintext documents, source code, and JSON typically register between 3.5 and 5.5 bits/byte, whereas encrypted blocks or compressed payloads exhibit entropy $> 7.5$ bits/byte.

- **Process Tracker (`src/process_tracker.cpp`, `src/process_tracker.hpp`)**:
  Maintains sliding-window write state per PID using `/proc/<pid>/comm` and `/proc/<pid>/cmdline`. Automatically prunes inactive processes while tracking burst write frequencies.

- **Shadow Buffer Manager (`src/shadow_buffer.cpp`, `src/shadow_buffer.hpp`)**:
  Maintains RAM-backed buffers that absorb malicious writes, isolating physical disk blocks from corrupted or encrypted data. Reads from the suspect PID are served from the shadow buffer to maintain illusion of execution.

- **Reversal Engine (`src/reversal_engine.cpp`, `src/reversal_engine.hpp`)**:
  Evaluates mathematical relationships between known file magic bytes (`\x89PNG\r\n\x1a\n`, `%PDF-1.4`, `\x7fELF`, `PK\x03\x04`, etc.) and encrypted blocks. Calculates candidate keystream material $K_i = C_i \oplus P_i$, determines key periodicity, performs inverse transformations, and verifies output sanity.

- **Kill Switch & Forensic Logger (`src/forensics.cpp`, `src/forensics.hpp`)**:
  Upon failure to reverse unkeyed block ciphers (such as AES-256), the kill switch terminates the adversary PID (`SIGTERM` followed by `SIGKILL`) and emits detailed forensic JSON logs (`r2e_forensics.json`).

---

## Performance Trade-Offs of Kernel / Filesystem Interception

Interception of every write request at the kernel/VFS layer introduces fundamental performance considerations:

### 1. Interception Overhead
- **Context Switching**: For FUSE-based interception, every I/O call traverses user space $\to$ kernel VFS $\to$ FUSE driver (user space) $\to$ kernel VFS $\to$ disk driver. This adds round-trip latency ($\sim 2-5\ \mu\text{s}$ per operation).
- **Entropy Computation Overhead**: Full-payload Shannon entropy calculation computes logarithmic histograms over every written block. On NVMe drives executing $500,000+$ IOPS, naive full-buffer calculation on 4KB or 64KB blocks can saturate host CPU cores.

### 2. Preventing Slowdowns on Legitimate Heavy-Disk Operations (e.g. Database Backups)
To ensure legitimate high-throughput operations (such as PostgreSQL `pg_dump`, MySQL `mysqldump`, Oracle redo logs, or video encoding) maintain line-rate throughput without false positives:

1. **Subsampling and Progressive Entropy Stride**:
   - Rather than computing entropy across 100% of large multi-megabyte writes, sample only the initial 512 bytes (file header) and periodic 256-byte strides.
   - Shannon entropy stabilizes rapidly over a small uniform sample size ($\sim 256-512$ bytes).
2. **Process Whitelisting & Verified Cgroups**:
   - Legitimate database daemons (e.g., `postgres`, `mysqld`) execute from known binary paths with cryptographic integrity validation (IMA/EVM, dm-verity) or within designated systemd cgroups.
   - Identified daemons can be placed in a trusted fast-path with pass-through direct I/O (`O_DIRECT`), bypassing userspace context switching.
3. **Sequential Large-Block vs. Burst Small-File Detection**:
   - Database backups write massive sequential blocks (e.g. 1MB - 64MB buffers) into a single archive file or pipe.
   - Ransomware targets hundreds of distinct files in short bursts (burst rate $> 50$ distinct file descriptors within $< 2\text{s}$). Distinguishing by *unique inode count* rather than pure write throughput avoids false positives on backups.
4. **Ring Buffer & Asynchronous Evaluation (eBPF Approach)**:
   - In production eBPF/LSM implementations, write syscalls (`sys_enter_write`) push header snapshots to a lockless perf/ring buffer, allowing the write call to return asynchronously while security analysis runs off the critical I/O path.

---

## Build Instructions

### Prerequisites (Ubuntu / Debian)
```bash
sudo apt-get update
sudo apt-get install -y build-essential libfuse3-dev fuse3 libssl-dev python3 python3-pip
pip install --break-system-packages cryptography
```

### Compiling R2E
```bash
make clean && make
```
The compiled binary will be placed in `bin/r2e_driver`.

---

## Running the Automated Test Suite

The test suite exercises:
1. **Benign heavy disk workloads**: Verifies that standard sequential file writes pass directly to disk with zero false alarms.
2. **AES-256 high-entropy burst attacks**: Verifies that rapid encryption is flagged, isolated in RAM, and stopped by the Kill Switch with forensic JSON generation.
3. **XOR / keystream burst attacks**: Verifies that reversible encryption patterns are reversed in real time, restoring clean plaintext to disk.

```bash
python3 test_r2e.py
```

---

## Deploying in a Sandboxed Environment (Docker)

To test the driver in a secure, isolated sandbox:

### 1. Build and Run via Docker Compose
```bash
docker compose up -d --build
docker compose exec r2e-sandbox bash
```

### 2. Manual Docker Run
```bash
docker run --rm -it \
    --privileged \
    --cap-add SYS_ADMIN \
    --cap-add SYS_PTRACE \
    --device /dev/fuse \
    --security-opt apparmor:unconfined \
    -v $(pwd):/r2e \
    ubuntu:24.04 bash
```

Inside the container:
```bash
cd /r2e
make
python3 test_r2e.py
```

---

## Manual Execution & Verification

### Step 1: Start the Driver
```bash
mkdir -p /tmp/r2e_backing /tmp/r2e_mount
./bin/r2e_driver -f /tmp/r2e_backing /tmp/r2e_mount \
    --entropy-threshold 7.0 \
    --file-threshold 50 \
    --window-ms 2000 \
    --forensic-log /tmp/r2e_forensics.json
```

### Step 2: In a Second Terminal, Run Mock Ransomware
```bash
# Generate 65 test files and attack with AES-256:
python3 mock_ransomware.py /tmp/r2e_mount --mode aes --generate --count 65 --delay-ms 2
```

### Step 3: Inspect Forensic Log
```bash
cat /tmp/r2e_forensics.json
```
Example forensic log output:
```json
{
  "timestamp": "2026-11-01T15:06:46Z",
  "pid": 24641,
  "process_name": "python3",
  "cmdline": "python3 mock_ransomware.py /tmp/r2e_test_mount --mode aes --count 65 --delay-ms 2",
  "action_taken": "TERMINATED_PROCESS_KILL_SWITCH",
  "reversal_success": false,
  "encryption_algorithm_suspected": "AES-CBC/ECB (128/256-bit block aligned)",
  "identified_key_or_keystream": "NONE (IRREVERSIBLE / STRONG ENCRYPTION)",
  "total_files_affected": 52,
  "average_entropy": 7.9273,
  "sample_ciphertext_hex": "4a98f12a3d0b...",
  "sample_files": [
    "/document_000.png",
    "/document_001.pdf"
  ]
}
```
