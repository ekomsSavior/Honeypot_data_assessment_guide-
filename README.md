#  Cowrie Malware Triage & Reverse Engineering Prep 

### For security professionals who caught malware and want to analyze it 

brought to you by: ** CHURCHOFMALWARE.org **
---

1. Locate the Downloads on Your Cowrie Server

Cowrie stores every downloaded file in:

```bash
/opt/cowrie/var/lib/cowrie/downloads/
```

Each file is named by its SHA256 hash. No extensions.

```bash
ls -la /opt/cowrie/var/lib/cowrie/downloads/
```

If you have many files, sort by date to find recent captures:

```bash
ls -lat /opt/cowrie/var/lib/cowrie/downloads/ | head -20
```

---

2. Copy Files to Your Analysis Machine

Use scp, rsync, or a shared volume.

```bash
# From Cowrie host to analysis VM
scp -r /opt/cowrie/var/lib/cowrie/downloads/ user@analysis-vm:~/honeypot_samples/

# Or rsync for resume capability
rsync -avz /opt/cowrie/var/lib/cowrie/downloads/ user@analysis-vm:~/honeypot_samples/
```

Pro tip: Keep a local copy of the Cowrie logs as well (.json files). They contain the commands attackers executed, which often reveal the download URLs and post‑exploitation actions.

```bash
scp /opt/cowrie/var/log/cowrie/cowrie.json* user@analysis-vm:~/honeypot_logs/
```

---

3. Initial Triage (Safe, Static)

Create a working directory:

```bash
mkdir -p ~/malware_analysis/{raw,unpacked,strings,iocs,notes,logs}
cd ~/malware_analysis/raw
```

3.1 Identify File Types

```bash
file * | tee ../file_types.txt
```

Look for:

Output Type

ELF 32/64-bit LSB executable Compiled binary (often IoT botnet)

Bourne-Again shell script Plaintext bash downloader

Perl script Plaintext Perl bot

Python script Plaintext Python bot (Discord, etc.)

gzip compressed data Often a coinminer or packed ELF

ASCII text Configuration, logs, or exploit output

3.2 Extract Strings (Always Do This)

strings extracts human-readable text from binaries. Use minimum length 8 to reduce noise.

```bash
for f in *; do
    strings -n 8 "$f" > "../strings/${f}.txt"
done
```

For unpacked binaries later, re‑run:

```bash
strings -n 8 ../unpacked/sample.elf > ../strings/sample.unpacked.txt
```

3.3 Look for Packing Signatures

```bash
grep -l "UPX" ../strings/*.txt
grep -l "This file is packed" ../strings/*.txt
```

UPX is the most common packer in IoT malware. Other packers (e.g., gzip, shc, upx variants) may appear as well.

3.4 Quick Family Detection

```bash
# Mirai
grep -l "mirai\|scanner\|attack_\|table_\|report" ../strings/*.txt

# Gafgyt
grep -l "gafgyt\|vseattack\|SendUDP\|HTTPSTOMP\|STDHEX" ../strings/*.txt

# Perl IRC bot
grep -l "!u udp\|!u tcp\|!u http\|PRIVMSG #" ../strings/*.txt

# Python Discord bot
grep -l "discord.ext.commands\|aiohttp\|webhook\|$help" ../strings/*.txt

# Coinminer
grep -l "pool.supportxmr\|donate-level\|cnrig\|xmrig" ../strings/*.txt
```

---

4. Extract IOCs Without Reverse Engineering

For each sample, create an IOC file. Use refined regex to avoid common false positives.

4.1 IP Addresses

```bash
SAMPLE="hash.ELF.txt"
strings "../strings/${SAMPLE}.txt" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
    grep -vE '^(0|127|255|8\.8\.|192\.168\.|10\.|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]\.)' | \
    sort -u > "../iocs/${SAMPLE}.ips"
```

For IPv4 only. IPv6 is rare in IoT malware.

4.2 Domains

```bash
strings "../strings/${SAMPLE}.txt" | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
    grep -vE 'example|localhost|schemas\.xmlsoap\.org|w3\.org|duckdns\.org(.*)' | \
    sort -u > "../iocs/${SAMPLE}.domains"
```

Note: Some legitimate domains (e.g., duckdns.org) appear in malware; you may want to keep them for enrichment.

4.3 URLs

```bash
strings "../strings/${SAMPLE}.txt" | grep -oE 'https?://[^\s<>"'\''{}|\\^`\[\]]+' | \
    sort -u > "../iocs/${SAMPLE}.urls"
```

4.4 File Paths (Artifacts)

```bash
strings "../strings/${SAMPLE}.txt" | grep '/' | \
    grep -vE 'http://|https://|\.com|\.net|\.org|\.edu' | \
    sort -u > "../iocs/${SAMPLE}.paths"
```

Typical paths: /tmp/, /var/run/, /proc/self/exe, /etc/cron, /root/.

4.5 Attack Methods

```bash
grep -iE 'udp|tcp|http|syn|ack|flood|vse|gre|std|slowloris|stomp' \
    "../strings/${SAMPLE}.txt" | sort -u > "../iocs/${SAMPLE}.attacks"
```

---

5. Enrich IOCs with Public Intelligence (VirusTotal, OTX)

First, get the SHA256 hash (the filename is already the hash).

```bash
echo "${SAMPLE}" | cut -d. -f1 > sample.hash
```

Then query VirusTotal using the API (requires API key). Save output as JSON and parse with jq.

```bash
# Example using curl and jq (replace with your API key)
API_KEY="your_key_here"
HASH=$(echo "${SAMPLE}" | cut -d. -f1)

curl -s "https://www.virustotal.com/api/v3/files/${HASH}" \
    -H "x-apikey: ${API_KEY}" > ../iocs/${SAMPLE}.vt.json

# Extract detection count
jq '.data.attributes.last_analysis_stats' ../iocs/${SAMPLE}.vt.json

# Extract first 10 detection names
jq '.data.attributes.last_analysis_results | to_entries[] | .value.engine_name + ": " + .value.result' \
    ../iocs/${SAMPLE}.vt.json | head -10
```

If you don't have an API key, use the web interface or offline tools.

---

6. Unpacking Compressed/Packed Binaries

6.1 UPX (most common in IoT malware)

```bash
# Check if packed
strings sample.ELF.txt | grep -i upx

# Unpack (make a copy first)
cp sample.ELF.txt sample.unpacked
upx -d sample.unpacked

# Verify unpack succeeded
file sample.unpacked
strings sample.unpacked > sample.unpacked.strings
```

If upx -d fails, the file may be corrupted or use a modified UPX. Try forcing with --force.

6.2 Gzip (coinminers often gzipped)

```bash
# Remove .txt suffix (Cowrie adds it)
mv sample.gzip.txt sample.gz
gunzip sample.gz
file sample   # now likely ELF
```

6.3 Tar archives (rare, but sometimes used for payloads)

```bash
mv sample.tar.txt sample.tar
tar -xvf sample.tar
```

6.4 Base64 encoded scripts

Sometimes the downloader is base64 encoded. Decode with:

```bash
cat sample.ASCII.txt | base64 -d > decoded_sample
file decoded_sample
```

6.5 Custom Packers / Unknown Compression

Use binwalk to scan for embedded files:

```bash
binwalk sample.ELF.txt
```

If you see gzip or xz offsets, you can extract manually.

---

7. Basic Static Analysis for ELF Binaries

Once you have an unpacked (or already unpacked) ELF:

7.1 Check sections and entry point

```bash
readelf -h sample.elf
readelf -S sample.elf          # if no sections → stripped/packed
```

If readelf -S returns nothing, the binary is either stripped or packed. Proceed with caution.

7.2 View imported functions (if dynamic linking)

Most IoT botnets are statically linked, so objdump -T will be empty. For those that aren't:

```bash
objdump -T sample.elf 2>/dev/null | grep FUNC
```

Look for socket, connect, sendto, fork, execve, system, open, write, read.

7.3 Quick disassembly (entry point or main)

```bash
objdump -d -M intel sample.elf | head -200
```

If the binary is stripped, main symbol won't exist. Look for the entry point address from readelf -h and disassemble that.

```bash
ENTRY=$(readelf -h sample.elf | grep "Entry point" | awk '{print $4}')
objdump -d -M intel --start-address=0x$ENTRY sample.elf | head -100
```

7.4 radare2 quick analysis

Radare2 is more powerful for interactive analysis.

```bash
r2 -A sample.elf
```

Within radare2:

Command Action
afl List all functions (will show many, including libc if dynamic)
pdf @main Disassemble main (if symbol exists)
s main Seek to main
/ udp Search for string "udp"
izz List all strings (like strings -n 8)
V Enter visual mode (cursor-driven)
q Quit

For binaries with no symbols, search for strings and cross‑reference:

```
izz | grep -i "udp"
/ udp
axt @ hit0_0   # Show references to that string
```

7.5 Ghidra quick import

Ghidra is free and excellent for GUI analysis. Install with:

```bash
sudo apt install ghidra
ghidra
```

Create a new project, import the ELF, run auto‑analysis. Ghidra will show decompiled C code even for stripped binaries (though variable names will be generic).

---

8. Dynamic Analysis (Sandbox Only)

Never execute malware on a machine connected to the internet or your internal network. Use a VM with network isolation (host‑only, no gateway).

8.1 Simple strace

```bash
strace -f -e trace=network,file,process ./sample.elf
```

You'll see system calls like connect, sendto, open, fork. This reveals C2 IPs/ports and file activity.

8.2 ltrace (library calls)

```bash
ltrace -f ./sample.elf
```

Shows calls to strcmp, printf, malloc, etc. Useful for understanding string comparisons.


---

9. Directory Structure for Long‑Term Analysis

```bash
~/malware_analysis/
├── raw/                  # original Cowrie downloads (hashed names)
├── unpacked/             # after UPX/gunzip decompression
├── strings/              # .txt output of strings (raw & unpacked)
├── iocs/                 # IPs, domains, URLs per sample (also JSON from VT)
├── logs/                 # Cowrie logs (cowrie.json) for context
├── notes/                # Markdown notes per sample
└── by_family/            # symlinks or copies organized by family (mirai/, gafgyt/, etc.)
```

---

10. Automation: Bash Script for Initial Triage

Save as triage.sh and run in the raw/ directory.

```bash
#!/bin/bash
# Quick triage for Cowrie downloads

mkdir -p ../strings ../iocs

for f in *; do
    echo "Processing $f"
    strings -n 8 "$f" > "../strings/${f}.txt"
    
    # Extract IPs (filter private)
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "../strings/${f}.txt" | \
        grep -vE '^(0|127|255|8\.8\.|192\.168\.|10\.|172\.1[6-9]|172\.2[0-9]|172\.3[0-1]\.)' | \
        sort -u > "../iocs/${f}.ips"
    
    # Extract domains
    grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "../strings/${f}.txt" | \
        grep -vE 'example|localhost|schemas\.xmlsoap\.org' | \
        sort -u > "../iocs/${f}.domains"
done

echo "Triage complete. Results in ../strings/ and ../iocs/"
```

---

11. When to Deep Dive into Reverse Engineering

Scenario Action
Unpacked ELF with readable strings but no obvious C2 Load into Ghidra/IDA, find main() (entry point), trace network calls.
Non‑stripped ELF (file shows not stripped) objdump -d is sufficient; function names visible.
Custom packer / encryption Requires dynamic analysis (strace, debugger). Consider sandbox with memory dumping.
Plaintext script (Perl, Python, Bash) Read the source – no reversing needed. But still extract IOCs.
Novel attack method not documented Publish findings (anonymized).
ELF with Go runtime (runtime.main) Use go tool objdump or Ghidra; function names are often preserved.

---

12. Quick Reference: Useful One‑Liners

```bash
# Count file types in raw directory
file * | cut -d: -f2 | sort | uniq -c

# Find all samples that contain a specific string (e.g., C2 domain)
grep -l "lastly.duckdns.org" ../strings/*

# Show only IPs from all strings files
cat ../strings/*.txt | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u

# Compare two samples' strings (identify variants)
diff ../strings/sample1.txt ../strings/sample2.txt

# Check entropy (high = packed/encrypted)
ent sample.elf   # install with `sudo apt install ent`
```

---

13. Next Steps for Aspiring Reverse Engineers

· Learn Ghidra – best free decompiler for ELF. Watch the NSA's training videos.
· Practice on known samples – get malware from VirusTotal (using their API) or from public repositories like MalwareBazaar.
· Set up a sandbox – use VirtualBox snapshots, firejail, or Docker with --read-only.
· Share IOCs – contribute to AlienVault OTX, MISP, or your internal threat intel platform.

---

This workflow is maintained by the Church of Malware. Adapt it to your own environment. Distribute freely.
