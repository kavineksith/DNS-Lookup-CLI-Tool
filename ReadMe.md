## 📘 DNS Lookup & Reverse Resolution Tool (Async Optimized)

### 🔹 Introduction

This tool is a robust, highly optimized Python command-line utility designed for **resolving DNS records** (A, AAAA, MX, TXT, etc.) and performing **reverse DNS lookups**. 

Built entirely with modern Python features, the script has been refactored for **maximum process efficiency and low memory overhead**, leveraging the following technical concepts:
* **Fully Asynchronous (`asyncio` & `dns.asyncresolver`)**: Eliminates the overhead of OS thread context-switching (replacing `ThreadPoolExecutor`), enabling thousands of concurrent non-blocking I/O queries.
* **Generator Patterns (`yield`)**: Consumes zero extra memory for output buffers. As queries complete in parallel, they are yielded to the application layer and streamed directly to the terminal interface.
* **Pythonic Dunder Methods**: Integrates standard Python dunder paradigms (`__str__`, `__repr__`, `__aenter__`, `__aexit__`, `__call__`), allowing the core API client to be robustly managed via async context managers.

Whether you're debugging DNS issues, auditing records, or automating lookups, this tool provides reliable and highly scalable DNS resolution features.

## 🛠️ How to Use

### ➤ Run via Command Line:

```bash
python dns_lookup.py example.com 8.8.8.8
```

### ➤ Available Arguments:

| Option            | Description                                          |
| ----------------- | ---------------------------------------------------- |
| `targets`         | One or more domains/IPs to resolve                   |
| `--record-types`  | DNS record types to fetch (default: all major types) |
| `--timeout`       | Per-query timeout (default: 5 sec)                   |
| `--lifetime`      | Total query lifetime (default: 5 sec)                |
| `--max-concurrent`| Max concurrent async tasks (default: 100)            |
| `--reverse-only`  | Perform only reverse DNS lookups on IPs              |
| `--prefer-socket` | Prefer `socket` over `dnspython` for reverse lookups |
| `--prefer-dns`    | Prefer `dnspython` over `socket` for reverse lookups |

### ➤ Examples:

```bash
# Get all default records for a domain
python dns_lookup.py example.com

# Get only A and MX records
python dns_lookup.py example.com --record-types A MX

# Perform reverse lookup for IPs only
python dns_lookup.py 8.8.8.8 1.1.1.1 --reverse-only

# Use DNS method instead of socket for reverse lookups
python dns_lookup.py 8.8.8.8 --reverse-only --prefer-dns
```

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

You are free to use, modify, and distribute this software for any purpose with proper attribution.

**MIT License** (Summary):

* ✅ Commercial use
* ✅ Modification
* ✅ Distribution
* ✅ Private use
* ❌ No warranty provided

Refer to the full `LICENSE` file for more details.

## ⚠️ Disclaimer

>This software is provided for security assessment and authorized testing purposes only. The developers assume no liability and are not responsible for any misuse or damage caused by this software. Before using these tools:

1. Ensure you have proper authorization
2. Review all relevant laws and regulations
3. Test in non-production environments first
4. Consult with your security team

>This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**