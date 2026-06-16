# vDefend IDPS Virtual Patching Automation

This repository contains a standalone, Python-based automation tool that demonstrates the power of **vDefend IDPS** for virtual patching. It integrates with Nessus vulnerability scans to automatically deploy targeted IDPS signatures to protect vulnerable workloads.

Included in this repository is the shareable code for the tool, as well as a recorded demo video showing the end-to-end workflow.

## Features

1. **Vulnerability Ingestion**: Connects to Nessus Essentials via API to extract completed vulnerability scans.
2. **CVE Parsing**: Parses the scan results to identify Critical and High severity CVEs affecting specific workloads.
3. **NSX Signature Mapping**: Queries the vDefend IDPS signature database to find exact matches for the detected CVEs.
4. **Dynamic Grouping & Tagging**: Automatically applies NSX tags to vulnerable workloads and creates dynamic Security Groups.
5. **Automated Policy Deployment**: Generates a custom IDPS profile containing only the necessary signatures and deploys a distributed IDPS policy to protect the vulnerable workloads.

## Running the Tool

This tool is built using only the Python standard library, meaning **no `pip install` is required**.

```bash
python3 app.py
```

Then open `http://localhost:5002` in your web browser.

## Demo Video

Check out the included `vdefend_virtual_patching_demo.mp4` for a full walkthrough of the tool in action, demonstrating how it automatically protects a workload against a critical vulnerability.
