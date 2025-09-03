# BellSec Vulnerability Scanner

A Python tool that scans hosts with **Nmap**, enriches findings with **CVEs** (NVD with **CIRCL** fallback), and generates **HTML/JSON** reports with severity filtering and an executive-style summary.

> **Legal**: Scan only systems you own or have explicit permission to test.

## Features
- Service/version detection (`nmap -sV`) on top ports
- CVE lookup via **NVD** (optional API key) with **CIRCL** fallback
- Severity filter: `--severity CRITICAL,HIGH,MEDIUM,LOW`
- Branded **HTML** report (title), severity counts, links to advisories
- **JSON** export for automation

## Quick Start
```bash
sudo apt update
sudo apt install -y nmap python3-nmap apache2
sudo systemctl start apache2

# optional: free NVD key helps reliability
# export NVD_API_KEY="YOUR_KEY"

python3 vuln_scanner.py 127.0.0.1 --top-ports 2000 \
  --severity CRITICAL,HIGH,MEDIUM \
  --title "BellSec Vulnerability Report" \
  --json examples/sample_localhost.json
cat > README.md <<'MD'
# BellSec Vulnerability Scanner

A Python tool that scans hosts with **Nmap**, enriches findings with **CVEs** (NVD with **CIRCL** fallback), and generates **HTML/JSON** reports with severity filtering and an executive-style summary.

> **Legal**: Scan only systems you own or have explicit permission to test.

## Features
- Service/version detection (`nmap -sV`) on top ports
- CVE lookup via **NVD** (optional API key) with **CIRCL** fallback
- Severity filter: `--severity CRITICAL,HIGH,MEDIUM,LOW`
- Branded **HTML** report (title), severity counts, links to advisories
- **JSON** export for automation

## Quick Start
```bash
sudo apt update
sudo apt install -y nmap python3-nmap apache2
sudo systemctl start apache2

# optional: free NVD key helps reliability
# export NVD_API_KEY="YOUR_KEY"

python3 vuln_scanner.py 127.0.0.1 --top-ports 2000 \
  --severity CRITICAL,HIGH,MEDIUM \
  --title "BellSec Vulnerability Report" \
  --json examples/sample_localhost.json
git add .gitignore vuln_scanner.py README.md LICENSE examples/
git commit -m "Initial BellSec release: HTML/JSON reports, NVD→CIRCL fallback, severity summary"
# set main as default branch
git branch -M main
gh repo create bellsec-vuln-scanner --public --source=. --remote=origin --push
