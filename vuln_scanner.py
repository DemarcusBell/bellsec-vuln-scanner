#!/usr/bin/env python3
import os, time, json, sys
import nmap
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

def nvd_search(keyword, max_results=5):
    params = {"keywordSearch": keyword, "startIndex": 0, "resultsPerPage": max_results}
    headers = {"User-Agent": "DemarcusVulnScanner/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    r = requests.get(NVD_API_URL, params=params, headers=headers, timeout=20)
    r.raise_for_status()
    return r.json()

def extract_cvss(cve):
    m = cve.get("metrics", {})
    for k in ("cvssMetricV31","cvssMetricV3","cvssMetricV2"):
        arr = m.get(k, [])
        if arr:
            data = arr[0]
            cv = data.get("cvssData", {})
            score = cv.get("baseScore")
            if k=="cvssMetricV2":
                sev = "HIGH" if (score or 0)>=7 else ("MEDIUM" if (score or 0)>=4 else "LOW")
            else:
                sev = data.get("baseSeverity", "UNKNOWN")
            return (k.replace("cvssMetric","CVSS v").replace("V","v"), score, sev)
    return ("N/A", None, "UNKNOWN")

def best_string(*vals):
    return " ".join([v for v in vals if v]).strip()

def scan_target(target, top_ports=1000):
    nm = nmap.PortScanner()
    print(f"[*] Scanning {target} …")
    nm.scan(hosts=target, arguments=f"-sV -T4 --top-ports {top_ports}")
    results = []
    for host in nm.all_hosts():
        host_data = {"host": host, "hostname": nm[host].hostname(), "state": nm[host].state(), "ports": []}
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                s = nm[host][proto][port]
                entry = {
                    "port": port, "protocol": proto, "state": s.get("state"),
                    "name": s.get("name",""), "product": s.get("product",""),
                    "version": s.get("version",""), "extrainfo": s.get("extrainfo",""),
                    "cpe": s.get("cpe",""), "cves": []
                }
                query = entry["product"] or entry["name"]
                ver = entry["version"]
                keyword = best_string(query, ver) or f"{entry['name']} port {port}"
                try:
                    resp = nvd_search(keyword, max_results=5)
                    time.sleep(0.6)  # be nice to the API
                    for item in resp.get("vulnerabilities", []):
                        cve = item.get("cve", {})
                        cve_id = cve.get("id","CVE-UNKNOWN")
                        descs = cve.get("descriptions", [])
                        desc = next((d.get("value") for d in descs if d.get("lang")=="en"), "")
                        scheme, score, severity = extract_cvss(cve)
                        entry["cves"].append({
                            "id": cve_id, "severity": severity, "score": score, "cvss": scheme,
                            "description": (desc[:240] + ("…" if len(desc)>240 else ""))
                        })
                except Exception as e:
                    entry["cves"].append({"id":"N/A","severity":"UNKNOWN","score":None,"cvss":"N/A","description":f"NVD error: {e}"})
                host_data["ports"].append(entry)
        results.append(host_data)
    return results

def summarize(results):
    summary = {"hosts": 0, "open_ports": 0, "high_or_crit": 0}
    for h in results:
        summary["hosts"] += 1
        for p in h["ports"]:
            if p["state"] == "open":
                summary["open_ports"] += 1
                if any((c["severity"] or "").upper() in ("HIGH","CRITICAL") for c in p["cves"]):
                    summary["high_or_crit"] += 1
    return summary

def write_reports(results, target):
    summary = summarize(results)
    with open("report.json","w") as f:
        json.dump({"target": target, "summary": summary, "results": results}, f, indent=2)
    lines = []
    lines.append("# Vulnerability Scan Report\n")
    lines.append(f"**Target:** `{target}`  \n**Hosts:** {summary['hosts']}  \n**Open ports:** {summary['open_ports']}  \n**Ports w/ High or Critical CVEs:** {summary['high_or_crit']}\n")
    for h in results:
        lines.append(f"## Host: {h['host']} ({h.get('hostname')}) — {h.get('state')}")
        for p in h["ports"]:
            if p["state"] != "open":
                continue
            head = f"- **{p['protocol']}/{p['port']}** — {best_string(p['name'], p['product'], p['version'])}"
            lines.append(head)
            if p["cves"]:
                for c in p["cves"][:3]:
                    sev = c['severity'] or 'UNKNOWN'
                    score = c['score'] if c['score'] is not None else "N/A"
                    lines.append(f"  - `{c['id']}` — **{sev}** (score: {score}, {c['cvss']}) — {c['description']}")
            else:
                lines.append("  - No CVEs returned by NVD for this service/version query.")
        lines.append("")
    with open("report.md","w") as f:
        f.write("\n".join(lines))
    return "report.md","report.json"

def main():
    target = sys.argv[1] if len(sys.argv)>1 else input("Enter target host or CIDR: ").strip()
    if not target:
        print("No target provided."); sys.exit(1)
    results = scan_target(target)
    md, js = write_reports(results, target)
    print(f"\n[+] Done. Wrote {md} and {js}")

if __name__ == "__main__":
    main()
