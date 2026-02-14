import argparse
from scanner.engine import threaded_scan
from scanner.cve_lookup import extract_product_version, fetch_cves
from scanner.splash import show_banner
from utils.validator import validate_target
from datetime import datetime
import time
from concurrent.futures import ThreadPoolExecutor
import json


UDP_NAMES = {
    53: "DNS",
    123: "NTP",
    161: "SNMP",
    69: "TFTP",
    11211: "Memcached"
}


def cve_worker(software):
    results = {}
    for product, version in software:
        cves = fetch_cves(product, version)
        results[f"{product} {version}"] = cves
    return results


def calculate_risk(tcp_count, udp_count, has_web, has_ssh, high_cves):
    score = 0
    score += tcp_count * 0.5
    score += udp_count * 0.5
    if has_web:
        score += 1
    if has_ssh:
        score += 1
    score += high_cves * 2

    if score > 10:
        score = 10

    if score >= 7:
        level = "HIGH"
    elif score >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"

    return round(score, 1), level


def main():
    parser = argparse.ArgumentParser(
        description="ReconForge — Your Frontline Port Recon Scanner",
        epilog="Example: sudo python main.py --target scanme.nmap.org --start 1 --end 200 --cve --json"
    )

    parser.add_argument("--target", required=True, help="Target IP address or domain name")
    parser.add_argument("--start", type=int, default=1, help="Starting port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="Ending port (default: 1024)")
    parser.add_argument("--cve", action="store_true", help="Enable exposure intelligence (CVE correlation)")
    parser.add_argument("--json", action="store_true", help="Export recon results to JSON report")

    # Show aura banner BEFORE argparse (so --help also gets splash)
    show_banner()

    args = parser.parse_args()

    target = args.target
    start_port = args.start
    end_port = args.end
    do_cve = args.cve
    do_json = args.json

    scan_start = datetime.now()
    perf_start = time.time()

    print(f"Scan started: {scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Target      : {target}")
    print(f"Port Range  : {start_port}-{end_port}\n")

    if not validate_target(target):
        print("Invalid target")
        return

    ports = list(range(start_port, end_port + 1))

    tcp_results, os_guess, udp_results = threaded_scan(target, ports)

    print(f"[*] OS Guess: {os_guess}")

    udp_list = []
    if udp_results:
        print("[*] UDP Exposure:")
        for port, _ in udp_results:
            service = UDP_NAMES.get(port, "Unknown")
            udp_list.append(port)
            print(f"    {port}/udp ({service})")
        print()

    software = []
    tcp_ports = []

    has_web = False
    has_ssh = False

    for item in tcp_results:
        port = item["port"]
        banner = item["banner"]

        tcp_ports.append(port)

        if port in [80, 443]:
            has_web = True
        if port == 22:
            has_ssh = True

        print(f"[+] TCP {port} OPEN")

        if banner:
            print(banner)
            product, version = extract_product_version(banner)
            if product and version:
                software.append((product, version))
                print(f"[!] Identified Software: {product} {version}")
        print()

    unique_software = list(set(software))

    cve_future = None
    cve_results = {}

    if do_cve and unique_software:
        print("[*] Running exposure intelligence in background...\n")
        executor = ThreadPoolExecutor(max_workers=1)
        cve_future = executor.submit(cve_worker, unique_software)

    perf_end = time.time()
    duration = int(perf_end - perf_start)

    high_cves = 0

    if cve_future:
        cve_results = cve_future.result()
        for _, cves in cve_results.items():
            high_cves += len(cves)

    risk_score, risk_level = calculate_risk(len(tcp_ports), len(udp_list), has_web, has_ssh, high_cves)

    print("\n========== RECON SUMMARY ==========")
    print(f"TCP Open Ports : {len(tcp_ports)}")
    print(f"UDP Exposure  : {len(udp_list)}")
    print(f"Web Surface  : {'Yes' if has_web else 'No'}")
    print(f"SSH Exposed  : {'Yes' if has_ssh else 'No'}")
    print(f"HIGH CVEs    : {high_cves}")
    print(f"OS           : {os_guess}")
    print(f"Risk Score   : {risk_score} / 10 ({risk_level})")
    print("=================================")

    print(f"\nRecon Time: {duration} seconds")

    if do_json:
        report = {
            "target": target,
            "duration": duration,
            "os": os_guess,
            "tcp_ports": tcp_ports,
            "udp_ports": udp_list,
            "software": [f"{p} {v}" for p, v in unique_software],
            "exposure_cves": cve_results,
            "risk": {"score": risk_score, "level": risk_level}
        }

        fname = f"reconforge_{target}_{scan_start.strftime('%Y%m%d_%H%M%S')}.json".replace("/", "_")
        with open(fname, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] Recon report saved to {fname}")

    print()


if __name__ == "__main__":
    main()

