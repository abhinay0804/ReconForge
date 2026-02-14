from scapy.all import IP, TCP, UDP, DNS, DNSQR, SNMP, SNMPget, SNMPvarbind, ASN1_OID, sr1, send, Raw
from scapy.layers.inet import ICMP
from concurrent.futures import ThreadPoolExecutor
from scanner.banner import grab_banner
import random
import time
import sys


MAX_RETRIES = 3
TIMEOUT = 2
WORKERS = 50
SCAN_DELAY = 0.02


def guess_os(ttl):
    if ttl <= 64:
        return "Linux / Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Network Device / Router"
    return "Unknown"


# ---------------- UDP PROTOCOL PROBES ----------------

def udp_probe(target, port):
    try:

        if port == 53:  # DNS
            pkt = IP(dst=target)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=target))

        elif port == 161:  # SNMP
            pkt = IP(dst=target)/UDP(dport=161)/SNMP(community="public")/SNMPget(
                varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))]
            )

        elif port == 123:  # NTP
            pkt = IP(dst=target)/UDP(dport=123)/b'\x1b' + b'\0' * 47

        elif port == 11211:  # Memcached
            pkt = IP(dst=target)/UDP(dport=11211)/b"stats\r\n"

        elif port == 5060:  # SIP
            sip = "OPTIONS sip:test SIP/2.0\r\n\r\n"
            pkt = IP(dst=target)/UDP(dport=5060)/Raw(load=sip)

        elif port == 67:  # DHCP
            pkt = IP(dst=target)/UDP(dport=67)/Raw(load=b'\x01')

        elif port == 1812:  # RADIUS
            pkt = IP(dst=target)/UDP(dport=1812)/Raw(load=b'\x01')

        elif port == 1900:  # SSDP
            ssdp = "M-SEARCH * HTTP/1.1\r\nMAN:\"ssdp:discover\"\r\n\r\n"
            pkt = IP(dst=target)/UDP(dport=1900)/Raw(load=ssdp)

        elif port == 500:  # ISAKMP
            pkt = IP(dst=target)/UDP(dport=500)/Raw(load=b'\x00')

        elif port == 4500:  # NAT-T
            pkt = IP(dst=target)/UDP(dport=4500)/Raw(load=b'\x00')

        elif port == 137:  # NetBIOS
            pkt = IP(dst=target)/UDP(dport=137)/Raw(load=b'\x81')

        elif port == 389:  # LDAP
            pkt = IP(dst=target)/UDP(dport=389)/Raw(load=b'\x30')

        else:
            pkt = IP(dst=target)/UDP(dport=port)

        resp = sr1(pkt, timeout=TIMEOUT, verbose=0)

        if resp is None:
            return None

        if resp.haslayer(ICMP):
            if resp[ICMP].type == 3 and resp[ICMP].code == 3:
                return None

        return port, resp

    except KeyboardInterrupt:
        sys.exit(0)
    except:
        return None


def udp_scan(target, ports):
    results = []

    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as executor:
            for res in executor.map(lambda p: udp_probe(target, p), ports):
                if res:
                    results.append(res)
    except KeyboardInterrupt:
        sys.exit(0)

    return results


# ---------------- TCP SECTION ----------------

def scan_port(target, port):
    try:
        src_port = random.randint(1024, 65535)
        syn = IP(dst=target)/TCP(sport=src_port, dport=port, flags="S")

        response = None

        for _ in range(MAX_RETRIES):
            response = sr1(syn, timeout=TIMEOUT, verbose=0)
            if response:
                break
            time.sleep(0.2)

        if response is None:
            return None

        if response.haslayer(TCP) and response[TCP].flags == 0x12:
            rst = IP(dst=target)/TCP(sport=src_port, dport=port, flags="R")
            send(rst, verbose=0)

            banner = grab_banner(target, port)

            return {
                "port": port,
                "banner": banner,
                "ttl": response.ttl
            }

        return None

    except KeyboardInterrupt:
        sys.exit(0)
    except:
        return None


def threaded_scan(target, ports):
    results = []
    detected_ttl = None

    random.shuffle(ports)

    try:
        with ThreadPoolExecutor(max_workers=WORKERS) as executor:
            for res in executor.map(lambda p: scan_port(target, p), ports):
                if res:
                    results.append(res)
                    if not detected_ttl:
                        detected_ttl = res["ttl"]
                time.sleep(SCAN_DELAY)
    except KeyboardInterrupt:
        sys.exit(0)

    os_guess = guess_os(detected_ttl) if detected_ttl else "Unknown"
    udp_results = udp_scan(target, ports)

    return results, os_guess, udp_results

