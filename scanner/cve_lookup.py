import re
import requests


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_CACHE = {}


def normalize_openssh_version(version):
    # Remove trailing pX (e.g., 6.6.1p1 → 6.6.1)
    return re.sub(r"p\d+$", "", version)


def extract_product_version(banner):
    if not banner:
        return None, None

    apache_match = re.search(r"Apache/?([\d\.]+)", banner, re.IGNORECASE)
    if apache_match:
        return "Apache", apache_match.group(1)

    ssh_match = re.search(r"OpenSSH[_-]([\d\.p]+)", banner, re.IGNORECASE)
    if ssh_match:
        version = ssh_match.group(1)
        return "OpenSSH", version

    nginx_match = re.search(r"nginx/?([\d\.]+)", banner, re.IGNORECASE)
    if nginx_match:
        return "nginx", nginx_match.group(1)

    return None, None


def fetch_cves(product, version):
    cache_key = f"{product}:{version}"
    if cache_key in CVE_CACHE:
        return CVE_CACHE[cache_key]

    try:
        # Special handling for OpenSSH
        if product == "OpenSSH":
            clean_version = normalize_openssh_version(version)
            query = "OpenSSH"
        else:
            clean_version = version
            query = f"{product} {version}"

        params = {
            "keywordSearch": query,
            "resultsPerPage": 20
        }

        response = requests.get(NVD_API, params=params, timeout=3)
        if response.status_code != 200:
            CVE_CACHE[cache_key] = []
            return []

        data = response.json()
        filtered = []

        for item in data.get("vulnerabilities", []):
            cve_id = item["cve"]["id"]
            description = item["cve"]["descriptions"][0]["value"]

            metrics = item["cve"].get("metrics", {})
            severity = None

            if "cvssMetricV31" in metrics:
                severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]

            # Version filtering for OpenSSH
            if product == "OpenSSH":
                if clean_version not in description:
                    continue

            if severity in ["HIGH", "CRITICAL"]:
                filtered.append((cve_id, severity))

        CVE_CACHE[cache_key] = filtered
        return filtered

    except:
        CVE_CACHE[cache_key] = []
        return []

