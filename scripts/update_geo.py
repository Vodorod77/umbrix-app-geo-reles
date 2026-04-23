import urllib.request
import os
import sys

SRS_V1_MAGIC = bytes([0x53, 0x52, 0x53, 0x01])

BASE_BLOCK    = "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block"
BASE_COUNTRY  = "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/country"
BASE_SAGERNET = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set"

files = [
    (f"{BASE_BLOCK}/geosite-category-ads-all.srs",   "geosite-category-ads-all.srs"),
    (f"{BASE_BLOCK}/geosite-malware.srs",             "geosite-malware.srs"),
    (f"{BASE_BLOCK}/geosite-phishing.srs",            "geosite-phishing.srs"),
    (f"{BASE_BLOCK}/geosite-cryptominers.srs",        "geosite-cryptominers.srs"),
    (f"{BASE_BLOCK}/geoip-phishing.srs",              "geoip-phishing.srs"),
    (f"{BASE_BLOCK}/geoip-malware.srs",               "geoip-malware.srs"),
    (f"{BASE_SAGERNET}/geosite-category-ads-all.srs", "sagernet-geosite-category-ads-all.srs"),
    (f"{BASE_COUNTRY}/geoip-ru.srs",                  "geoip-ru.srs"),
    (f"{BASE_COUNTRY}/geosite-ru.srs",                "geosite-ru.srs"),
    (f"{BASE_COUNTRY}/geoip-ir.srs",                  "geoip-ir.srs"),
    (f"{BASE_COUNTRY}/geosite-ir.srs",                "geosite-ir.srs"),
]

failed = []

for url, filename in files:
    print(f"Downloading: {filename}")
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = resp.read()
    except Exception as e:
        print(f"  ERROR: {e}")
        failed.append(f"{filename}(download_failed)")
        continue

    if data[:4] == SRS_V1_MAGIC:
        with open(filename, "wb") as f:
            f.write(data)
        print(f"  OK: SRS v1, {len(data)} bytes")
    else:
        magic_hex = data[:4].hex()
        print(f"  SKIP: incompatible format (magic={magic_hex})")
        failed.append(f"{filename}(SRS_v2)")

github_output = os.environ.get("GITHUB_OUTPUT", "")
if github_output:
    with open(github_output, "a") as f:
        if failed:
            f.write("has_failures=true\n")
            f.write("failed_files<<EOF\n")
            f.write("\n".join(failed) + "\n")
            f.write("EOF\n")
        else:
            f.write("has_failures=false\n")

if failed:
    print(f"\nFailed: {failed}")
    sys.exit(1)
else:
    print("\nAll files OK.")
