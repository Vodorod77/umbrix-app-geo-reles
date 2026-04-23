# Umbrix App Geo Rules

Binary rule-set files (`.srs` format, SRS v1) for split tunneling in Umbrix VPN app.

## Files

### Block lists (updated from hiddify-geo)
- `geosite-category-ads-all.srs` — Ads domains
- `geosite-malware.srs` — Malware domains
- `geosite-phishing.srs` — Phishing domains
- `geosite-cryptominers.srs` — Cryptominer domains
- `geoip-phishing.srs` — Phishing IPs
- `geoip-malware.srs` — Malware IPs
- `sagernet-geosite-category-ads-all.srs` — Extended ads (SagerNet)

### Country-specific (split tunneling)
- `geoip-ru.srs` — Russian IP ranges (direct routing)
- `geosite-ru.srs` — Russian domains (direct routing)
- `geoip-ir.srs` — Iranian IP ranges (direct routing)
- `geosite-ir.srs` — Iranian domains (direct routing)

## Source
Originally sourced from [hiddify/hiddify-geo](https://github.com/hiddify/hiddify-geo) and [SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite).
