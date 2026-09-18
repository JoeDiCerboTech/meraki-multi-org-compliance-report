#!/usr/bin/env python3
"""
Meraki Multi-Org Compliance Report V2
=====================================

Read-only Cisco Meraki Dashboard API audit.

Checks:
- Organization licensing state
- Dashboard admin MFA / account status
- Current device health overview
- Network alert baseline and offline-alert timeouts
- Firmware upgrade availability (informational by default)
- Enabled wireless SSID security
- Optional organization exclusions for known lab/holding environments

Outputs:
- findings.csv
- organizations.csv
- networks.csv
- report.html

No Dashboard configuration changes are made.
Standard-library Python only.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import getpass
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

BASE_URL = "https://api.meraki.com/api/v1"

REQUIRED_ALERTS = {
    "applianceDown": "MX unreachable",
    "dhcpNoLeases": "MX DHCP pool exhausted",
    "rogueDhcp": "Rogue DHCP server detected",
    "ampMalwareBlocked": "Malware download blocked",
    "ampMalwareDetected": "Downloaded content later identified as malware",
    "switchDown": "Switch unreachable",
    "newDhcpServer": "New DHCP server detected",
    "powerSupplyDown": "Switch power supply failure",
    "rpsBackup": "Redundant power supply active",
    "udldError": "UDLD error",
    "switchCriticalTemperature": "Critical switch temperature",
    "gatewayDown": "Gateway AP unreachable",
    "repeaterDown": "Repeater AP unreachable",
    "gatewayToRepeater": "Wired AP fell back to repeater",
    "cameraDown": "Camera unreachable",
    "cellularGatewayDown": "Cellular gateway unreachable",
    "nodeHardwareFailure": "Node hardware failure",
    "sensorDown": "Sensor unreachable",
    "sensorBatteryPercentage": "Sensor low battery",
    "pccExpiredApnsCert": "APNS certificate expiration",
}

OFFLINE_ALERT_TYPES = {
    "applianceDown", "switchDown", "gatewayDown", "repeaterDown",
    "cameraDown", "cellularGatewayDown", "sensorDown",
}

SEVERITY_ORDER = {"FAIL": 0, "WARN": 1, "REVIEW": 2, "PASS": 3, "INFO": 4}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Read-only Cisco Meraki multi-organization compliance report.")
    p.add_argument("--output-root", default=str(Path.home() / "Documents" / "Meraki-Compliance"))
    p.add_argument("--public-display", action="store_true")
    p.add_argument("--required-email", default="")
    p.add_argument("--offline-timeout-minutes", type=int, default=5)
    p.add_argument("--license-warning-days", type=int, default=90)
    p.add_argument("--require-settings-changed", action="store_true")
    p.add_argument(
        "--exclude-org-regex",
        action="append",
        default=[],
        help="Regex for an organization to exclude from compliance scoring. May be supplied more than once.",
    )
    p.add_argument(
        "--firmware-warn",
        action="store_true",
        help="Promote 'firmware upgrade available' from INFO to WARN.",
    )
    p.add_argument(
        "--open-ssid-warn",
        action="store_true",
        help="Promote enabled open-association SSIDs from REVIEW to WARN.",
    )
    return p.parse_args()


class MerakiClient:
    def __init__(self, api_key: str):
        self.api_key = api_key.strip()

    def get(self, path: str, retries: int = 6) -> Any:
        url = path if path.startswith("http") else BASE_URL + path
        for attempt in range(1, retries + 1):
            req = urllib.request.Request(
                url,
                headers={
                    "X-Cisco-Meraki-API-Key": self.api_key,
                    "Accept": "application/json",
                    "User-Agent": "Meraki-Compliance-Report/1.0",
                },
                method="GET",
            )
            try:
                with urllib.request.urlopen(req, timeout=90) as resp:
                    raw = resp.read()
                    return json.loads(raw.decode("utf-8")) if raw else None
            except urllib.error.HTTPError as exc:
                body = ""
                try:
                    body = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
                if exc.code == 429 and attempt < retries:
                    retry_after = exc.headers.get("Retry-After", "2")
                    try:
                        wait = max(1, int(retry_after))
                    except Exception:
                        wait = 2
                    time.sleep(wait)
                    continue
                raise RuntimeError(f"HTTP {exc.code}: {body or exc.reason}") from exc
            except urllib.error.URLError as exc:
                if attempt < retries:
                    time.sleep(min(attempt * 2, 10))
                    continue
                raise RuntimeError(f"Network error: {exc.reason}") from exc


def get_api_key() -> str:
    key = os.environ.get("MERAKI_DASHBOARD_API_KEY") or os.environ.get("MERAKI_API_KEY")
    if key:
        return key.strip()
    print("No Meraki API key environment variable was found.")
    return getpass.getpass("Enter Meraki Dashboard API key: ").strip()


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_meraki_date(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    for fmt in ("%b %d, %Y UTC", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            parsed = dt.datetime.strptime(value, fmt)
            return parsed.replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    return None


def masked(prefix: str, index: int) -> str:
    return f"{prefix}-{index:02d}"


def org_is_excluded(name: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        try:
            if re.search(pattern, name, flags=re.IGNORECASE):
                return True
        except re.error as exc:
            raise ValueError(f"Invalid --exclude-org-regex pattern {pattern!r}: {exc}") from exc
    return False


def contains_email(alert_settings: dict, email: str) -> bool:
    wanted = email.strip().lower()
    if not wanted:
        return True
    default = alert_settings.get("defaultDestinations") or {}
    for item in default.get("emails") or []:
        if str(item).strip().lower() == wanted:
            return True
    for alert in alert_settings.get("alerts") or []:
        dest = alert.get("alertDestinations") or {}
        for item in dest.get("emails") or []:
            if str(item).strip().lower() == wanted:
                return True
    return False


def recursive_true(obj: Any, key_name: str) -> bool:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key_name and v is True:
                return True
            if recursive_true(v, key_name):
                return True
    elif isinstance(obj, list):
        return any(recursive_true(v, key_name) for v in obj)
    return False


def add_finding(findings: list[dict], **kwargs: Any) -> None:
    findings.append({
        "Severity": kwargs.get("severity", "INFO"),
        "Category": kwargs.get("category", ""),
        "Organization": kwargs.get("org", ""),
        "Network": kwargs.get("network", ""),
        "Object": kwargs.get("obj", ""),
        "Finding": kwargs.get("finding", ""),
        "Current": kwargs.get("current", ""),
        "Expected": kwargs.get("expected", ""),
        "Source": kwargs.get("source", ""),
    })


def license_findings(findings: list[dict], org_name: str, overview: dict, warning_days: int) -> tuple[str, str]:
    status = str(overview.get("status") or "").strip()
    expiration = str(overview.get("expirationDate") or "").strip()
    states = overview.get("states") or {}
    active = ((states.get("active") or {}).get("count")) if isinstance(states, dict) else None
    expired = ((states.get("expired") or {}).get("count")) if isinstance(states, dict) else None
    expiring = ((states.get("expiring") or {}).get("count")) if isinstance(states, dict) else None

    summary = status or "Per-device / state-based"
    detail = expiration

    if status:
        low = status.lower()
        if "expired" in low or "shutdown" in low:
            add_finding(findings, severity="FAIL", category="Licensing", org=org_name,
                        finding=f"Organization license status is {status}.", current=status,
                        expected="Active / OK licensing",
                        source="GET /organizations/{organizationId}/licenses/overview")
        elif low in {"license expires soon", "expires soon"}:
            # The expiration-date finding below is more actionable; avoid double-counting the same condition.
            pass
        elif low not in {"ok", "active"}:
            add_finding(findings, severity="WARN", category="Licensing", org=org_name,
                        finding=f"Organization license status requires review: {status}.", current=status,
                        expected="OK", source="GET /organizations/{organizationId}/licenses/overview")
        exp_dt = parse_meraki_date(expiration)
        if exp_dt and exp_dt >= now_utc():
            days = (exp_dt - now_utc()).days
            if days <= warning_days:
                add_finding(findings, severity="FAIL" if days <= 30 else "WARN", category="Licensing", org=org_name,
                            finding=f"Co-term license expiration is {days} day(s) away.", current=expiration,
                            expected=f"More than {warning_days} days remaining",
                            source="GET /organizations/{organizationId}/licenses/overview")
    else:
        if isinstance(expired, int) and expired > 0:
            add_finding(findings, severity="WARN", category="Licensing", org=org_name,
                        finding=f"{expired} expired per-device license(s) reported.", current=expired, expected=0,
                        source="GET /organizations/{organizationId}/licenses/overview")
        if isinstance(expiring, int) and expiring > 0:
            add_finding(findings, severity="WARN", category="Licensing", org=org_name,
                        finding=f"{expiring} per-device license(s) are expiring.", current=expiring, expected=0,
                        source="GET /organizations/{organizationId}/licenses/overview")
    return summary, detail


def html_report(path: Path, findings: list[dict], org_rows: list[dict], net_rows: list[dict], generated: str) -> None:
    counts = {k: sum(1 for f in findings if f["Severity"] == k) for k in ("FAIL", "WARN", "REVIEW", "INFO")}
    categories: dict[str, int] = {}
    for f in findings:
        categories[f["Category"]] = categories.get(f["Category"], 0) + 1

    esc = lambda x: html.escape(str(x if x is not None else ""))
    rows = sorted(findings, key=lambda r: (SEVERITY_ORDER.get(r["Severity"], 99), r["Organization"], r["Network"], r["Category"]))
    body_rows = "\n".join(
        f"<tr><td><span class='badge {esc(r['Severity'].lower())}'>{esc(r['Severity'])}</span></td>"
        f"<td>{esc(r['Category'])}</td><td>{esc(r['Organization'])}</td><td>{esc(r['Network'])}</td>"
        f"<td>{esc(r['Object'])}</td><td>{esc(r['Finding'])}</td><td>{esc(r['Current'])}</td><td>{esc(r['Expected'])}</td></tr>"
        for r in rows
    )
    cat_html = "".join(f"<div class='mini'><strong>{esc(k)}</strong><span>{v}</span></div>" for k, v in sorted(categories.items(), key=lambda kv: (-kv[1], kv[0])))
    doc = f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Meraki Compliance Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#0f141c;color:#eef3f8;margin:0}}.wrap{{max-width:1600px;margin:auto;padding:28px}}
h1{{margin:0 0 4px;font-size:34px}}.sub{{color:#9eacbb;margin-bottom:24px}}.cards{{display:grid;grid-template-columns:repeat(7,1fr);gap:12px;margin:20px 0}}
.card,.mini{{background:#171f2a;border:1px solid #293646;border-radius:12px;padding:16px}}.card b{{display:block;font-size:31px}}.card span,.mini strong{{color:#9eacbb}}
.fail b{{color:#ff6262}}.warn b{{color:#ffc24d}}.review b{{color:#62bfff}}.good b{{color:#52df88}}.cats{{display:flex;gap:10px;flex-wrap:wrap;margin:15px 0 24px}}.mini span{{margin-left:12px;font-size:20px}}
table{{width:100%;border-collapse:collapse;background:#111821;font-size:13px}}th,td{{padding:9px 10px;border-bottom:1px solid #263241;text-align:left;vertical-align:top}}th{{position:sticky;top:0;background:#19222e}}
.badge{{font-weight:700;padding:3px 8px;border-radius:999px}}.badge.fail{{background:#522;color:#ffb2b2}}.badge.warn{{background:#4b3815;color:#ffd987}}.badge.review{{background:#16384d;color:#9edcff}}.badge.info{{background:#27323e;color:#bac7d4}}
</style></head><body><div class='wrap'><h1>Meraki Multi-Org Compliance Report</h1><div class='sub'>Generated {esc(generated)} · Read-only audit</div>
<div class='cards'><div class='card good'><span>Organizations</span><b>{len(org_rows)}</b></div><div class='card good'><span>Networks</span><b>{len(net_rows)}</b></div>
<div class='card fail'><span>FAIL</span><b>{counts['FAIL']}</b></div><div class='card warn'><span>WARN</span><b>{counts['WARN']}</b></div><div class='card review'><span>REVIEW</span><b>{counts['REVIEW']}</b></div><div class='card info'><span>INFO</span><b>{counts['INFO']}</b></div><div class='card'><span>Total findings</span><b>{len(findings)}</b></div></div>
<div class='cats'>{cat_html}</div><table><thead><tr><th>Severity</th><th>Category</th><th>Organization</th><th>Network</th><th>Object</th><th>Finding</th><th>Current</th><th>Expected</th></tr></thead><tbody>{body_rows}</tbody></table></div></body></html>"""
    path.write_text(doc, encoding="utf-8")


def main() -> int:
    args = parse_args()
    key = get_api_key()
    if not key:
        print("No API key supplied.", file=sys.stderr)
        return 2

    client = MerakiClient(key)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    output = Path(args.output_root) / f"Meraki-Compliance-{stamp}"
    output.mkdir(parents=True, exist_ok=True)

    findings: list[dict] = []
    org_rows: list[dict] = []
    net_rows: list[dict] = []

    try:
        orgs = client.get("/organizations?perPage=9000") or []
    except Exception as exc:
        print(f"Unable to enumerate organizations: {exc}", file=sys.stderr)
        return 1

    print("=" * 78)
    print("MERAKI MULTI-ORG COMPLIANCE REPORT - READ ONLY")
    print("=" * 78)
    print(f"Organizations found: {len(orgs)}")
    print(f"Output: {output}")
    print("No Dashboard changes will be made.\n")

    net_counter = 0
    excluded_orgs = 0

    # Validate regexes before beginning the audit.
    for pattern in args.exclude_org_regex:
        try:
            re.compile(pattern)
        except re.error as exc:
            print(f"Invalid --exclude-org-regex pattern {pattern!r}: {exc}", file=sys.stderr)
            return 2

    for org_index, org in enumerate(orgs, 1):
        org_id = str(org.get("id") or "")
        real_org_name = str(org.get("name") or org_id)

        if org_is_excluded(real_org_name, args.exclude_org_regex):
            excluded_orgs += 1
            shown = masked("Excluded-Organization", excluded_orgs) if args.public_display else real_org_name
            print(f"[SKIP] {shown} (excluded from compliance scoring)")
            continue

        display_org = masked("Organization", org_index) if args.public_display else real_org_name
        print(f"[{org_index}/{len(orgs)}] {display_org}")

        org_row = {"Organization": display_org, "LicenseStatus": "", "LicenseExpiration": "", "FullAdmins": "", "FullAdminsWithout2FA": "",
                   "OnlineDevices": "", "OfflineDevices": "", "AlertingDevices": "", "DormantDevices": "", "Networks": "", "ApiErrors": 0}

        try:
            lic = client.get(f"/organizations/{urllib.parse.quote(org_id)}/licenses/overview") or {}
            ls, le = license_findings(findings, display_org, lic, args.license_warning_days)
            org_row["LicenseStatus"] = ls
            org_row["LicenseExpiration"] = le
        except Exception as exc:
            org_row["ApiErrors"] += 1
            add_finding(findings, severity="REVIEW", category="API Access", org=display_org, finding="Could not read licensing overview.", current=str(exc), expected="API endpoint readable", source="GET /organizations/{organizationId}/licenses/overview")

        try:
            admins = client.get(f"/organizations/{urllib.parse.quote(org_id)}/admins") or []
            full_admins = [a for a in admins if str(a.get("orgAccess") or "").lower() == "full"]
            no_2fa = [a for a in full_admins if a.get("twoFactorAuthEnabled") is False]
            org_row["FullAdmins"] = len(full_admins)
            org_row["FullAdminsWithout2FA"] = len(no_2fa)
            for idx, admin in enumerate(no_2fa, 1):
                obj = f"Full admin #{idx}" if args.public_display else str(admin.get("email") or admin.get("name") or f"Admin {idx}")
                add_finding(findings, severity="FAIL", category="Admin Security", org=display_org, obj=obj,
                            finding="Full-access Dashboard administrator does not have two-factor authentication enabled.", current="2FA disabled", expected="2FA enabled", source="GET /organizations/{organizationId}/admins")
            for idx, admin in enumerate(full_admins, 1):
                status = str(admin.get("accountStatus") or "")
                if status and status.lower() != "ok":
                    obj = f"Full admin #{idx}" if args.public_display else str(admin.get("email") or admin.get("name") or f"Admin {idx}")
                    add_finding(findings, severity="WARN", category="Admin Security", org=display_org, obj=obj,
                                finding="Full-access Dashboard administrator account status requires review.", current=status, expected="ok", source="GET /organizations/{organizationId}/admins")
        except Exception as exc:
            org_row["ApiErrors"] += 1
            add_finding(findings, severity="REVIEW", category="API Access", org=display_org, finding="Could not read organization administrators.", current=str(exc), expected="API endpoint readable", source="GET /organizations/{organizationId}/admins")

        try:
            dev = client.get(f"/organizations/{urllib.parse.quote(org_id)}/devices/statuses/overview") or {}
            counts = dev.get("counts") or {}
            by_status = dev.get("byStatus") or {}
            def cv(name: str) -> int:
                v = counts.get(name)
                if v is None:
                    v = by_status.get(name)
                    if isinstance(v, dict):
                        v = v.get("count")
                return int(v or 0)
            online, offline, alerting, dormant = cv("online"), cv("offline"), cv("alerting"), cv("dormant")
            org_row.update({"OnlineDevices": online, "OfflineDevices": offline, "AlertingDevices": alerting, "DormantDevices": dormant})
            if offline:
                add_finding(findings, severity="FAIL", category="Device Health", org=display_org, finding=f"{offline} device(s) are currently offline.", current=offline, expected=0, source="GET /organizations/{organizationId}/devices/statuses/overview")
            if alerting:
                add_finding(findings, severity="WARN", category="Device Health", org=display_org, finding=f"{alerting} device(s) are currently alerting.", current=alerting, expected=0, source="GET /organizations/{organizationId}/devices/statuses/overview")
            if dormant:
                add_finding(findings, severity="WARN", category="Device Health", org=display_org, finding=f"{dormant} device(s) are currently dormant.", current=dormant, expected=0, source="GET /organizations/{organizationId}/devices/statuses/overview")
        except Exception as exc:
            org_row["ApiErrors"] += 1
            add_finding(findings, severity="REVIEW", category="API Access", org=display_org, finding="Could not read device status overview.", current=str(exc), expected="API endpoint readable", source="GET /organizations/{organizationId}/devices/statuses/overview")

        try:
            networks = client.get(f"/organizations/{urllib.parse.quote(org_id)}/networks?perPage=1000") or []
            org_row["Networks"] = len(networks)
        except Exception as exc:
            org_row["ApiErrors"] += 1
            add_finding(findings, severity="REVIEW", category="API Access", org=display_org, finding="Could not list organization networks.", current=str(exc), expected="API endpoint readable", source="GET /organizations/{organizationId}/networks")
            networks = []

        for network in networks:
            net_counter += 1
            net_id = str(network.get("id") or "")
            real_net_name = str(network.get("name") or net_id)
            display_net = masked("Network", net_counter) if args.public_display else real_net_name
            products = [str(x) for x in (network.get("productTypes") or [])]
            net_row = {"Organization": display_org, "Network": display_net, "ProductTypes": ";".join(products), "TimeZone": network.get("timeZone") or "",
                       "EnabledAlerts": "", "MissingBaselineAlerts": "", "FirmwareUpgradeAvailable": "", "EnabledSSIDs": "", "WirelessSecurityFindings": "", "ApiErrors": 0}

            try:
                aset = client.get(f"/networks/{urllib.parse.quote(net_id)}/alerts/settings") or {}
                alerts = aset.get("alerts") or []
                enabled = [a for a in alerts if a.get("enabled") is True]
                exposed = {str(a.get("type") or ""): a for a in alerts}
                missing = [t for t in REQUIRED_ALERTS if t in exposed and exposed[t].get("enabled") is not True]
                net_row["EnabledAlerts"] = len(enabled)
                net_row["MissingBaselineAlerts"] = len(missing)
                if not enabled and alerts:
                    add_finding(findings, severity="FAIL", category="Alerts", org=display_org, network=display_net, finding="Network exposes alert types but none are enabled.", current=0, expected="Core alerts enabled", source="GET /networks/{networkId}/alerts/settings")
                for alert_type in missing:
                    add_finding(findings, severity="FAIL", category="Alerts", org=display_org, network=display_net, obj=alert_type,
                                finding=f"Core alert is disabled: {REQUIRED_ALERTS[alert_type]}.", current="disabled", expected="enabled", source="GET /networks/{networkId}/alerts/settings")
                settings_alert = exposed.get("settingsChanged")
                if settings_alert and settings_alert.get("enabled") is not True:
                    add_finding(findings, severity="FAIL" if args.require_settings_changed else "WARN", category="Alerts", org=display_org, network=display_net, obj="settingsChanged",
                                finding="Dashboard configuration-change alert is disabled.", current="disabled", expected="enabled" if args.require_settings_changed else "review", source="GET /networks/{networkId}/alerts/settings")
                # In the network alert settings returned by this environment, timeout is represented
                # as the Dashboard minute value (for example, 5 == five minutes). V1 incorrectly
                # multiplied the baseline by 60, producing false 5-vs-300 warnings.
                expected_timeout = args.offline_timeout_minutes
                for alert_type in OFFLINE_ALERT_TYPES:
                    a = exposed.get(alert_type)
                    if not a or a.get("enabled") is not True:
                        continue
                    timeout = (a.get("filters") or {}).get("timeout")
                    if isinstance(timeout, (int, float)) and int(timeout) != expected_timeout:
                        add_finding(findings, severity="WARN", category="Alerts", org=display_org, network=display_net, obj=alert_type,
                                    finding="Offline alert timeout differs from the expected baseline.",
                                    current=f"{timeout:g} minute(s)", expected=f"{expected_timeout} minute(s)",
                                    source="GET /networks/{networkId}/alerts/settings")
                if args.required_email and not contains_email(aset, args.required_email):
                    add_finding(findings, severity="FAIL", category="Alerts", org=display_org, network=display_net, finding="Required central alert recipient was not found in network alert destinations.", current="missing", expected=args.required_email if not args.public_display else "required recipient present", source="GET /networks/{networkId}/alerts/settings")
            except Exception as exc:
                net_row["ApiErrors"] += 1
                add_finding(findings, severity="REVIEW", category="API Access", org=display_org, network=display_net, finding="Could not read network alert settings.", current=str(exc), expected="API endpoint readable", source="GET /networks/{networkId}/alerts/settings")

            try:
                fw = client.get(f"/networks/{urllib.parse.quote(net_id)}/firmwareUpgrades") or {}
                upgrade = recursive_true(fw, "isUpgradeAvailable")
                net_row["FirmwareUpgradeAvailable"] = "YES" if upgrade else "NO"
                if upgrade:
                    add_finding(findings, severity="WARN" if args.firmware_warn else "INFO",
                                category="Firmware", org=display_org, network=display_net,
                                finding="A firmware upgrade is available for at least one product in this network.",
                                current="upgrade available", expected="review current/target firmware",
                                source="GET /networks/{networkId}/firmwareUpgrades")
            except Exception as exc:
                net_row["ApiErrors"] += 1
                add_finding(findings, severity="REVIEW", category="API Access", org=display_org, network=display_net, finding="Could not read network firmware-upgrade information.", current=str(exc), expected="API endpoint readable", source="GET /networks/{networkId}/firmwareUpgrades")

            wifi_findings = 0
            if "wireless" in products:
                try:
                    ssids = client.get(f"/networks/{urllib.parse.quote(net_id)}/wireless/ssids") or []
                    enabled_ssids = [s for s in ssids if s.get("enabled") is True]
                    net_row["EnabledSSIDs"] = len(enabled_ssids)
                    for ssid in enabled_ssids:
                        num = ssid.get("number")
                        ssid_name = f"SSID {num}" if args.public_display else str(ssid.get("name") or f"SSID {num}")
                        auth = str(ssid.get("authMode") or "")
                        enc = str(ssid.get("encryptionMode") or "")
                        wpa = str(ssid.get("wpaEncryptionMode") or "")
                        if enc.lower() == "wep":
                            wifi_findings += 1
                            add_finding(findings, severity="FAIL", category="Wireless Security", org=display_org, network=display_net, obj=ssid_name, finding="Enabled SSID uses WEP encryption.", current="WEP", expected="WPA2/WPA3 or an approved enterprise/open guest design", source="GET /networks/{networkId}/wireless/ssids")
                        elif wpa in {"WPA1 only", "WPA1 and WPA2"}:
                            wifi_findings += 1
                            add_finding(findings, severity="FAIL", category="Wireless Security", org=display_org, network=display_net, obj=ssid_name, finding="Enabled SSID permits WPA1.", current=wpa, expected="WPA2 only, WPA3 Transition, WPA3 only, or approved enterprise design", source="GET /networks/{networkId}/wireless/ssids")
                        elif auth in {"open", "open-with-radius", "open-with-nac"}:
                            wifi_findings += 1
                            add_finding(findings, severity="WARN" if args.open_ssid_warn else "REVIEW",
                                        category="Wireless Security", org=display_org, network=display_net, obj=ssid_name,
                                        finding="Enabled SSID uses an open association mode; validate that this is an intentional guest/NAC design.",
                                        current=auth, expected="intentional documented design",
                                        source="GET /networks/{networkId}/wireless/ssids")
                    net_row["WirelessSecurityFindings"] = wifi_findings
                except Exception as exc:
                    net_row["ApiErrors"] += 1
                    add_finding(findings, severity="REVIEW", category="API Access", org=display_org, network=display_net, finding="Could not read wireless SSID configuration.", current=str(exc), expected="API endpoint readable", source="GET /networks/{networkId}/wireless/ssids")

            net_rows.append(net_row)

        org_rows.append(org_row)

    def write_csv(name: str, rows: list[dict]) -> None:
        path = output / name
        if not rows:
            path.write_text("", encoding="utf-8")
            return
        with path.open("w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    write_csv("findings.csv", findings)
    write_csv("organizations.csv", org_rows)
    write_csv("networks.csv", net_rows)
    generated = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    html_report(output / "report.html", findings, org_rows, net_rows, generated)

    counts = {k: sum(1 for f in findings if f["Severity"] == k) for k in ("FAIL", "WARN", "REVIEW", "INFO")}
    print("\n" + "=" * 78)
    print("COMPLIANCE AUDIT COMPLETE")
    print("=" * 78)
    print(f"Organizations audited: {len(org_rows)}")
    print(f"Organizations excluded:{excluded_orgs:>7}")
    print(f"Networks audited:      {len(net_rows)}")
    print(f"FAIL findings:         {counts['FAIL']}")
    print(f"WARN findings:         {counts['WARN']}")
    print(f"REVIEW findings:       {counts['REVIEW']}")
    print(f"INFO findings:         {counts['INFO']}")
    print(f"Total findings:        {len(findings)}")
    print(f"\nHTML report: {output / 'report.html'}")
    print(f"CSV findings: {output / 'findings.csv'}")
    print("\nREAD ONLY: no Dashboard configuration changes were made.")
    if args.public_display:
        print("PUBLIC DISPLAY: organization/network names and IDs were masked; excluded names were not printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())