# Meraki Multi-Org Compliance Report

A read-only Cisco Meraki Dashboard API audit tool for MSPs and administrators who manage multiple Meraki organizations.

The script checks licensing, Dashboard administrator security, device health, alert configuration, firmware availability, and wireless security across every organization the API key can access. It generates both CSV data and a standalone HTML report.

## What it checks

- Organization licensing status and expiration
- Full-access Dashboard administrators without two-factor authentication
- Dashboard administrator account status
- Online, offline, alerting, and dormant device counts
- Network alert baseline
- Offline-alert timeout values
- Optional central alert-recipient verification
- Dashboard Settings Changed alert status
- Firmware upgrade availability
- Enabled wireless SSIDs using WEP
- Enabled wireless SSIDs permitting WPA1
- Enabled open-association SSIDs for review
- Optional exclusion of lab or hardware-holding organizations

## Read-only

This tool performs **GET requests only** and does not change Meraki Dashboard configuration.

Always review scripts before running them in production.

## Requirements

- Python 3.10 or newer recommended
- A Cisco Meraki Dashboard API key with access to the organizations you want to audit
- Internet access to `api.meraki.com`

No Meraki Python SDK or third-party Python packages are required. The script uses only the Python standard library.

## Security

Treat your Meraki Dashboard API key like a password.

Do **not**:

- Commit an API key to GitHub
- Put an API key in a ticket, email, Teams message, screenshot, video, or public post
- Store an API key in this repository

The script first checks these environment variables:

```text
MERAKI_DASHBOARD_API_KEY
MERAKI_API_KEY
```

If neither exists, it prompts securely for the key.

If a key is ever exposed, revoke it in Meraki Dashboard and generate a new one.

## Quick start

Clone the repository:

```powershell
git clone https://github.com/JoeDiCerboTech/meraki-multi-org-compliance-report.git
cd meraki-multi-org-compliance-report
```

Run the audit:

```powershell
python .\meraki_multi_org_compliance_report.py
```

You can also set the API key for the current PowerShell session first:

```powershell
$env:MERAKI_DASHBOARD_API_KEY = Read-Host "Meraki API key"
python .\meraki_multi_org_compliance_report.py
```

For a public screenshot/demo run that masks organization and network names:

```powershell
python .\meraki_multi_org_compliance_report.py --public-display
```

## Output

Each run creates a timestamped folder under:

```text
Documents\Meraki-Compliance\Meraki-Compliance-YYYYMMDD-HHMMSS
```

The folder contains:

| File | Purpose |
| --- | --- |
| `report.html` | Standalone visual compliance report |
| `findings.csv` | Individual FAIL, WARN, REVIEW, and INFO findings |
| `organizations.csv` | Organization-level licensing, admin, and device-health summary |
| `networks.csv` | Network-level alert, firmware, wireless, and API status summary |

## Useful options

Show all command-line options:

```powershell
python .\meraki_multi_org_compliance_report.py --help
```

Examples:

```powershell
# Mask organization/network names for screenshots or demos
python .\meraki_multi_org_compliance_report.py --public-display

# Require a central alert-recipient address
python .\meraki_multi_org_compliance_report.py --required-email alerts@example.com

# Change expected offline alert timeout from the default 5 minutes
python .\meraki_multi_org_compliance_report.py --offline-timeout-minutes 10

# Warn when co-term licensing is within 120 days
python .\meraki_multi_org_compliance_report.py --license-warning-days 120

# Exclude known lab or hardware-holding organizations from scoring
python .\meraki_multi_org_compliance_report.py --exclude-org-regex "lab" --exclude-org-regex "hardware holding"

# Promote firmware availability from INFO to WARN
python .\meraki_multi_org_compliance_report.py --firmware-warn

# Promote open SSIDs from REVIEW to WARN
python .\meraki_multi_org_compliance_report.py --open-ssid-warn

# Treat a disabled Settings Changed alert as FAIL instead of WARN
python .\meraki_multi_org_compliance_report.py --require-settings-changed
```

## Severity levels

- **FAIL** — security, licensing, device-health, or alert-baseline condition that should be addressed
- **WARN** — condition that should be reviewed soon
- **REVIEW** — requires administrator judgment or could not be fully validated
- **INFO** — informational item, such as available firmware when `--firmware-warn` is not enabled

The checks are a practical operational baseline, not a substitute for your organization's security policy or Cisco Meraki documentation.

## API endpoints used

The script reads from endpoints including:

```text
GET /organizations
GET /organizations/{organizationId}/licenses/overview
GET /organizations/{organizationId}/admins
GET /organizations/{organizationId}/devices/statuses/overview
GET /organizations/{organizationId}/networks
GET /networks/{networkId}/alerts/settings
GET /networks/{networkId}/firmwareUpgrades
GET /networks/{networkId}/wireless/ssids
```

API availability and returned fields can vary by organization, licensing model, product type, and administrator permissions. Endpoint errors are recorded as REVIEW findings rather than silently ignored.

## Video

This repository accompanies **Video 7** in my Cisco Meraki automation series:

**I Built a Meraki Compliance Report That Finds Problems Before Users Do**

## Disclaimer

This project is provided as an administrative aid. Test it against your own environment and validate findings before making production changes.
