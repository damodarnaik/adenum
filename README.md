# Active Directory Enumeration & Vulnerability Analysis Tool

A comprehensive Python tool for Active Directory enumeration, vulnerability detection, and attack path analysis. Designed for authorized penetration testing and security assessments.

## ⚠️ Legal Disclaimer

**This tool is intended for authorized security testing only.** You must have explicit written permission from the target organization before using this tool. Unauthorized access to computer systems is illegal.

## Features

### 🔍 Comprehensive Enumeration
- **Domain Information**: Functional levels, password policies, domain controllers, sites
- **User Accounts**: All users, privileged users, service accounts, account attributes
- **Computer Accounts**: Workstations, servers, domain controllers, OS information
- **Groups**: All groups, privileged groups, nested membership resolution
- **Trust Relationships**: Domain trusts, forest trusts, trust attributes
- **GPOs**: Group Policy Objects and their configurations

### 🚨 Vulnerability Detection
- **Kerberoasting**: Identifies accounts with SPNs vulnerable to offline password cracking
- **AS-REP Roasting**: Finds accounts without Kerberos pre-authentication
- **Delegation Issues**: Unconstrained, constrained, and resource-based constrained delegation
- **Password Policy Weaknesses**: Analyzes domain password policy for security gaps
- **Privileged Account Issues**: Identifies security concerns with high-privilege accounts
- **Stale Accounts**: Detects inactive user and computer accounts
- **DNSAdmins**: Identifies members of the DNSAdmins group (privilege escalation vector)
- **Weak Password Settings**: Finds accounts with reversible encryption or no password requirement

### 🎯 Attack Path Analysis
- **Graph-Based Analysis**: Uses NetworkX to build attack graphs
- **Path Finding**: Identifies shortest paths to Domain Admin and other high-value targets
- **Risk Scoring**: Prioritizes paths based on risk and exploitability
- **Relationship Mapping**: Group memberships, delegation, and ACL-based paths

### 📊 Professional Reporting
- **HTML Reports**: Beautiful, interactive reports with charts and color-coded risk levels
- **JSON Reports**: Machine-readable data for integration with other tools
- **Text Reports**: Console-friendly summaries with colored output

## Installation

### Prerequisites
- Python 3.8 or higher
- Windows, Linux, or macOS
- Network access to target domain controller

### Install Dependencies

```bash
cd C:\Users\Team\.gemini\antigravity\scratch\ad-enum-tool
pip install -r requirements.txt
```

## Usage

### Basic Enumeration

```bash
# Password authentication
python ad_enum_tool.py -d example.com -u admin -p Password123 -t 192.168.1.10

# Full enumeration with HTML report
python ad_enum_tool.py -d example.com -u admin -p Password123 -t 192.168.1.10 --full-enum --output-html report.html
```

### Pass-the-Hash Authentication

```bash
# Using NT hash
python ad_enum_tool.py -d example.com -u admin --nthash <hash> -t 192.168.1.10

# Using both LM and NT hashes
python ad_enum_tool.py -d example.com -u admin --lmhash <lm> --nthash <nt> -t 192.168.1.10
```

### Targeted Enumeration

```bash
# Only enumerate users and groups
python ad_enum_tool.py -d example.com -u admin -p Password123 -t 192.168.1.10 --users --groups

# Only perform vulnerability scan
python ad_enum_tool.py -d example.com -u admin -p Password123 -t 192.168.1.10 --vuln-scan

# Find attack paths
python ad_enum_tool.py -d example.com -u admin -p Password123 -t 192.168.1.10 --attack-paths
```

### Multiple Output Formats

```bash
# Generate all report types
python ad_enum_tool.py -d example.com -u admin -p Password123 -t 192.168.1.10 \
  --output-json data.json \
  --output-html report.html \
  --output-text report.txt
```

## Command-Line Options

### Connection Options
- `-d, --domain`: Target domain (e.g., example.com) **[Required]**
- `-u, --username`: Username for authentication **[Required]**
- `-p, --password`: Password for authentication
- `-t, --target`: Domain controller IP address **[Required]**
- `--lmhash`: LM hash for pass-the-hash
- `--nthash`: NT hash for pass-the-hash
- `--kerberos`: Use Kerberos authentication

### Enumeration Options
- `--full-enum`: Perform full enumeration (default if no specific options selected)
- `--users`: Enumerate users
- `--computers`: Enumerate computers
- `--groups`: Enumerate groups
- `--domain-info`: Enumerate domain information
- `--vuln-scan`: Perform vulnerability analysis
- `--attack-paths`: Find attack paths

### OpSec / Stealth Options
- `--stealth`: Enable stealth mode (rate limiting, delays, randomization)
- `--delay-min SECONDS`: Minimum delay between queries (default: 2s)
- `--delay-max SECONDS`: Maximum delay between queries (default: 8s)
- `--max-qpm NUM`: Maximum queries per minute (default: 15)
- `--spread-hours NUM`: Spread enumeration over N hours

### Output Options
- `--output-json FILE`: Save JSON report to file
- `--output-html FILE`: Save HTML report to file
- `--output-text FILE`: Save text report to file
- `--quiet`: Suppress console output
- `-v, --verbose`: Enable verbose logging

## Report Examples

### HTML Report
The HTML report provides:
- Executive summary with statistics
- Color-coded vulnerability findings by severity
- Attack path visualizations
- Detailed recommendations

### JSON Report
Machine-readable format containing:
- Complete enumeration data
- All vulnerability findings
- Attack paths with step-by-step details
- Statistics and metadata

### Text Report
Console-friendly format with:
- Summary statistics
- Vulnerabilities grouped by severity
- Top attack paths
- Key recommendations

## Vulnerability Categories

| Type | Severity | Description |
|------|----------|-------------|
| Kerberoasting | HIGH/CRITICAL | Service accounts with SPNs vulnerable to offline cracking |
| AS-REP Roasting | HIGH | Accounts without Kerberos pre-authentication |
| Unconstrained Delegation | CRITICAL | Accounts that can impersonate any user to any service |
| Constrained Delegation | MEDIUM | Accounts with targeted delegation permissions |
| Weak Password Policy | HIGH | Domain password policy below security best practices |
| Stale Accounts | MEDIUM | Inactive accounts that pose security risks |
| DNSAdmins | HIGH | Members can achieve code execution on DNS servers |

## Architecture

```
ad-enum-tool/
├── ad_enum_tool.py          # Main entry point
├── config.py                 # Configuration and constants
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── modules/
│   ├── ldap_connector.py    # LDAP connection management
│   ├── domain_enum.py       # Domain enumeration
│   ├── user_enum.py         # User enumeration
│   ├── computer_enum.py     # Computer enumeration
│   ├── group_enum.py        # Group enumeration
│   ├── vuln_analyzer.py     # Vulnerability detection
│   ├── attack_paths.py      # Attack path analysis
│   ├── reporter.py          # Report generation
│   └── utils.py             # Utility functions
└── templates/
    └── report_template.html  # HTML report template
```

## Dependencies

- **impacket**: SMB and LDAP protocol implementation
- **ldap3**: LDAP client library
- **networkx**: Graph analysis for attack paths
- **jinja2**: HTML template rendering
- **colorama**: Colored console output

## Troubleshooting

### Connection Issues
- Verify domain controller IP is correct and reachable
- Ensure credentials are valid
- Check firewall rules allow LDAP (389/tcp) or LDAPS (636/tcp)

### Authentication Errors
- Verify username format (just username, not DOMAIN\\username)
- For pass-the-hash, ensure hashes are in correct format
- Check if account has sufficient permissions

### Missing Data
- Some enumeration requires specific privileges
- Increase verbosity with `-v` for debugging
- Check LDAP query permissions

## Best Practices

1. **Always obtain written authorization** before running this tool
2. **Document your scope** and stay within authorized boundaries
3. **Handle reports securely** - they contain sensitive security information
4. **Report findings responsibly** to the appropriate parties
5. **Clean up test artifacts** after assessment completion

## Future Enhancements

Potential features for future versions:
- LDAP over SSL (LDAPS) support
- Additional vulnerability checks (ACL abuse, GPO vulnerabilities)
- Integration with BloodHound data format
- Automated exploitation suggestions
- Support for forest-level enumeration

## Contributing

This is a security assessment tool. If you find bugs or have enhancement suggestions, please report them responsibly.

## License

This tool is provided for authorized security testing purposes only. Use at your own risk.

## Credits

Built using:
- [Impacket](https://github.com/SecureAuthCorp/impacket) by SecureAuth Corporation
- [ldap3](https://github.com/cannatag/ldap3) by Giovanni Cannata
- [NetworkX](https://networkx.org/) for graph analysis

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
