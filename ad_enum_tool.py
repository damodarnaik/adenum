"""
AD Enumeration & Vulnerability Analysis Tool
For authorized penetration testing only
"""

import argparse
import logging
import sys
from datetime import datetime

from modules.ldap_connector import LDAPConnector
from modules.domain_enum import DomainEnumerator
from modules.user_enum import UserEnumerator
from modules.computer_enum import ComputerEnumerator
from modules.group_enum import GroupEnumerator
from modules.vuln_analyzer import VulnerabilityAnalyzer
from modules.attack_paths import AttackPathAnalyzer
from modules.reporter import Reporter


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def main():
    parser = argparse.ArgumentParser(
        description='Active Directory Enumeration and Vulnerability Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic enumeration with password auth
  python ad_enum_tool.py -d example.com -u admin -p Password123 -t 192.168.1.10

  # Full enumeration with HTML report
  python ad_enum_tool.py -d example.com -u admin -p Password123 -t 192.168.1.10 --full-enum --output-html report.html

  # Pass-the-hash authentication
  python ad_enum_tool.py -d example.com -u admin --nthash <hash> -t 192.168.1.10

  # Output to multiple formats
  python ad_enum_tool.py -d example.com -u admin -p Password123 -t 192.168.1.10 --output-json data.json --output-html report.html
        """
    )

    # Connection arguments
    conn_group = parser.add_argument_group('Connection')
    conn_group.add_argument('-d', '--domain', required=True, help='Target domain (e.g., example.com)')
    conn_group.add_argument('-u', '--username', required=True, help='Username for authentication')
    conn_group.add_argument('-p', '--password', help='Password for authentication')
    conn_group.add_argument('-t', '--target', required=True, help='Domain controller IP address')
    conn_group.add_argument('--lmhash', default='', help='LM hash for pass-the-hash')
    conn_group.add_argument('--nthash', default='', help='NT hash for pass-the-hash')
    conn_group.add_argument('--kerberos', action='store_true', help='Use Kerberos authentication')

    # Enumeration options
    enum_group = parser.add_argument_group('Enumeration Options')
    enum_group.add_argument('--full-enum', action='store_true', help='Perform full enumeration (default: targeted)')
    enum_group.add_argument('--users', action='store_true', help='Enumerate users')
    enum_group.add_argument('--computers', action='store_true', help='Enumerate computers')
    enum_group.add_argument('--groups', action='store_true', help='Enumerate groups')
    enum_group.add_argument('--domain-info', action='store_true', help='Enumerate domain information')
    enum_group.add_argument('--vuln-scan', action='store_true', help='Perform vulnerability analysis')
    enum_group.add_argument('--attack-paths', action='store_true', help='Find attack paths')

    # OpSec / Stealth options
    opsec_group = parser.add_argument_group('OpSec / Stealth Options')
    opsec_group.add_argument('--stealth', action='store_true', help='Enable stealth mode (rate limiting, delays, randomization)')
    opsec_group.add_argument('--delay-min', type=float, help='Minimum delay between queries (seconds)')
    opsec_group.add_argument('--delay-max', type=float, help='Maximum delay between queries (seconds)')
    opsec_group.add_argument('--max-qpm', type=int, help='Maximum queries per minute')
    opsec_group.add_argument('--spread-hours', type=float, help='Spread enumeration over N hours')

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--output-json', help='Output JSON report to file')
    output_group.add_argument('--output-html', help='Output HTML report to file')
    output_group.add_argument('--output-text', help='Output text report to file')
    output_group.add_argument('--quiet', action='store_true', help='Suppress console output')

    # General options
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    # Validate authentication
    if not args.password and not args.nthash:
        parser.error("Either --password or --nthash is required")

    # If no specific enumeration is selected, use full enumeration
    if not any([args.users, args.computers, args.groups, args.domain_info, 
                args.vuln_scan, args.attack_paths]):
        args.full_enum = True

    logger.info("=" * 60)
    logger.info("AD Enumeration & Vulnerability Analysis Tool")
    logger.info("=" * 60)
    logger.info(f"Target Domain: {args.domain}")
    logger.info(f"Domain Controller: {args.target}")
    logger.info(f"Username: {args.username}")
    
    # Configure stealth mode
    if args.stealth:
        import config as cfg
        cfg.STEALTH_SETTINGS['enabled'] = True
        if args.delay_min:
            cfg.STEALTH_SETTINGS['query_delay_min'] = args.delay_min
        if args.delay_max:
            cfg.STEALTH_SETTINGS['query_delay_max'] = args.delay_max
        if args.max_qpm:
            cfg.STEALTH_SETTINGS['max_queries_per_minute'] = args.max_qpm
        if args.spread_hours:
            cfg.STEALTH_SETTINGS['spread_enumeration_hours'] = args.spread_hours
        
        logger.info("")
        logger.info("[!] STEALTH MODE ENABLED")
        logger.info(f"    Delay: {cfg.STEALTH_SETTINGS['query_delay_min']}-{cfg.STEALTH_SETTINGS['query_delay_max']}s")
        logger.info(f"    Rate Limit: {cfg.STEALTH_SETTINGS['max_queries_per_minute']} QPM")
        if cfg.STEALTH_SETTINGS['spread_enumeration_hours'] > 0:
            logger.info(f"    Spread Duration: {cfg.STEALTH_SETTINGS['spread_enumeration_hours']} hours")
    
    logger.info("")

    # Connect to LDAP
    logger.info("[*] Establishing LDAP connection...")
    ldap_conn = LDAPConnector(
        domain=args.domain,
        username=args.username,
        password=args.password or '',
        dc_ip=args.target,
        use_kerberos=args.kerberos,
        lmhash=args.lmhash,
        nthash=args.nthash,
        stealth_mode=args.stealth
    )

    if not ldap_conn.connect():
        logger.error("[!] Failed to establish LDAP connection")
        sys.exit(1)

    logger.info("[+] LDAP connection established successfully")
    logger.info("")

    # Storage for all enumeration data
    enum_data = {}

    try:
        # Domain enumeration
        if args.full_enum or args.domain_info:
            logger.info("[*] Enumerating domain information...")
            domain_enum = DomainEnumerator(ldap_conn)
            enum_data['domain_info'] = domain_enum.enumerate_domain_info()
            enum_data['domain_controllers'] = domain_enum.enumerate_domain_controllers()
            enum_data['trusts'] = domain_enum.enumerate_trusts()
            enum_data['sites'] = domain_enum.enumerate_sites()
            logger.info(f"[+] Found {len(enum_data['domain_controllers'])} domain controllers")
            logger.info(f"[+] Found {len(enum_data['trusts'])} trust relationships")
            logger.info("")

        # User enumeration
        if args.full_enum or args.users:
            logger.info("[*] Enumerating users...")
            user_enum = UserEnumerator(ldap_conn)
            enum_data['all_users'] = user_enum.enumerate_all_users()
            enum_data['privileged_users'] = user_enum.enumerate_privileged_users()
            enum_data['kerberoastable_users'] = user_enum.enumerate_kerberoastable_users()
            enum_data['asreproastable_users'] = user_enum.enumerate_asreproastable_users()
            enum_data['delegated_users'] = user_enum.enumerate_delegated_users()
            logger.info(f"[+] Found {len(enum_data['all_users'])} total users")
            logger.info(f"[+] Found {len(enum_data['privileged_users'])} privileged users")
            logger.info(f"[+] Found {len(enum_data['kerberoastable_users'])} kerberoastable users")
            logger.info(f"[+] Found {len(enum_data['asreproastable_users'])} AS-REP roastable users")
            logger.info("")

        # Computer enumeration
        if args.full_enum or args.computers:
            logger.info("[*] Enumerating computers...")
            computer_enum = ComputerEnumerator(ldap_conn)
            enum_data['all_computers'] = computer_enum.enumerate_all_computers()
            enum_data['servers'] = computer_enum.enumerate_servers()
            enum_data['delegated_computers'] = computer_enum.enumerate_delegated_computers()
            logger.info(f"[+] Found {len(enum_data['all_computers'])} total computers")
            logger.info(f"[+] Found {len(enum_data['servers'])} servers")
            logger.info("")

        # Group enumeration
        if args.full_enum or args.groups:
            logger.info("[*] Enumerating groups...")
            group_enum = GroupEnumerator(ldap_conn)
            enum_data['all_groups'] = group_enum.enumerate_all_groups()
            enum_data['privileged_groups'] = group_enum.enumerate_privileged_groups()
            logger.info(f"[+] Found {len(enum_data['all_groups'])} total groups")
            logger.info(f"[+] Found {len(enum_data['privileged_groups'])} privileged groups")
            logger.info("")

        # Vulnerability analysis
        if args.full_enum or args.vuln_scan:
            logger.info("[*] Performing vulnerability analysis...")
            vuln_analyzer = VulnerabilityAnalyzer()
            enum_data['vulnerabilities'] = vuln_analyzer.analyze(enum_data)
            
            # Count by severity
            severity_counts = {}
            for vuln in enum_data['vulnerabilities']:
                severity = vuln.get('severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            logger.info(f"[+] Found {len(enum_data['vulnerabilities'])} total vulnerabilities")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if severity in severity_counts:
                    logger.info(f"    - {severity}: {severity_counts[severity]}")
            logger.info("")

        # Attack path analysis
        if args.full_enum or args.attack_paths:
            logger.info("[*] Analyzing attack paths...")
            attack_analyzer = AttackPathAnalyzer()
            attack_analyzer.build_graph(enum_data)
            enum_data['attack_paths'] = attack_analyzer.find_attack_paths()
            enum_data['graph_stats'] = attack_analyzer.get_statistics()
            logger.info(f"[+] Found {len(enum_data['attack_paths'])} attack paths")
            logger.info("")

        # Generate reports
        reporter = Reporter()

        if args.output_json:
            logger.info(f"[*] Generating JSON report: {args.output_json}")
            reporter.generate_json_report(enum_data, args.output_json)
            logger.info("[+] JSON report generated")

        if args.output_html:
            logger.info(f"[*] Generating HTML report: {args.output_html}")
            reporter.generate_html_report(enum_data, args.output_html)
            logger.info("[+] HTML report generated")

        if args.output_text:
            logger.info(f"[*] Generating text report: {args.output_text}")
            reporter.generate_text_report(enum_data, args.output_text)
            logger.info("[+] Text report generated")

        # Console output if not quiet
        if not args.quiet and not any([args.output_json, args.output_html, args.output_text]):
            reporter.generate_text_report(enum_data)

        # Show stealth session statistics
        if args.stealth:
            stats = ldap_conn.stealth.get_session_stats()
            logger.info("")
            logger.info("[*] Stealth Session Statistics:")
            logger.info(f"    Total Queries: {stats['total_queries']}")
            logger.info(f"    Session Duration: {stats['elapsed_time']}")
            logger.info(f"    Avg Queries/Min: {stats['queries_per_minute']:.1f}")

        logger.info("")
        logger.info("=" * 60)
        logger.info("[+] Enumeration completed successfully")
        logger.info("=" * 60)

    except KeyboardInterrupt:
        logger.warning("\n[!] Enumeration interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"[!] Error during enumeration: {e}", exc_info=True)
        sys.exit(1)
    finally:
        ldap_conn.close()


if __name__ == '__main__':
    main()
