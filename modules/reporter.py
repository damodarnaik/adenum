"""Report generation module."""

import logging
import json
from typing import Any, Dict, List
from datetime import datetime
from jinja2 import Template
from colorama import Fore, Style, init
import config

# Initialize colorama for Windows
init()


class Reporter:
    """Generate reports in multiple formats."""
    
    def __init__(self):
        """Initialize reporter."""
        self.logger = logging.getLogger(__name__)
    
    def generate_json_report(self, data: Dict[str, Any], output_file: str):
        """
        Generate JSON report.
        
        Args:
            data: All enumeration and analysis data
            output_file: Output file path
        """
        self.logger.info(f"Generating JSON report: {output_file}")
        
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool': 'AD Enumeration Tool',
                'version': '1.0',
            },
            'domain_info': data.get('domain_info', {}),
            'statistics': {
                'total_users': len(data.get('all_users', [])),
                'total_computers': len(data.get('all_computers', [])),
                'total_groups': len(data.get('all_groups', [])),
                'privileged_users': len(data.get('privileged_users', [])),
                'kerberoastable_users': len(data.get('kerberoastable_users', [])),
                'asreproastable_users': len(data.get('asreproastable_users', [])),
                'vulnerabilities': len(data.get('vulnerabilities', [])),
                'attack_paths': len(data.get('attack_paths', [])),
            },
            'vulnerabilities': data.get('vulnerabilities', []),
            'attack_paths': data.get('attack_paths', []),
            'enumeration': {
                'users': data.get('all_users', []),
                'computers': data.get('all_computers', []),
                'groups': data.get('all_groups', []),
                'domain_controllers': data.get('domain_controllers', []),
                'trusts': data.get('trusts', []),
            }
        }
        
        # Convert datetime objects to strings for JSON serialization
        report = self._serialize_datetime(report)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        self.logger.info("JSON report generated successfully")
    
    def generate_text_report(self, data: Dict[str, Any], output_file: str = None):
        """
        Generate text report for console or file.
        
        Args:
            data: All enumeration and analysis data
            output_file: Output file path (None for console output)
        """
        self.logger.info("Generating text report...")
        
        lines = []
        
        # Header
        lines.append("=" * 80)
        lines.append("AD ENUMERATION AND VULNERABILITY ASSESSMENT REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        # Domain Information
        domain_info = data.get('domain_info', {})
        lines.append("[+] DOMAIN INFORMATION")
        lines.append("-" * 80)
        lines.append(f"Domain: {domain_info.get('dns_name', 'N/A')}")
        lines.append(f"Functional Level: {domain_info.get('functional_level', 'N/A')}")
        lines.append(f"Domain SID: {domain_info.get('sid', 'N/A')}")
        lines.append("")
        
        # Statistics
        lines.append("[+] ENUMERATION STATISTICS")
        lines.append("-" * 80)
        lines.append(f"Total Users:       {len(data.get('all_users', []))}")
        lines.append(f"Total Computers:   {len(data.get('all_computers', []))}")
        lines.append(f"Total Groups:      {len(data.get('all_groups', []))}")
        lines.append(f"Privileged Users:  {len(data.get('privileged_users', []))}")
        lines.append(f"Domain Controllers: {len(data.get('domain_controllers', []))}")
        lines.append("")
        
        # Vulnerabilities
        vulnerabilities = data.get('vulnerabilities', [])
        lines.append(f"[+] VULNERABILITIES FOUND: {len(vulnerabilities)}")
        lines.append("-" * 80)
        
        # Group by severity
        by_severity = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in by_severity:
                lines.append(f"\n{self._get_severity_label(severity)} ({len(by_severity[severity])} findings)")
                lines.append("")
                
                for vuln in by_severity[severity]:
                    lines.append(f"  [{vuln.get('type', 'UNKNOWN')}] {vuln.get('title', 'No title')}")
                    lines.append(f"  Risk Score: {vuln.get('risk_score', 0):.1f}/10")
                    lines.append(f"  {vuln.get('description', '')}")
                    
                    if 'affected_accounts' in vuln:
                        accounts = vuln['affected_accounts']
                        if isinstance(accounts, list) and accounts:
                            count = vuln.get('count', len(accounts))
                            shown = accounts[:5]
                            lines.append(f"  Affected: {', '.join(shown)}")
                            if count > 5:
                                lines.append(f"  ... and {count - 5} more")
                    
                    lines.append(f"  Recommendation: {vuln.get('recommendation', 'N/A')}")
                    lines.append("")
        
        # Attack Paths
        attack_paths = data.get('attack_paths', [])
        if attack_paths:
            lines.append(f"[+] ATTACK PATHS TO HIGH-VALUE TARGETS: {len(attack_paths)}")
            lines.append("-" * 80)
            lines.append("")
            
            for i, path in enumerate(attack_paths[:10], 1):
                lines.append(f"Path #{i}: {path.get('source')} → {path.get('target')}")
                lines.append(f"  Length: {path.get('length')} hops | Risk: {path.get('risk_score', 0):.1f}/10")
                lines.append(f"  {path.get('description', '')}")
                lines.append("")
        
        # Recommendations Summary
        lines.append("[+] KEY RECOMMENDATIONS")
        lines.append("-" * 80)
        critical_vulns = by_severity.get('CRITICAL', [])
        high_vulns = by_severity.get('HIGH', [])
        
        priority_fixes = (critical_vulns + high_vulns)[:5]
        for i, vuln in enumerate(priority_fixes, 1):
            lines.append(f"{i}. {vuln.get('recommendation', '')}")
        
        lines.append("")
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        
        report_text = '\n'.join(lines)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            self.logger.info(f"Text report saved to: {output_file}")
        else:
            print(report_text)
    
    def generate_html_report(self, data: Dict[str, Any], output_file: str):
        """
        Generate HTML report.
        
        Args:
            data: All enumeration and analysis data
            output_file: Output file path
        """
        self.logger.info(f"Generating HTML report: {output_file}")
        
        # Read template
        template_path = 'templates/report_template.html'
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
        except FileNotFoundError:
            self.logger.error(f"Template not found: {template_path}")
            return
        
        # Prepare data for template
        template_data = {
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'domain_info': data.get('domain_info', {}),
            'statistics': {
                'total_users': len(data.get('all_users', [])),
                'total_computers': len(data.get('all_computers', [])),
                'total_groups': len(data.get('all_groups', [])),
                'privileged_users': len(data.get('privileged_users', [])),
                'kerberoastable_users': len(data.get('kerberoastable_users', [])),
                'asreproastable_users': len(data.get('asreproastable_users', [])),
                'domain_controllers': len(data.get('domain_controllers', [])),
            },
            'vulnerabilities': self._group_vulnerabilities_by_severity(data.get('vulnerabilities', [])),
            'attack_paths': data.get('attack_paths', [])[:10],
            'domain_controllers': data.get('domain_controllers', []),
            'trusts': data.get('trusts', []),
        }
        
        # Render template
        template = Template(template_content)
        html_content = template.render(**template_data)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info("HTML report generated successfully")
    
    def _group_vulnerabilities_by_severity(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group vulnerabilities by severity."""
        grouped = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFO': [],
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            if severity in grouped:
                grouped[severity].append(vuln)
        
        return grouped
    
    def _get_severity_label(self, severity: str) -> str:
        """Get colored severity label for console output."""
        colors = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.YELLOW,
            'MEDIUM': Fore.BLUE,
            'LOW': Fore.GREEN,
            'INFO': Fore.WHITE,
        }
        
        color = colors.get(severity, Fore.WHITE)
        return f"{color}[{severity}]{Style.RESET_ALL}"
    
    def _serialize_datetime(self, obj: Any) -> Any:
        """Recursively convert datetime objects to ISO format strings."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {k: self._serialize_datetime(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._serialize_datetime(item) for item in obj]
        else:
            return obj
