"""Vulnerability analysis module."""

import logging
from typing import Any, Dict, List
from datetime import datetime, timedelta
import config


class VulnerabilityAnalyzer:
    """Analyze enumerated AD data for vulnerabilities."""
    
    def __init__(self):
        """Initialize vulnerability analyzer."""
        self.logger = logging.getLogger(__name__)
        self.findings = []
    
    def analyze(self, enum_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze all enumerated data for vulnerabilities.
        
        Args:
            enum_data: Dictionary containing all enumeration results
        
        Returns:
            List of vulnerability findings
        """
        self.findings = []
        
        self.logger.info("Starting vulnerability analysis...")
        
        # Analyze different vulnerability categories
        self._analyze_kerberoasting(enum_data.get('kerberoastable_users', []))
        self._analyze_asreproasting(enum_data.get('asreproastable_users', []))
        self._analyze_delegation(
            enum_data.get('delegated_users', []),
            enum_data.get('delegated_computers', [])
        )
        self._analyze_password_policy(enum_data.get('domain_info', {}))
        self._analyze_privileged_accounts(enum_data.get('privileged_users', []))
        self._analyze_stale_accounts(
            enum_data.get('all_users', []),
            enum_data.get('all_computers', [])
        )
        self._analyze_weak_passwords(enum_data.get('all_users', []))
        self._analyze_dnsadmins(enum_data.get('privileged_groups', []))
        
        self.logger.info(f"Found {len(self.findings)} vulnerabilities")
        return self.findings
    
    def _analyze_kerberoasting(self, users: List[Dict[str, Any]]):
        """Analyze kerberoastable users."""
        if not users:
            return
        
        high_priv_kerberoastable = [
            u for u in users 
            if u.get('admin_count') == 1 or self._is_privileged(u)
        ]
        
        if high_priv_kerberoastable:
            self.findings.append({
                'type': 'KERBEROASTING_PRIVILEGED',
                'severity': 'CRITICAL',
                'risk_score': 9.5,
                'title': 'Privileged Accounts Kerberoastable',
                'description': f'{len(high_priv_kerberoastable)} privileged user accounts have SPNs and are vulnerable to Kerberoasting attacks.',
                'affected_accounts': [u['username'] for u in high_priv_kerberoastable],
                'recommendation': 'Use managed service accounts (MSA/gMSA) for service accounts. Ensure service account passwords are long and complex (25+ characters).',
                'attack_vector': 'An attacker can request service tickets for these accounts and perform offline password cracking.',
            })
        
        if users:
            self.findings.append({
                'type': 'KERBEROASTING',
                'severity': 'HIGH',
                'risk_score': 7.5,
                'title': 'Kerberoastable User Accounts',
                'description': f'{len(users)} user accounts with SPNs are vulnerable to Kerberoasting.',
                'affected_accounts': [u['username'] for u in users[:20]],  # Limit output
                'count': len(users),
                'recommendation': 'Migrate to managed service accounts or ensure strong passwords (25+ characters).',
                'attack_vector': 'Service tickets can be requested and cracked offline to obtain plaintext passwords.',
            })
    
    def _analyze_asreproasting(self, users: List[Dict[str, Any]]):
        """Analyze AS-REP roastable users."""
        if not users:
            return
        
        self.findings.append({
            'type': 'ASREPROAST',
            'severity': 'HIGH',
            'risk_score': 7.0,
            'title': 'AS-REP Roastable Accounts',
            'description': f'{len(users)} accounts do not require Kerberos pre-authentication (DONT_REQ_PREAUTH).',
            'affected_accounts': [u['username'] for u in users],
            'recommendation': 'Remove the "Do not require Kerberos preauthentication" flag from all accounts unless absolutely necessary.',
            'attack_vector': 'AS-REP messages can be captured and cracked offline without authentication.',
        })
    
    def _analyze_delegation(self, users: List[Dict[str, Any]], computers: List[Dict[str, Any]]):
        """Analyze delegation vulnerabilities."""
        # Unconstrained delegation
        unconstrained_users = [
            u for u in users 
            if u.get('uac_flags', {}).get('TRUSTED_FOR_DELEGATION', False)
        ]
        unconstrained_computers = [
            c for c in computers 
            if c.get('uac_flags', {}).get('TRUSTED_FOR_DELEGATION', False) and not c.get('is_dc', False)
        ]
        
        if unconstrained_users or unconstrained_computers:
            self.findings.append({
                'type': 'UNCONSTRAINED_DELEGATION',
                'severity': 'CRITICAL',
                'risk_score': 9.0,
                'title': 'Unconstrained Delegation Enabled',
                'description': f'{len(unconstrained_users)} users and {len(unconstrained_computers)} computers have unconstrained delegation enabled.',
                'affected_users': [u['username'] for u in unconstrained_users],
                'affected_computers': [c['name'] for c in unconstrained_computers],
                'recommendation': 'Disable unconstrained delegation. Use constrained delegation or resource-based constrained delegation instead.',
                'attack_vector': 'Compromise of delegated accounts allows impersonation of any user to any service.',
            })
        
        # Constrained delegation
        constrained_users = [u for u in users if u.get('allowed_to_delegate')]
        constrained_computers = [c for c in computers if c.get('allowed_to_delegate')]
        
        if constrained_users or constrained_computers:
            self.findings.append({
                'type': 'CONSTRAINED_DELEGATION',
                'severity': 'MEDIUM',
                'risk_score': 5.5,
                'title': 'Constrained Delegation Configured',
                'description': f'{len(constrained_users)} users and {len(constrained_computers)} computers have constrained delegation configured.',
                'affected_users': [u['username'] for u in constrained_users],
                'affected_computers': [c['name'] for c in constrained_computers],
                'recommendation': 'Review delegation configurations to ensure they follow least privilege principles.',
                'attack_vector': 'Compromised accounts can impersonate users to specific services.',
            })
        
        # RBCD
        rbcd_users = [u for u in users if u.get('rbcd')]
        rbcd_computers = [c for c in computers if c.get('rbcd')]
        
        if rbcd_users or rbcd_computers:
            self.findings.append({
                'type': 'RBCD',
                'severity': 'MEDIUM',
                'risk_score': 6.0,
                'title': 'Resource-Based Constrained Delegation',
                'description': f'{len(rbcd_users)} users and {len(rbcd_computers)} computers have RBCD configured.',
                'affected_users': [u['username'] for u in rbcd_users],
                'affected_computers': [c['name'] for c in rbcd_computers],
                'recommendation': 'Review RBCD configurations and ensure proper access controls.',
                'attack_vector': 'Accounts with write access to msDS-AllowedToActOnBehalfOfOtherIdentity can configure RBCD.',
            })
    
    def _analyze_password_policy(self, domain_info: Dict[str, Any]):
        """Analyze password policy for weaknesses."""
        policy = domain_info.get('password_policy', {})
        
        if not policy:
            return
        
        issues = []
        
        # Check minimum password length
        min_length = policy.get('min_password_length', 0)
        if min_length < 14:
            issues.append(f'Minimum password length is {min_length} (recommended: 14+)')
        
        # Check lockout threshold
        lockout = policy.get('lockout_threshold', 0)
        if lockout == 0:
            issues.append('Account lockout is disabled (allows unlimited password attempts)')
        elif lockout > 5:
            issues.append(f'Lockout threshold is {lockout} (recommended: 3-5)')
        
        # Check password history
        history = policy.get('password_history', 0)
        if history < 24:
            issues.append(f'Password history is {history} (recommended: 24+)')
        
        if issues:
            self.findings.append({
                'type': 'WEAK_PASSWORD_POLICY',
                'severity': 'HIGH',
                'risk_score': 7.5,
                'title': 'Weak Password Policy',
                'description': 'Domain password policy has multiple weaknesses.',
                'issues': issues,
                'recommendation': 'Strengthen password policy: 14+ character minimum, 3-5 lockout threshold, 24 password history.',
                'attack_vector': 'Weak policies facilitate password attacks (brute force, password spraying).',
            })
    
    def _analyze_privileged_accounts(self, users: List[Dict[str, Any]]):
        """Analyze privileged accounts for security issues."""
        issues = []
        
        for user in users:
            user_issues = []
            
            # Check if password never expires
            if user.get('uac_flags', {}).get('DONT_EXPIRE_PASSWORD', False):
                user_issues.append('Password never expires')
            
            # Check if smartcard not required
            if not user.get('uac_flags', {}).get('SMARTCARD_REQUIRED', False):
                user_issues.append('Smartcard not required')
            
            # Check password age
            pwd_age = user.get('password_age_days')
            if pwd_age and pwd_age > 365:
                user_issues.append(f'Password not changed in {pwd_age} days')
            
            if user_issues:
                issues.append({
                    'username': user['username'],
                    'issues': user_issues
                })
        
        if issues:
            self.findings.append({
                'type': 'PRIVILEGED_ACCOUNT_ISSUES',
                'severity': 'HIGH',
                'risk_score': 8.0,
                'title': 'Privileged Account Security Issues',
                'description': f'{len(issues)} privileged accounts have security concerns.',
                'affected_accounts': issues,
                'recommendation': 'Enable smartcard requirement for privileged accounts. Set password expiration. Implement regular password rotation.',
                'attack_vector': 'Privileged accounts with weak security controls are high-value targets.',
            })
    
    def _analyze_stale_accounts(self, users: List[Dict[str, Any]], computers: List[Dict[str, Any]]):
        """Analyze stale/inactive accounts."""
        stale_users = []
        stale_computers = []
        
        now = datetime.now()
        
        for user in users:
            last_logon = user.get('last_logon')
            if last_logon:
                days_inactive = (now - last_logon).days
                if days_inactive > config.PASSWORD_AGE_THRESHOLDS['inactive_user']:
                    stale_users.append({
                        'username': user['username'],
                        'days_inactive': days_inactive
                    })
        
        for computer in computers:
            last_logon = computer.get('last_logon')
            if last_logon:
                days_inactive = (now - last_logon).days
                if days_inactive > config.PASSWORD_AGE_THRESHOLDS['stale_computer']:
                    stale_computers.append({
                        'name': computer['name'],
                        'days_inactive': days_inactive
                    })
        
        if stale_users:
            self.findings.append({
                'type': 'STALE_USERS',
                'severity': 'MEDIUM',
                'risk_score': 5.0,
                'title': 'Stale User Accounts',
                'description': f'{len(stale_users)} user accounts inactive for over 1 year.',
                'affected_accounts': [u['username'] for u in stale_users[:50]],
                'count': len(stale_users),
                'recommendation': 'Disable or remove inactive accounts. Implement automated account deprovisioning.',
                'attack_vector': 'Stale accounts are often overlooked and can be compromised without detection.',
            })
        
        if stale_computers:
            self.findings.append({
                'type': 'STALE_COMPUTERS',
                'severity': 'MEDIUM',
                'risk_score': 4.5,
                'title': 'Stale Computer Accounts',
                'description': f'{len(stale_computers)} computer accounts inactive for over 90 days.',
                'affected_accounts': [c['name'] for c in stale_computers[:50]],
                'count': len(stale_computers),
                'recommendation': 'Remove inactive computer accounts from the domain.',
                'attack_vector': 'Stale computer accounts can be compromised to gain domain access.',
            })
    
    def _analyze_weak_passwords(self, users: List[Dict[str, Any]]):
        """Analyze accounts with weak password settings."""
        weak_pwd_accounts = []
        
        for user in users:
            issues = []
            
            if user.get('uac_flags', {}).get('PASSWD_NOTREQD', False):
                issues.append('Password not required')
            
            if user.get('uac_flags', {}).get('ENCRYPTED_TEXT_PWD_ALLOWED', False):
                issues.append('Reversible encryption enabled')
            
            if issues:
                weak_pwd_accounts.append({
                    'username': user['username'],
                    'issues': issues
                })
        
        if weak_pwd_accounts:
            self.findings.append({
                'type': 'WEAK_PASSWORD_SETTINGS',
                'severity': 'HIGH',
                'risk_score': 7.0,
                'title': 'Weak Password Settings on Accounts',
                'description': f'{len(weak_pwd_accounts)} accounts have weak password settings.',
                'affected_accounts': weak_pwd_accounts,
                'recommendation': 'Require passwords for all accounts. Disable reversible encryption.',
                'attack_vector': 'Accounts without password requirements or with reversible encryption are easily compromised.',
            })
    
    def _analyze_dnsadmins(self, groups: List[Dict[str, Any]]):
        """Analyze DNSAdmins group membership."""
        dnsadmins = next((g for g in groups if 'dnsadmins' in g.get('name', '').lower()), None)
        
        if dnsadmins and dnsadmins.get('members'):
            self.findings.append({
                'type': 'DNSADMINS',
                'severity': 'HIGH',
                'risk_score': 7.5,
                'title': 'DNSAdmins Group Members Detected',
                'description': f'DNSAdmins group has {len(dnsadmins["members"])} members.',
                'members': dnsadmins['members'][:20],
                'recommendation': 'Review DNSAdmins membership. Members can load arbitrary DLLs on DNS servers.',
                'attack_vector': 'DNSAdmins can achieve code execution on DNS servers (often DCs) via DLL injection.',
            })
    
    def _is_privileged(self, user: Dict[str, Any]) -> bool:
        """Check if user is in privileged groups."""
        privileged_keywords = [
            'domain admins', 'enterprise admins', 'administrators',
            'schema admins', 'account operators'
        ]
        
        for group in user.get('groups', []):
            if any(keyword in group.lower() for keyword in privileged_keywords):
                return True
        
        return False
