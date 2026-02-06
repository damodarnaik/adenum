"""Utility functions for AD enumeration."""

import datetime
from typing import Any, Dict, List, Optional
import struct


def filetime_to_datetime(filetime: int) -> Optional[datetime.datetime]:
    """
    Convert Windows FILETIME to datetime.
    
    Args:
        filetime: Windows FILETIME (100-nanosecond intervals since 1601-01-01)
    
    Returns:
        datetime object or None if invalid
    """
    if not filetime or filetime == 0 or filetime == 0x7FFFFFFFFFFFFFFF:
        return None
    
    try:
        # FILETIME epoch is 1601-01-01
        epoch = datetime.datetime(1601, 1, 1)
        return epoch + datetime.timedelta(microseconds=filetime / 10)
    except (ValueError, OverflowError):
        return None


def parse_user_account_control(uac: int) -> Dict[str, bool]:
    """
    Parse userAccountControl bitmask.
    
    Args:
        uac: userAccountControl integer value
    
    Returns:
        Dictionary of UAC flags and their boolean values
    """
    flags = {
        'SCRIPT': 0x0001,
        'ACCOUNTDISABLE': 0x0002,
        'HOMEDIR_REQUIRED': 0x0008,
        'LOCKOUT': 0x0010,
        'PASSWD_NOTREQD': 0x0020,
        'PASSWD_CANT_CHANGE': 0x0040,
        'ENCRYPTED_TEXT_PWD_ALLOWED': 0x0080,
        'TEMP_DUPLICATE_ACCOUNT': 0x0100,
        'NORMAL_ACCOUNT': 0x0200,
        'INTERDOMAIN_TRUST_ACCOUNT': 0x0800,
        'WORKSTATION_TRUST_ACCOUNT': 0x1000,
        'SERVER_TRUST_ACCOUNT': 0x2000,
        'DONT_EXPIRE_PASSWORD': 0x10000,
        'MNS_LOGON_ACCOUNT': 0x20000,
        'SMARTCARD_REQUIRED': 0x40000,
        'TRUSTED_FOR_DELEGATION': 0x80000,
        'NOT_DELEGATED': 0x100000,
        'USE_DES_KEY_ONLY': 0x200000,
        'DONT_REQ_PREAUTH': 0x400000,
        'PASSWORD_EXPIRED': 0x800000,
        'TRUSTED_TO_AUTH_FOR_DELEGATION': 0x1000000,
        'PARTIAL_SECRETS_ACCOUNT': 0x04000000,
    }
    
    return {name: bool(uac & value) for name, value in flags.items()}


def parse_sid(sid_bytes: bytes) -> str:
    """
    Parse binary SID to string representation.
    
    Args:
        sid_bytes: Binary SID data
    
    Returns:
        SID string (e.g., S-1-5-21-...)
    """
    try:
        # SID structure: revision(1) + subauth_count(1) + authority(6) + subauths(4*n)
        revision = sid_bytes[0]
        subauth_count = sid_bytes[1]
        authority = struct.unpack('>Q', b'\x00\x00' + sid_bytes[2:8])[0]
        
        sid_parts = [f'S-{revision}', str(authority)]
        
        for i in range(subauth_count):
            offset = 8 + (i * 4)
            subauth = struct.unpack('<I', sid_bytes[offset:offset + 4])[0]
            sid_parts.append(str(subauth))
        
        return '-'.join(sid_parts)
    except (IndexError, struct.error):
        return ''


def get_relative_id(sid: str) -> Optional[str]:
    """
    Extract the relative ID (RID) from a SID.
    
    Args:
        sid: SID string
    
    Returns:
        RID as string or None
    """
    parts = sid.split('-')
    if len(parts) >= 2:
        return parts[-1]
    return None


def calculate_password_age(pwd_last_set: int) -> Optional[int]:
    """
    Calculate password age in days.
    
    Args:
        pwd_last_set: pwdLastSet attribute value
    
    Returns:
        Age in days or None
    """
    if not pwd_last_set or pwd_last_set == 0:
        return None
    
    pwd_date = filetime_to_datetime(pwd_last_set)
    if pwd_date:
        age = datetime.datetime.now() - pwd_date
        return age.days
    return None


def calculate_risk_score(findings: List[str], severity_map: Dict[str, float]) -> float:
    """
    Calculate overall risk score based on findings.
    
    Args:
        findings: List of finding identifiers
        severity_map: Mapping of finding types to severity scores
    
    Returns:
        Combined risk score
    """
    if not findings:
        return 0.0
    
    scores = [severity_map.get(finding, 1.0) for finding in findings]
    # Use maximum score as the overall risk
    return max(scores) if scores else 0.0


def format_dn(distinguished_name: str) -> str:
    """
    Format distinguished name for readable output.
    
    Args:
        distinguished_name: Full DN
    
    Returns:
        Formatted DN with proper spacing
    """
    return distinguished_name.replace(',', ', ')


def extract_domain_from_dn(dn: str) -> str:
    """
    Extract domain name from distinguished name.
    
    Args:
        dn: Distinguished name
    
    Returns:
        Domain in DNS format (e.g., example.com)
    """
    parts = [p.split('=')[1] for p in dn.split(',') if p.startswith('DC=')]
    return '.'.join(parts)


def is_privileged_group(group_sid: str, domain_sid: str) -> bool:
    """
    Check if a group is a well-known privileged group.
    
    Args:
        group_sid: Full SID of the group
        domain_sid: Domain SID
    
    Returns:
        True if privileged group
    """
    from config import HIGH_PRIVILEGE_GROUPS
    
    rid = get_relative_id(group_sid)
    return rid in HIGH_PRIVILEGE_GROUPS if rid else False


def get_severity_color(severity: str) -> str:
    """
    Get color code for severity level.
    
    Args:
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    
    Returns:
        ANSI color code
    """
    colors = {
        'CRITICAL': '\033[91m',  # Red
        'HIGH': '\033[93m',      # Yellow
        'MEDIUM': '\033[94m',    # Blue
        'LOW': '\033[92m',       # Green
        'INFO': '\033[37m',      # White
    }
    return colors.get(severity, '\033[0m')


def reset_color() -> str:
    """Get ANSI reset code."""
    return '\033[0m'
