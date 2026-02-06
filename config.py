"""Configuration settings for AD enumeration tool."""

# LDAP Search Filters
LDAP_FILTERS = {
    'all_users': '(&(objectCategory=person)(objectClass=user))',
    'all_computers': '(objectClass=computer)',
    'all_groups': '(objectClass=group)',
    'spn_users': '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))',
    'asrep_users': '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
    'trusted_for_delegation': '(userAccountControl:1.2.840.113556.1.4.803:=524288)',
    'domain_controllers': '(userAccountControl:1.2.840.113556.1.4.803:=8192)',
}

# High-Privilege Group SIDs (relative to domain)
HIGH_PRIVILEGE_GROUPS = {
    '512': 'Domain Admins',
    '519': 'Enterprise Admins',
    '544': 'Administrators',
    '548': 'Account Operators',
    '549': 'Server Operators',
    '550': 'Print Operators',
    '551': 'Backup Operators',
    '552': 'Replicator',
    '518': 'Schema Admins',
    '520': 'Group Policy Creator Owners',
}

# Interesting User Attributes
USER_ATTRIBUTES = [
    'sAMAccountName', 'distinguishedName', 'userPrincipalName',
    'displayName', 'description', 'mail', 'memberOf',
    'userAccountControl', 'pwdLastSet', 'lastLogon', 'lastLogonTimestamp',
    'badPwdCount', 'logonCount', 'adminCount', 'servicePrincipalName',
    'objectSid', 'primaryGroupID', 'whenCreated', 'whenChanged',
    'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity',
]

# Computer Attributes
COMPUTER_ATTRIBUTES = [
    'sAMAccountName', 'distinguishedName', 'dNSHostName',
    'operatingSystem', 'operatingSystemVersion', 'description',
    'userAccountControl', 'lastLogon', 'lastLogonTimestamp',
    'servicePrincipalName', 'objectSid', 'whenCreated',
    'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity',
]

# Group Attributes
GROUP_ATTRIBUTES = [
    'sAMAccountName', 'distinguishedName', 'description',
    'member', 'memberOf', 'objectSid', 'groupType', 'adminCount',
]

# Domain Attributes
DOMAIN_ATTRIBUTES = [
    'distinguishedName', 'name', 'dc', 'objectSid',
    'msDS-Behavior-Version', 'lockoutThreshold', 'lockoutDuration',
    'lockOutObservationWindow', 'minPwdLength', 'minPwdAge', 'maxPwdAge',
    'pwdHistoryLength', 'pwdProperties',
]

# Risk Scoring Thresholds
RISK_SCORES = {
    'CRITICAL': 9.0,
    'HIGH': 7.0,
    'MEDIUM': 5.0,
    'LOW': 3.0,
    'INFO': 1.0,
}

# Password Age Thresholds (in days)
PASSWORD_AGE_THRESHOLDS = {
    'stale_user': 180,      # Users who haven't changed password in 6 months
    'stale_computer': 90,   # Computers that haven't authenticated in 3 months
    'inactive_user': 365,   # Users inactive for 1 year
}

# Report Settings
REPORT_SETTINGS = {
    'max_attack_paths': 10,  # Maximum attack paths to show in report
    'graph_depth': 5,        # Maximum depth for attack path graph traversal
}

# LDAP Connection Settings
LDAP_SETTINGS = {
    'page_size': 1000,       # LDAP paging size
    'timeout': 30,           # Connection timeout in seconds
    'use_ssl': False,        # Use LDAPS by default
}

# Stealth/OpSec Settings for Red Team Operations
STEALTH_SETTINGS = {
    'enabled': False,                    # Enable stealth mode
    'query_delay_min': 2.0,              # Minimum delay between queries (seconds)
    'query_delay_max': 8.0,              # Maximum delay between queries (seconds)
    'jitter_enabled': True,              # Add random jitter to delays
    'jitter_percentage': 30,             # Jitter variance (% of delay)
    'max_queries_per_minute': 15,        # Rate limit for queries
    'page_size_stealth': 100,            # Smaller page size for stealth (vs 1000)
    'randomize_query_order': True,       # Randomize enumeration order
    'connection_reuse': True,            # Reuse LDAP connections
    'spread_enumeration_hours': 0,       # Spread enumeration over N hours (0=disabled)
}

# Behavioral OpSec - Query Patterns
OPSEC_PATTERNS = {
    'use_targeted_queries': False,       # Only query specific OUs (set target_ous)
    'target_ous': [],                    # List of target OUs when targeted mode enabled
    'exclude_attributes': [],            # Attributes to exclude from queries
    'incremental_enum': False,           # Enumerate incrementally over multiple sessions
    'batch_size': 50,                    # Objects to enumerate per batch in incremental mode
}
