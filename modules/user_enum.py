"""User enumeration and analysis module."""

import logging
from typing import Any, Dict, List, Optional
from modules.ldap_connector import LDAPConnector
from modules.utils import (
    filetime_to_datetime, parse_user_account_control, 
    parse_sid, calculate_password_age
)
import config


class UserEnumerator:
    """Enumerate and analyze user accounts."""
    
    def __init__(self, ldap_conn: LDAPConnector):
        """
        Initialize user enumerator.
        
        Args:
            ldap_conn: Active LDAP connection
        """
        self.ldap = ldap_conn
        self.logger = logging.getLogger(__name__)
    
    def enumerate_all_users(self) -> List[Dict[str, Any]]:
        """
        Enumerate all user accounts.
        
        Returns:
            List of user information dictionaries
        """
        self.logger.info("Enumerating all users...")
        
        try:
            results = self.ldap.search(
                search_filter=config.LDAP_FILTERS['all_users'],
                attributes=config.USER_ATTRIBUTES
            )
            
            users = []
            for result in results:
                user_info = self._parse_user(result)
                users.append(user_info)
            
            self.logger.info(f"Found {len(users)} users")
            return users
            
        except Exception as e:
            self.logger.error(f"User enumeration failed: {e}")
            return []
    
    def enumerate_privileged_users(self) -> List[Dict[str, Any]]:
        """
        Enumerate users in high-privilege groups.
        
        Returns:
            List of privileged user dictionaries
        """
        self.logger.info("Enumerating privileged users...")
        
        privileged_users = []
        all_users = self.enumerate_all_users()
        
        for user in all_users:
            if user.get('admin_count') == 1 or self._is_privileged_user(user):
                privileged_users.append(user)
        
        self.logger.info(f"Found {len(privileged_users)} privileged users")
        return privileged_users
    
    def enumerate_kerberoastable_users(self) -> List[Dict[str, Any]]:
        """
        Enumerate users with SPNs (Kerberoastable).
        
        Returns:
            List of kerberoastable user dictionaries
        """
        self.logger.info("Enumerating kerberoastable users...")
        
        try:
            results = self.ldap.search(
                search_filter=config.LDAP_FILTERS['spn_users'],
                attributes=config.USER_ATTRIBUTES
            )
            
            users = []
            for result in results:
                user_info = self._parse_user(result)
                # Exclude computer accounts and krbtgt
                if (not user_info['username'].endswith('$') and 
                    user_info['username'].lower() != 'krbtgt'):
                    users.append(user_info)
            
            self.logger.info(f"Found {len(users)} kerberoastable users")
            return users
            
        except Exception as e:
            self.logger.error(f"Kerberoastable user enumeration failed: {e}")
            return []
    
    def enumerate_asreproastable_users(self) -> List[Dict[str, Any]]:
        """
        Enumerate users without Kerberos pre-authentication (AS-REP roastable).
        
        Returns:
            List of AS-REP roastable user dictionaries
        """
        self.logger.info("Enumerating AS-REP roastable users...")
        
        try:
            results = self.ldap.search(
                search_filter=config.LDAP_FILTERS['asrep_users'],
                attributes=config.USER_ATTRIBUTES
            )
            
            users = []
            for result in results:
                user_info = self._parse_user(result)
                users.append(user_info)
            
            self.logger.info(f"Found {len(users)} AS-REP roastable users")
            return users
            
        except Exception as e:
            self.logger.error(f"AS-REP roastable user enumeration failed: {e}")
            return []
    
    def enumerate_delegated_users(self) -> List[Dict[str, Any]]:
        """
        Enumerate users with delegation enabled.
        
        Returns:
            List of delegated user dictionaries
        """
        self.logger.info("Enumerating delegated users...")
        
        try:
            results = self.ldap.search(
                search_filter=config.LDAP_FILTERS['trusted_for_delegation'],
                attributes=config.USER_ATTRIBUTES
            )
            
            users = []
            for result in results:
                user_info = self._parse_user(result)
                # Exclude computer accounts
                if not user_info['username'].endswith('$'):
                    users.append(user_info)
            
            self.logger.info(f"Found {len(users)} delegated users")
            return users
            
        except Exception as e:
            self.logger.error(f"Delegated user enumeration failed: {e}")
            return []
    
    def _parse_user(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse user attributes into structured dictionary.
        
        Args:
            attrs: Raw LDAP attributes
        
        Returns:
            Parsed user information
        """
        user_info = {}
        
        # Basic attributes
        user_info['username'] = self._get_attr(attrs, 'sAMAccountName')
        user_info['dn'] = self._get_attr(attrs, 'distinguishedName')
        user_info['upn'] = self._get_attr(attrs, 'userPrincipalName')
        user_info['display_name'] = self._get_attr(attrs, 'displayName')
        user_info['description'] = self._get_attr(attrs, 'description')
        user_info['email'] = self._get_attr(attrs, 'mail')
        
        # SID
        sid_bytes = self._get_attr(attrs, 'objectSid', raw=True)
        if sid_bytes:
            user_info['sid'] = parse_sid(sid_bytes)
        else:
            user_info['sid'] = None
        
        # User Account Control
        uac = self._get_attr(attrs, 'userAccountControl', as_int=True)
        user_info['uac'] = uac
        user_info['uac_flags'] = parse_user_account_control(uac)
        user_info['enabled'] = not user_info['uac_flags'].get('ACCOUNTDISABLE', False)
        
        # Password information
        pwd_last_set = self._get_attr(attrs, 'pwdLastSet', as_int=True)
        user_info['pwd_last_set'] = filetime_to_datetime(pwd_last_set)
        user_info['password_age_days'] = calculate_password_age(pwd_last_set)
        
        # Logon information
        last_logon = self._get_attr(attrs, 'lastLogonTimestamp', as_int=True)
        user_info['last_logon'] = filetime_to_datetime(last_logon)
        user_info['logon_count'] = self._get_attr(attrs, 'logonCount', as_int=True)
        user_info['bad_pwd_count'] = self._get_attr(attrs, 'badPwdCount', as_int=True)
        
        # Privilege indicators
        user_info['admin_count'] = self._get_attr(attrs, 'adminCount', as_int=True)
        
        # SPNs
        spns = self._get_attr(attrs, 'servicePrincipalName', multi=True)
        user_info['spns'] = spns if spns else []
        
        # Group memberships
        groups = self._get_attr(attrs, 'memberOf', multi=True)
        user_info['groups'] = groups if groups else []
        
        # Delegation
        user_info['allowed_to_delegate'] = self._get_attr(attrs, 'msDS-AllowedToDelegateTo', multi=True)
        user_info['rbcd'] = self._get_attr(attrs, 'msDS-AllowedToActOnBehalfOfOtherIdentity', raw=True)
        
        # Creation/modification
        user_info['created'] = self._get_attr(attrs, 'whenCreated')
        user_info['modified'] = self._get_attr(attrs, 'whenChanged')
        
        return user_info
    
    def _is_privileged_user(self, user: Dict[str, Any]) -> bool:
        """Check if user is in privileged groups."""
        from modules.utils import is_privileged_group
        
        domain_sid = self.ldap.get_domain_sid()
        if not domain_sid:
            return False
        
        for group_dn in user.get('groups', []):
            # Extract group name and check against known privileged groups
            if any(priv_group in group_dn for priv_group in [
                'Domain Admins', 'Enterprise Admins', 'Administrators',
                'Schema Admins', 'Account Operators', 'Backup Operators'
            ]):
                return True
        
        return False
    
    def _get_attr(self, attrs: Dict, name: str, as_int: bool = False, 
                  raw: bool = False, multi: bool = False) -> Any:
        """Extract attribute value from result."""
        if name not in attrs or not attrs[name]:
            return [] if multi else None
        
        values = attrs[name]
        
        if raw:
            return values[0] if values else None
        
        if multi:
            decoded_values = []
            for value in values:
                if isinstance(value, bytes):
                    try:
                        decoded_values.append(value.decode('utf-8'))
                    except UnicodeDecodeError:
                        decoded_values.append(value.hex())
                else:
                    decoded_values.append(str(value))
            return decoded_values
        
        value = values[0]
        
        if isinstance(value, bytes):
            try:
                value = value.decode('utf-8')
            except UnicodeDecodeError:
                return value
        
        if as_int:
            try:
                return int(value)
            except (ValueError, TypeError):
                return 0
        
        return value
