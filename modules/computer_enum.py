"""Computer enumeration module."""

import logging
from typing import Any, Dict, List, Optional
from modules.ldap_connector import LDAPConnector
from modules.utils import filetime_to_datetime, parse_user_account_control, parse_sid
import config


class ComputerEnumerator:
    """Enumerate and analyze computer accounts."""
    
    def __init__(self, ldap_conn: LDAPConnector):
        """
        Initialize computer enumerator.
        
        Args:
            ldap_conn: Active LDAP connection
        """
        self.ldap = ldap_conn
        self.logger = logging.getLogger(__name__)
    
    def enumerate_all_computers(self) -> List[Dict[str, Any]]:
        """
        Enumerate all computer accounts.
        
        Returns:
            List of computer information dictionaries
        """
        self.logger.info("Enumerating all computers...")
        
        try:
            results = self.ldap.search(
                search_filter=config.LDAP_FILTERS['all_computers'],
                attributes=config.COMPUTER_ATTRIBUTES
            )
            
            computers = []
            for result in results:
                computer_info = self._parse_computer(result)
                computers.append(computer_info)
            
            self.logger.info(f"Found {len(computers)} computers")
            return computers
            
        except Exception as e:
            self.logger.error(f"Computer enumeration failed: {e}")
            return []
    
    def enumerate_servers(self) -> List[Dict[str, Any]]:
        """
        Enumerate server computers.
        
        Returns:
            List of server computer dictionaries
        """
        all_computers = self.enumerate_all_computers()
        servers = [
            comp for comp in all_computers 
            if comp.get('os', '').lower().find('server') != -1
        ]
        
        self.logger.info(f"Found {len(servers)} servers")
        return servers
    
    def enumerate_delegated_computers(self) -> List[Dict[str, Any]]:
        """
        Enumerate computers with delegation enabled.
        
        Returns:
            List of delegated computer dictionaries
        """
        self.logger.info("Enumerating delegated computers...")
        
        try:
            results = self.ldap.search(
                search_filter=config.LDAP_FILTERS['trusted_for_delegation'],
                attributes=config.COMPUTER_ATTRIBUTES
            )
            
            computers = []
            for result in results:
                computer_info = self._parse_computer(result)
                # Only include actual computer accounts
                if computer_info['name'].endswith('$'):
                    computers.append(computer_info)
            
            self.logger.info(f"Found {len(computers)} delegated computers")
            return computers
            
        except Exception as e:
            self.logger.error(f"Delegated computer enumeration failed: {e}")
            return []
    
    def _parse_computer(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse computer attributes into structured dictionary.
        
        Args:
            attrs: Raw LDAP attributes
        
        Returns:
            Parsed computer information
        """
        computer_info = {}
        
        # Basic attributes
        computer_info['name'] = self._get_attr(attrs, 'sAMAccountName')
        computer_info['dn'] = self._get_attr(attrs, 'distinguishedName')
        computer_info['dns_hostname'] = self._get_attr(attrs, 'dNSHostName')
        computer_info['description'] = self._get_attr(attrs, 'description')
        
        # Operating system
        computer_info['os'] = self._get_attr(attrs, 'operatingSystem')
        computer_info['os_version'] = self._get_attr(attrs, 'operatingSystemVersion')
        
        # SID
        sid_bytes = self._get_attr(attrs, 'objectSid', raw=True)
        if sid_bytes:
            computer_info['sid'] = parse_sid(sid_bytes)
        else:
            computer_info['sid'] = None
        
        # User Account Control
        uac = self._get_attr(attrs, 'userAccountControl', as_int=True)
        computer_info['uac'] = uac
        computer_info['uac_flags'] = parse_user_account_control(uac)
        computer_info['enabled'] = not computer_info['uac_flags'].get('ACCOUNTDISABLE', False)
        
        # Logon information
        last_logon = self._get_attr(attrs, 'lastLogonTimestamp', as_int=True)
        computer_info['last_logon'] = filetime_to_datetime(last_logon)
        
        # SPNs
        spns = self._get_attr(attrs, 'servicePrincipalName', multi=True)
        computer_info['spns'] = spns if spns else []
        
        # Delegation
        computer_info['allowed_to_delegate'] = self._get_attr(attrs, 'msDS-AllowedToDelegateTo', multi=True)
        computer_info['rbcd'] = self._get_attr(attrs, 'msDS-AllowedToActOnBehalfOfOtherIdentity', raw=True)
        
        # Creation
        computer_info['created'] = self._get_attr(attrs, 'whenCreated')
        
        # Determine if it's a server or workstation
        computer_info['is_server'] = self._is_server(computer_info)
        computer_info['is_dc'] = computer_info['uac_flags'].get('SERVER_TRUST_ACCOUNT', False)
        
        return computer_info
    
    def _is_server(self, computer: Dict[str, Any]) -> bool:
        """Determine if computer is a server."""
        os = computer.get('os', '').lower()
        return 'server' in os
    
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
