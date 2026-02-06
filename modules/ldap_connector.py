"""LDAP connection manager using impacket."""

import logging
from typing import Any, Dict, List, Optional, Tuple
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection
import config
from modules.stealth import StealthManager


class LDAPConnector:
    """Manages LDAP connections to Active Directory."""
    
    def __init__(self, domain: str, username: str, password: str, 
                 dc_ip: str, use_kerberos: bool = False, lmhash: str = '', nthash: str = '',
                 stealth_mode: bool = False):
        """
        Initialize LDAP connector.
        
        Args:
            domain: Target domain name
            username: Username for authentication
            password: Password for authentication
            dc_ip: Domain controller IP address
            use_kerberos: Use Kerberos authentication
            lmhash: LM hash for pass-the-hash
            nthash: NT hash for pass-the-hash
            stealth_mode: Enable stealth/OpSec features
        """
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.use_kerberos = use_kerberos
        self.lmhash = lmhash
        self.nthash = nthash
        self.ldap_conn = None
        self.base_dn = None
        self.domain_sid = None
        
        self.logger = logging.getLogger(__name__)
        self.stealth = StealthManager(stealth_mode)
    
    def connect(self) -> bool:
        """
        Establish LDAP connection.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Build target string
            if self.use_kerberos:
                target = self.domain
            else:
                target = self.dc_ip
            
            # Create LDAP connection
            self.ldap_conn = ldap.LDAPConnection(f'ldap://{target}', self.base_dn)
            
            # Authenticate
            if self.lmhash or self.nthash:
                # Pass-the-hash
                self.ldap_conn.login(
                    user=f'{self.domain}\\{self.username}',
                    password='',
                    domain=self.domain,
                    lmhash=self.lmhash,
                    nthash=self.nthash
                )
            else:
                # Password authentication
                self.ldap_conn.login(
                    user=self.username,
                    password=self.password,
                    domain=self.domain
                )
            
            # Get base DN from domain
            self.base_dn = ','.join([f'DC={part}' for part in self.domain.split('.')])
            
            self.logger.info(f"Successfully connected to {self.dc_ip}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to LDAP: {e}")
            return False
    
    def search(self, search_filter: str, attributes: List[str], 
               search_base: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Perform LDAP search with automatic paging.
        
        Args:
            search_filter: LDAP filter string
            attributes: List of attributes to retrieve
            search_base: Custom search base (uses domain base DN if None)
        
        Returns:
            List of result dictionaries
        """
        if not self.ldap_conn:
            self.logger.error("LDAP connection not established")
            return []
        
        # Apply OpSec delay before query
        self.stealth.wait_before_query()
        
        results = []
        search_base = search_base or self.base_dn
        
        try:
            # Use stealth-appropriate page size
            page_size = self.stealth.get_page_size()
            
            # Perform search with paging
            search_control = ldapasn1.SimplePagedResultsControl(
                criticality=False,
                size=page_size
            )
            
            cookie = ''
            while True:
                resp = self.ldap_conn.search(
                    searchBase=search_base,
                    searchFilter=search_filter,
                    attributes=attributes,
                    searchControls=[search_control]
                )
                
                for item in resp:
                    if isinstance(item, ldapasn1.SearchResultEntry):
                        entry = {}
                        for attr in item['attributes']:
                            attr_name = str(attr['type'])
                            attr_vals = []
                            for val in attr['vals']:
                                attr_vals.append(bytes(val))
                            entry[attr_name] = attr_vals
                        results.append(entry)
                
                # Check for more pages
                for control in resp:
                    if isinstance(control, ldapasn1.SimplePagedResultsControl):
                        cookie = control['value']['cookie']
                        if not cookie:
                            return results
                        search_control['value']['cookie'] = cookie
                        break
                else:
                    break
            
        except Exception as e:
            self.logger.error(f"LDAP search failed: {e}")
        
        return results
    
    def get_domain_sid(self) -> Optional[str]:
        """
        Retrieve the domain SID.
        
        Returns:
            Domain SID string
        """
        if self.domain_sid:
            return self.domain_sid
        
        try:
            results = self.search(
                search_filter='(objectClass=domain)',
                attributes=['objectSid']
            )
            
            if results and 'objectSid' in results[0]:
                from modules.utils import parse_sid
                self.domain_sid = parse_sid(results[0]['objectSid'][0])
                return self.domain_sid
                
        except Exception as e:
            self.logger.error(f"Failed to get domain SID: {e}")
        
        return None
    
    def close(self):
        """Close LDAP connection."""
        if self.ldap_conn:
            try:
                self.ldap_conn.close()
                self.logger.info("LDAP connection closed")
            except Exception as e:
                self.logger.error(f"Error closing connection: {e}")
