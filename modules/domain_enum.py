"""Domain and forest enumeration module."""

import logging
from typing import Any, Dict, List, Optional
from modules.ldap_connector import LDAPConnector
from modules.utils import filetime_to_datetime, extract_domain_from_dn
import config


class DomainEnumerator:
    """Enumerate domain and forest information."""
    
    def __init__(self, ldap_conn: LDAPConnector):
        """
        Initialize domain enumerator.
        
        Args:
            ldap_conn: Active LDAP connection
        """
        self.ldap = ldap_conn
        self.logger = logging.getLogger(__name__)
    
    def enumerate_domain_info(self) -> Dict[str, Any]:
        """
        Enumerate basic domain information.
        
        Returns:
            Dictionary with domain details
        """
        self.logger.info("Enumerating domain information...")
        
        try:
            results = self.ldap.search(
                search_filter='(objectClass=domain)',
                attributes=config.DOMAIN_ATTRIBUTES
            )
            
            if not results:
                return {}
            
            domain_data = {}
            attrs = results[0]
            
            # Parse domain attributes
            domain_data['name'] = self._get_attr(attrs, 'name')
            domain_data['distinguished_name'] = self._get_attr(attrs, 'distinguishedName')
            domain_data['dns_name'] = extract_domain_from_dn(domain_data['distinguished_name'])
            domain_data['sid'] = self.ldap.get_domain_sid()
            
            # Functional level
            behavior_version = self._get_attr(attrs, 'msDS-Behavior-Version', as_int=True)
            domain_data['functional_level'] = self._parse_functional_level(behavior_version)
            
            # Password policy
            domain_data['password_policy'] = {
                'min_password_length': self._get_attr(attrs, 'minPwdLength', as_int=True),
                'password_history': self._get_attr(attrs, 'pwdHistoryLength', as_int=True),
                'lockout_threshold': self._get_attr(attrs, 'lockoutThreshold', as_int=True),
                'lockout_duration': self._get_attr(attrs, 'lockoutDuration', as_int=True),
                'lockout_window': self._get_attr(attrs, 'lockOutObservationWindow', as_int=True),
                'max_password_age': self._get_attr(attrs, 'maxPwdAge', as_int=True),
                'min_password_age': self._get_attr(attrs, 'minPwdAge', as_int=True),
            }
            
            return domain_data
            
        except Exception as e:
            self.logger.error(f"Domain enumeration failed: {e}")
            return {}
    
    def enumerate_domain_controllers(self) -> List[Dict[str, Any]]:
        """
        Enumerate all domain controllers.
        
        Returns:
            List of DC information dictionaries
        """
        self.logger.info("Enumerating domain controllers...")
        
        try:
            results = self.ldap.search(
                search_filter=config.LDAP_FILTERS['domain_controllers'],
                attributes=['dNSHostName', 'operatingSystem', 'operatingSystemVersion', 
                           'distinguishedName', 'whenCreated']
            )
            
            dcs = []
            for result in results:
                dc_info = {
                    'hostname': self._get_attr(result, 'dNSHostName'),
                    'os': self._get_attr(result, 'operatingSystem'),
                    'os_version': self._get_attr(result, 'operatingSystemVersion'),
                    'dn': self._get_attr(result, 'distinguishedName'),
                    'created': self._get_attr(result, 'whenCreated'),
                }
                dcs.append(dc_info)
            
            return dcs
            
        except Exception as e:
            self.logger.error(f"DC enumeration failed: {e}")
            return []
    
    def enumerate_trusts(self) -> List[Dict[str, Any]]:
        """
        Enumerate domain trust relationships.
        
        Returns:
            List of trust information dictionaries
        """
        self.logger.info("Enumerating domain trusts...")
        
        try:
            results = self.ldap.search(
                search_filter='(objectClass=trustedDomain)',
                attributes=['name', 'trustPartner', 'trustDirection', 'trustType', 
                           'trustAttributes', 'securityIdentifier']
            )
            
            trusts = []
            for result in results:
                trust_info = {
                    'name': self._get_attr(result, 'name'),
                    'partner': self._get_attr(result, 'trustPartner'),
                    'direction': self._parse_trust_direction(
                        self._get_attr(result, 'trustDirection', as_int=True)
                    ),
                    'type': self._parse_trust_type(
                        self._get_attr(result, 'trustType', as_int=True)
                    ),
                    'attributes': self._parse_trust_attributes(
                        self._get_attr(result, 'trustAttributes', as_int=True)
                    ),
                }
                trusts.append(trust_info)
            
            return trusts
            
        except Exception as e:
            self.logger.error(f"Trust enumeration failed: {e}")
            return []
    
    def enumerate_sites(self) -> List[Dict[str, Any]]:
        """
        Enumerate AD sites and subnets.
        
        Returns:
            List of site information dictionaries
        """
        self.logger.info("Enumerating AD sites...")
        
        try:
            # Get configuration naming context
            config_dn = f"CN=Configuration,{self.ldap.base_dn}"
            
            results = self.ldap.search(
                search_filter='(objectClass=site)',
                attributes=['name', 'description'],
                search_base=config_dn
            )
            
            sites = []
            for result in results:
                site_info = {
                    'name': self._get_attr(result, 'name'),
                    'description': self._get_attr(result, 'description'),
                }
                sites.append(site_info)
            
            return sites
            
        except Exception as e:
            self.logger.error(f"Site enumeration failed: {e}")
            return []
    
    def _get_attr(self, attrs: Dict, name: str, as_int: bool = False) -> Any:
        """Extract attribute value from result."""
        if name not in attrs or not attrs[name]:
            return None
        
        value = attrs[name][0]
        
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
    
    def _parse_functional_level(self, level: int) -> str:
        """Parse domain functional level."""
        levels = {
            0: 'Windows 2000',
            1: 'Windows Server 2003 Interim',
            2: 'Windows Server 2003',
            3: 'Windows Server 2008',
            4: 'Windows Server 2008 R2',
            5: 'Windows Server 2012',
            6: 'Windows Server 2012 R2',
            7: 'Windows Server 2016',
            10: 'Windows Server 2025',
        }
        return levels.get(level, f'Unknown ({level})')
    
    def _parse_trust_direction(self, direction: int) -> str:
        """Parse trust direction."""
        directions = {
            0: 'Disabled',
            1: 'Inbound',
            2: 'Outbound',
            3: 'Bidirectional',
        }
        return directions.get(direction, f'Unknown ({direction})')
    
    def _parse_trust_type(self, trust_type: int) -> str:
        """Parse trust type."""
        types = {
            1: 'Downlevel (Windows NT)',
            2: 'Uplevel (Active Directory)',
            3: 'MIT Kerberos',
            4: 'DCE',
        }
        return types.get(trust_type, f'Unknown ({trust_type})')
    
    def _parse_trust_attributes(self, attributes: int) -> List[str]:
        """Parse trust attributes bitmask."""
        attr_flags = {
            0x001: 'Non-Transitive',
            0x002: 'Uplevel-Only',
            0x004: 'Quarantined Domain (SID Filtering)',
            0x008: 'Forest-Transitive',
            0x010: 'Cross-Organization (Selective Auth)',
            0x020: 'Within Forest',
            0x040: 'Treat as External',
            0x080: 'Trust Uses RC4 Encryption',
            0x200: 'Trust Uses AES Keys',
        }
        
        active_attrs = []
        for flag, name in attr_flags.items():
            if attributes & flag:
                active_attrs.append(name)
        
        return active_attrs
