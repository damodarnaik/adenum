"""Group enumeration module."""

import logging
from typing import Any, Dict, List, Set
from modules.ldap_connector import LDAPConnector
from modules.utils import parse_sid
import config


class GroupEnumerator:
    """Enumerate and analyze groups."""
    
    def __init__(self, ldap_conn: LDAPConnector):
        """
        Initialize group enumerator.
        
        Args:
            ldap_conn: Active LDAP connection
        """
        self.ldap = ldap_conn
        self.logger = logging.getLogger(__name__)
        self._group_cache = {}
    
    def enumerate_all_groups(self) -> List[Dict[str, Any]]:
        """
        Enumerate all groups.
        
        Returns:
            List of group information dictionaries
        """
        self.logger.info("Enumerating all groups...")
        
        try:
            results = self.ldap.search(
                search_filter=config.LDAP_FILTERS['all_groups'],
                attributes=config.GROUP_ATTRIBUTES
            )
            
            groups = []
            for result in results:
                group_info = self._parse_group(result)
                groups.append(group_info)
                self._group_cache[group_info['dn']] = group_info
            
            self.logger.info(f"Found {len(groups)} groups")
            return groups
            
        except Exception as e:
            self.logger.error(f"Group enumeration failed: {e}")
            return []
    
    def enumerate_privileged_groups(self) -> List[Dict[str, Any]]:
        """
        Enumerate high-privilege groups.
        
        Returns:
            List of privileged group dictionaries
        """
        self.logger.info("Enumerating privileged groups...")
        
        all_groups = self.enumerate_all_groups()
        privileged = []
        
        for group in all_groups:
            if self._is_privileged_group(group):
                # Resolve nested members
                group['all_members'] = self._get_nested_members(group['dn'])
                privileged.append(group)
        
        self.logger.info(f"Found {len(privileged)} privileged groups")
        return privileged
    
    def _parse_group(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse group attributes into structured dictionary.
        
        Args:
            attrs: Raw LDAP attributes
        
        Returns:
            Parsed group information
        """
        group_info = {}
        
        # Basic attributes
        group_info['name'] = self._get_attr(attrs, 'sAMAccountName')
        group_info['dn'] = self._get_attr(attrs, 'distinguishedName')
        group_info['description'] = self._get_attr(attrs, 'description')
        
        # SID
        sid_bytes = self._get_attr(attrs, 'objectSid', raw=True)
        if sid_bytes:
            group_info['sid'] = parse_sid(sid_bytes)
        else:
            group_info['sid'] = None
        
        # Members
        members = self._get_attr(attrs, 'member', multi=True)
        group_info['members'] = members if members else []
        group_info['member_count'] = len(group_info['members'])
        
        # Member of
        member_of = self._get_attr(attrs, 'memberOf', multi=True)
        group_info['member_of'] = member_of if member_of else []
        
        # Group type
        group_type = self._get_attr(attrs, 'groupType', as_int=True)
        group_info['group_type'] = self._parse_group_type(group_type)
        
        # Privilege indicator
        group_info['admin_count'] = self._get_attr(attrs, 'adminCount', as_int=True)
        
        return group_info
    
    def _is_privileged_group(self, group: Dict[str, Any]) -> bool:
        """Check if group is a known privileged group."""
        privileged_names = [
            'domain admins', 'enterprise admins', 'administrators',
            'schema admins', 'account operators', 'server operators',
            'backup operators', 'print operators', 'group policy creator owners',
            'dnsadmins'
        ]
        
        group_name = group.get('name', '').lower()
        return any(priv in group_name for priv in privileged_names) or group.get('admin_count') == 1
    
    def _get_nested_members(self, group_dn: str, visited: Set[str] = None) -> List[str]:
        """
        Recursively resolve nested group members.
        
        Args:
            group_dn: Group distinguished name
            visited: Set of already visited groups (for cycle detection)
        
        Returns:
            List of all member DNs (users and computers)
        """
        if visited is None:
            visited = set()
        
        if group_dn in visited:
            return []
        
        visited.add(group_dn)
        all_members = []
        
        # Get group from cache or enumerate
        if group_dn not in self._group_cache:
            self.enumerate_all_groups()
        
        group = self._group_cache.get(group_dn)
        if not group:
            return []
        
        for member_dn in group.get('members', []):
            all_members.append(member_dn)
            
            # If member is a group, recurse
            if 'CN=Users' in member_dn or 'OU=' in member_dn:
                if member_dn in self._group_cache:
                    nested = self._get_nested_members(member_dn, visited)
                    all_members.extend(nested)
        
        return list(set(all_members))
    
    def _parse_group_type(self, group_type: int) -> str:
        """Parse group type flag."""
        types = []
        
        if group_type & 0x00000001:
            types.append('System')
        if group_type & 0x00000002:
            types.append('Global')
        if group_type & 0x00000004:
            types.append('Domain Local')
        if group_type & 0x00000008:
            types.append('Universal')
        if group_type & 0x80000000:
            types.append('Security')
        else:
            types.append('Distribution')
        
        return ', '.join(types) if types else 'Unknown'
    
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
