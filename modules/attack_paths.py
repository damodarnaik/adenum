"""Attack path analysis module."""

import logging
from typing import Any, Dict, List, Set, Tuple
import networkx as nx
import config


class AttackPathAnalyzer:
    """Analyze and map attack paths in Active Directory."""
    
    def __init__(self):
        """Initialize attack path analyzer."""
        self.logger = logging.getLogger(__name__)
        self.graph = nx.DiGraph()
        self.high_value_targets = set()
    
    def build_graph(self, enum_data: Dict[str, Any]):
        """
        Build attack graph from enumerated data.
        
        Args:
            enum_data: Dictionary containing all enumeration results
        """
        self.logger.info("Building attack graph...")
        
        # Add nodes for all users and computers
        self._add_user_nodes(enum_data.get('all_users', []))
        self._add_computer_nodes(enum_data.get('all_computers', []))
        
        # Add group membership edges
        self._add_group_edges(enum_data.get('all_groups', []))
        
        # Add delegation edges
        self._add_delegation_edges(
            enum_data.get('delegated_users', []),
            enum_data.get('delegated_computers', [])
        )
        
        # Add local admin edges (if available)
        # This would require additional enumeration like BloodHound does
        
        # Identify high-value targets
        self._identify_high_value_targets(enum_data.get('privileged_groups', []))
        
        self.logger.info(f"Graph built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")
    
    def find_attack_paths(self, source: str = None) -> List[Dict[str, Any]]:
        """
        Find attack paths to high-value targets.
        
        Args:
            source: Starting node (if None, finds paths from all nodes)
        
        Returns:
            List of attack path dictionaries
        """
        self.logger.info("Finding attack paths...")
        
        attack_paths = []
        max_paths = config.REPORT_SETTINGS['max_attack_paths']
        
        if source:
            sources = [source]
        else:
            # Find paths from compromised or vulnerable accounts
            sources = self._get_potential_entry_points()
        
        for target in self.high_value_targets:
            for src in sources:
                if src == target or not self.graph.has_node(src):
                    continue
                
                try:
                    # Find all simple paths up to max depth
                    paths = list(nx.all_simple_paths(
                        self.graph, src, target,
                        cutoff=config.REPORT_SETTINGS['graph_depth']
                    ))
                    
                    # Sort by length (shorter = better)
                    paths.sort(key=len)
                    
                    for path in paths[:3]:  # Top 3 paths per source-target pair
                        attack_path = self._analyze_path(path)
                        if attack_path:
                            attack_paths.append(attack_path)
                        
                        if len(attack_paths) >= max_paths:
                            break
                    
                    if len(attack_paths) >= max_paths:
                        break
                        
                except nx.NetworkXNoPath:
                    continue
            
            if len(attack_paths) >= max_paths:
                break
        
        # Sort paths by risk score
        attack_paths.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        
        self.logger.info(f"Found {len(attack_paths)} attack paths")
        return attack_paths[:max_paths]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get graph statistics.
        
        Returns:
            Dictionary of statistics
        """
        return {
            'total_nodes': self.graph.number_of_nodes(),
            'total_edges': self.graph.number_of_edges(),
            'high_value_targets': len(self.high_value_targets),
            'avg_degree': sum(dict(self.graph.degree()).values()) / self.graph.number_of_nodes() if self.graph.number_of_nodes() > 0 else 0,
        }
    
    def _add_user_nodes(self, users: List[Dict[str, Any]]):
        """Add user nodes to graph."""
        for user in users:
            self.graph.add_node(
                user['username'],
                node_type='user',
                enabled=user.get('enabled', True),
                privileged=user.get('admin_count') == 1,
                data=user
            )
    
    def _add_computer_nodes(self, computers: List[Dict[str, Any]]):
        """Add computer nodes to graph."""
        for computer in computers:
            self.graph.add_node(
                computer['name'],
                node_type='computer',
                enabled=computer.get('enabled', True),
                is_dc=computer.get('is_dc', False),
                is_server=computer.get('is_server', False),
                data=computer
            )
    
    def _add_group_edges(self, groups: List[Dict[str, Any]]):
        """Add group membership edges."""
        for group in groups:
            group_name = group['name']
            
            # Add group node
            self.graph.add_node(
                group_name,
                node_type='group',
                privileged=self._is_privileged_group(group),
                data=group
            )
            
            # Add member -> group edges
            for member_dn in group.get('members', []):
                # Extract CN from DN
                member_name = self._extract_cn(member_dn)
                if member_name:
                    # Check if member exists in graph
                    if self.graph.has_node(member_name):
                        self.graph.add_edge(
                            member_name, group_name,
                            edge_type='MemberOf',
                            risk=2.0
                        )
    
    def _add_delegation_edges(self, users: List[Dict[str, Any]], computers: List[Dict[str, Any]]):
        """Add delegation relationship edges."""
        all_principals = users + computers
        
        for principal in all_principals:
            principal_name = principal.get('username') or principal.get('name')
            
            # Unconstrained delegation
            if principal.get('uac_flags', {}).get('TRUSTED_FOR_DELEGATION', False):
                # Can impersonate any user to any service
                for node in self.graph.nodes():
                    if self.graph.nodes[node].get('node_type') in ['user', 'computer']:
                        self.graph.add_edge(
                            principal_name, node,
                            edge_type='UnconstrainedDelegation',
                            risk=9.0
                        )
            
            # Constrained delegation
            allowed_to = principal.get('allowed_to_delegate', [])
            if allowed_to:
                for target_spn in allowed_to:
                    # Extract target from SPN
                    target_name = self._extract_target_from_spn(target_spn)
                    if target_name and self.graph.has_node(target_name):
                        self.graph.add_edge(
                            principal_name, target_name,
                            edge_type='ConstrainedDelegation',
                            risk=6.0
                        )
    
    def _identify_high_value_targets(self, privileged_groups: List[Dict[str, Any]]):
        """Identify high-value targets (Domain Admins, Enterprise Admins, etc.)."""
        target_names = [
            'domain admins', 'enterprise admins', 'administrators',
            'schema admins', 'domain controllers'
        ]
        
        for group in privileged_groups:
            group_name = group.get('name', '').lower()
            if any(target in group_name for target in target_names):
                self.high_value_targets.add(group['name'])
                
                # Also add all members as high-value
                for member_dn in group.get('all_members', []):
                    member_name = self._extract_cn(member_dn)
                    if member_name and self.graph.has_node(member_name):
                        self.high_value_targets.add(member_name)
    
    def _get_potential_entry_points(self) -> List[str]:
        """Get potential attack entry points (vulnerable accounts)."""
        entry_points = []
        
        for node, data in self.graph.nodes(data=True):
            if data.get('node_type') != 'user':
                continue
            
            user_data = data.get('data', {})
            
            # Check for vulnerabilities
            if user_data.get('spns') and not user_data.get('username', '').endswith('$'):
                entry_points.append(node)
            elif user_data.get('uac_flags', {}).get('DONT_REQ_PREAUTH', False):
                entry_points.append(node)
            elif user_data.get('uac_flags', {}).get('PASSWD_NOTREQD', False):
                entry_points.append(node)
        
        return entry_points[:20]  # Limit to 20 entry points
    
    def _analyze_path(self, path: List[str]) -> Dict[str, Any]:
        """
        Analyze an attack path for risk and steps.
        
        Args:
            path: List of nodes in the path
        
        Returns:
            Attack path dictionary
        """
        steps = []
        total_risk = 0.0
        
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]
            
            edge_data = self.graph.get_edge_data(source, target)
            if not edge_data:
                continue
            
            edge_type = edge_data.get('edge_type', 'Unknown')
            risk = edge_data.get('risk', 1.0)
            
            steps.append({
                'from': source,
                'to': target,
                'method': edge_type,
                'risk': risk
            })
            
            total_risk += risk
        
        if not steps:
            return None
        
        return {
            'source': path[0],
            'target': path[-1],
            'length': len(path),
            'steps': steps,
            'risk_score': total_risk / len(steps),  # Average risk
            'description': self._generate_path_description(steps)
        }
    
    def _generate_path_description(self, steps: List[Dict[str, Any]]) -> str:
        """Generate human-readable path description."""
        descriptions = []
        
        for step in steps:
            method = step['method']
            from_node = step['from']
            to_node = step['to']
            
            if method == 'MemberOf':
                descriptions.append(f"{from_node} is member of {to_node}")
            elif method == 'UnconstrainedDelegation':
                descriptions.append(f"{from_node} can impersonate any user to {to_node} via unconstrained delegation")
            elif method == 'ConstrainedDelegation':
                descriptions.append(f"{from_node} can delegate to {to_node} via constrained delegation")
            else:
                descriptions.append(f"{from_node} -> {to_node} ({method})")
        
        return ' → '.join(descriptions)
    
    def _is_privileged_group(self, group: Dict[str, Any]) -> bool:
        """Check if group is privileged."""
        privileged_names = [
            'domain admins', 'enterprise admins', 'administrators',
            'schema admins', 'account operators', 'backup operators'
        ]
        group_name = group.get('name', '').lower()
        return any(priv in group_name for priv in privileged_names)
    
    def _extract_cn(self, dn: str) -> str:
        """Extract CN from distinguished name."""
        if not dn:
            return ''
        
        parts = dn.split(',')
        if parts and parts[0].startswith('CN='):
            return parts[0][3:]  # Remove 'CN='
        return ''
    
    def _extract_target_from_spn(self, spn: str) -> str:
        """Extract target computer name from SPN."""
        # SPN format: service/hostname
        if '/' in spn:
            parts = spn.split('/')
            if len(parts) > 1:
                hostname = parts[1].split(':')[0].split('.')[0]
                return hostname + '$'
        return ''
