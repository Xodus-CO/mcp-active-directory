"""Tests for security and audit tools."""

import pytest
from unittest.mock import Mock, patch
import json
import base64
from datetime import datetime, timedelta

from active_directory_mcp.tools.security import SecurityTools
from mcp.types import TextContent


@pytest.fixture
def mock_ldap_manager():
    """Mock LDAP manager for testing."""
    manager = Mock()
    manager.ad_config = Mock()
    manager.ad_config.base_dn = "DC=test,DC=local"
    manager.ad_config.domain = "test.local"
    return manager


@pytest.fixture
def security_tools(mock_ldap_manager):
    """Security tools instance for testing."""
    return SecurityTools(mock_ldap_manager)


class TestSecurityTools:
    """Test security and audit functionality."""
    
    def test_get_domain_info_success(self, security_tools, mock_ldap_manager):
        """Test successful domain information retrieval."""
        # Mock domain object search
        mock_domain_result = [
            {
                'dn': 'DC=test,DC=local',
                'attributes': {
                    'name': ['test'],
                    'dc': ['test'],
                    'objectSid': [b'\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00'],
                    'whenCreated': [datetime.now() - timedelta(days=365)],
                    'whenChanged': [datetime.now() - timedelta(days=1)],
                    'lockoutThreshold': [5],
                    'lockoutDuration': [-18000000000],  # 30 minutes in 100ns intervals
                    'maxPwdAge': [-36288000000000],  # 42 days
                    'minPwdAge': [-864000000000],  # 1 day
                    'minPwdLength': [8],
                    'pwdHistoryLength': [24],
                    'functionalLevel': [7]  # Windows Server 2008 R2
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_domain_result
        
        # Test get_domain_info
        result = security_tools.get_domain_info()
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['name'] == 'test'
        assert response_data['domain_component'] == 'test'
        assert 'password_policy' in response_data
        
        password_policy = response_data['password_policy']
        assert password_policy['min_password_length'] == 8
        assert password_policy['password_history_length'] == 24
        assert password_policy['lockout_threshold'] == 5
        
        # Verify LDAP search was called
        mock_ldap_manager.search.assert_called_once()
    
    def test_get_privileged_groups_success(self, security_tools, mock_ldap_manager):
        """Test successful privileged group retrieval."""
        # Map each privileged group name (the code iterates 9 of these and
        # issues one search per name) to the result it should return.
        group_entries = {
            'Domain Admins': {
                'dn': 'CN=Domain Admins,CN=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['Domain Admins'],
                    'displayName': ['Domain Admins'],
                    'description': ['Designated administrators of the domain'],
                    'member': [
                        'CN=Administrator,CN=Users,DC=test,DC=local',
                        'CN=Admin User,OU=Users,DC=test,DC=local'
                    ],
                    'adminCount': [1],
                }
            },
            'Enterprise Admins': {
                'dn': 'CN=Enterprise Admins,CN=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['Enterprise Admins'],
                    'displayName': ['Enterprise Admins'],
                    'description': ['Designated administrators of the enterprise'],
                    'member': ['CN=Administrator,CN=Users,DC=test,DC=local'],
                    'adminCount': [1],
                }
            },
            'Backup Operators': {
                'dn': 'CN=Backup Operators,CN=Builtin,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['Backup Operators'],
                    'displayName': ['Backup Operators'],
                    'description': ['Backup Operators can override security restrictions'],
                    'member': ['CN=Backup Service,OU=Service Accounts,DC=test,DC=local'],
                }
            },
        }

        def search_side_effect(*args, **kwargs):
            sf = kwargs.get('search_filter', '')
            for name, entry in group_entries.items():
                if f'sAMAccountName={name}' in sf:
                    return [entry]
            return []

        mock_ldap_manager.search.side_effect = search_side_effect

        # Test get_privileged_groups
        result = security_tools.get_privileged_groups()

        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)

        # Parse JSON response (code returns sam_account_name and member_count,
        # without a risk_level field).
        response_data = json.loads(result[0].text)
        assert response_data['total_groups'] == 3
        assert len(response_data['privileged_groups']) == 3

        groups = {g['sam_account_name']: g for g in response_data['privileged_groups']}
        assert 'Domain Admins' in groups
        assert 'Enterprise Admins' in groups
        assert 'Backup Operators' in groups

        assert groups['Domain Admins']['member_count'] == 2
        assert groups['Enterprise Admins']['member_count'] == 1
        assert groups['Backup Operators']['member_count'] == 1
    
    def test_audit_admin_accounts_success(self, security_tools, mock_ldap_manager):
        """Test successful admin account audit."""
        # Use integer FILETIME values for lastLogon to avoid datetime/int
        # comparison errors deep in the audit code path.
        def _ft(days_ago):
            epoch = datetime(1601, 1, 1)
            return int(((datetime.now() - timedelta(days=days_ago)) - epoch).total_seconds() * 10000000)

        admin_users = {
            'CN=Administrator,CN=Users,DC=test,DC=local': {
                'dn': 'CN=Administrator,CN=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['Administrator'],
                    'displayName': ['Built-in Administrator'],
                    'userAccountControl': [512],
                    'lastLogon': [_ft(1)],
                    'pwdLastSet': [_ft(30)],
                    'memberOf': [
                        'CN=Domain Admins,CN=Users,DC=test,DC=local',
                    ],
                }
            },
            'CN=Admin User,OU=Users,DC=test,DC=local': {
                'dn': 'CN=Admin User,OU=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['admin.user'],
                    'displayName': ['Admin User'],
                    'userAccountControl': [512],
                    'lastLogon': [_ft(90)],
                    'pwdLastSet': [_ft(180)],
                    'memberOf': ['CN=Domain Admins,CN=Users,DC=test,DC=local'],
                }
            },
            'CN=Service Admin,OU=Service Accounts,DC=test,DC=local': {
                'dn': 'CN=Service Admin,OU=Service Accounts,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['svc.admin'],
                    'displayName': ['Service Admin Account'],
                    'userAccountControl': [66048],  # password never expires
                    'lastLogon': [_ft(0)],
                    'pwdLastSet': [_ft(365)],
                }
            },
        }

        group_entries = {
            'Domain Admins': {
                'dn': 'CN=Domain Admins,CN=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['Domain Admins'],
                    'member': list(admin_users.keys()),
                }
            },
        }

        def search_side_effect(*args, **kwargs):
            sb = kwargs.get('search_base', '')
            sf = kwargs.get('search_filter', '')

            # User lookup by DN (search_scope=BASE on a user DN)
            if sb in admin_users and 'objectClass=user' in sf:
                return [admin_users[sb]]

            # Group lookup by sAMAccountName
            if 'objectClass=group' in sf:
                for name, entry in group_entries.items():
                    if f'sAMAccountName={name}' in sf:
                        return [entry]
                return []

            return []

        mock_ldap_manager.search.side_effect = search_side_effect

        # Test audit_admin_accounts
        result = security_tools.audit_admin_accounts()

        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)

        # Parse JSON response (code returns total_admin_accounts and
        # high_risk_count/medium_risk_count/low_risk_count, not a generic
        # accounts_by_risk grouping). Risk levels are uppercase here because
        # they come from _calculate_admin_risk_level.
        response_data = json.loads(result[0].text)
        assert response_data['total_admin_accounts'] == 3
        assert 'high_risk_count' in response_data
        assert 'medium_risk_count' in response_data
        assert 'low_risk_count' in response_data

        accounts = {acc['sam_account_name']: acc for acc in response_data['admin_accounts']}
        assert 'Administrator' in accounts
        assert 'admin.user' in accounts
        assert 'svc.admin' in accounts

        # Service admin has password_never_expires and is in a privileged group.
        svc_admin = accounts['svc.admin']
        assert svc_admin['risk_level'] in ['HIGH', 'MEDIUM']
    
    def test_check_password_policy_success(self, security_tools, mock_ldap_manager):
        """Test password policy compliance check."""
        # Mock domain policy search
        mock_results = [
            {
                'dn': 'DC=test,DC=local',
                'attributes': {
                    'maxPwdAge': [-36288000000000],  # 42 days
                    'minPwdAge': [-864000000000],  # 1 day
                    'minPwdLength': [8],
                    'pwdHistoryLength': [24],
                    'pwdProperties': [1],  # DOMAIN_PASSWORD_COMPLEX
                    'lockoutThreshold': [5],
                    'lockoutDuration': [-18000000000]  # 30 minutes
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test check_password_policy
        result = security_tools.check_password_policy()
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert 'password_policy' in response_data
        assert 'compliance_status' in response_data
        assert 'recommendations' in response_data
        
        policy = response_data['password_policy']
        assert policy['min_password_length'] == 8
        assert policy['password_history_length'] == 24
        assert policy['lockout_threshold'] == 5
        
        # Check compliance recommendations
        compliance = response_data['compliance_status']
        assert 'overall_score' in compliance
        assert compliance['overall_score'] >= 0
        assert compliance['overall_score'] <= 100
    
    def test_find_weak_passwords_success(self, security_tools, mock_ldap_manager):
        """Test weak password detection."""
        # Mock user search results
        mock_results = [
            {
                'dn': 'CN=Weak User,OU=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['weak.user'],
                    'displayName': ['Weak User'],
                    'userAccountControl': [544],  # Password not required
                    'pwdLastSet': [datetime.now() - timedelta(days=365)],
                    'badPasswordTime': [datetime.now() - timedelta(hours=1)]
                }
            },
            {
                'dn': 'CN=Never Changed,OU=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['never.changed'],
                    'displayName': ['Never Changed Password'],
                    'userAccountControl': [66048],  # Password never expires
                    'pwdLastSet': [datetime.fromtimestamp(0)]  # Never set
                }
            },
            {
                'dn': 'CN=Good User,OU=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['good.user'],
                    'displayName': ['Good User'],
                    'userAccountControl': [512],  # Normal account
                    'pwdLastSet': [datetime.now() - timedelta(days=15)]
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test find_weak_passwords
        result = security_tools.find_weak_passwords()
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert 'weak_password_accounts' in response_data
        assert 'total_checked' in response_data
        assert 'total_weak' in response_data
        
        weak_accounts = response_data['weak_password_accounts']
        assert len(weak_accounts) >= 2  # Should find weak.user and never.changed
        
        # Check specific weak account types
        weak_types = {acc['weakness_type'] for acc in weak_accounts}
        assert 'password_not_required' in weak_types or 'old_password' in weak_types
        assert 'never_changed' in weak_types or 'password_never_expires' in weak_types
    
    def test_analyze_permissions_success(self, security_tools, mock_ldap_manager):
        """Test permission analysis."""
        # Mock object search results
        mock_results = [
            {
                'dn': 'CN=Sensitive OU,OU=Admin,DC=test,DC=local',
                'attributes': {
                    'objectClass': ['organizationalUnit'],
                    'nTSecurityDescriptor': [
                        base64.b64decode('AQAUhCQAAAAwAAAAAAAAABQAAAABABQALAAAADAADgAHAAEBAAAAAAAABQoAAAAqAA4ABwABAQAAAAAAAAUKAAAA')
                    ]
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test analyze_permissions
        result = security_tools.analyze_permissions('CN=Sensitive OU,OU=Admin,DC=test,DC=local')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert 'object_dn' in response_data
        assert 'permission_analysis' in response_data
    
    def test_detect_privilege_escalation_success(self, security_tools, mock_ldap_manager):
        """Test privilege escalation detection."""
        # Mock recent privilege changes (mock implementation)
        # This would typically query event logs or change tracking
        mock_results = [
            {
                'dn': 'CN=Recent Admin,OU=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['recent.admin'],
                    'displayName': ['Recently Promoted User'],
                    'whenChanged': [datetime.now() - timedelta(hours=2)],
                    'memberOf': ['CN=Domain Admins,CN=Users,DC=test,DC=local'],
                    'adminCount': [1]
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test detect_privilege_escalation
        result = security_tools.detect_privilege_escalation(hours_back=24)
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert 'privilege_changes' in response_data
        assert 'analysis_period_hours' in response_data
        assert response_data['analysis_period_hours'] == 24
    
    def test_check_service_accounts_success(self, security_tools, mock_ldap_manager):
        """Test service account security check."""
        # Mock service account search results
        mock_results = [
            {
                'dn': 'CN=Service Account,OU=Service Accounts,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['svc.database'],
                    'displayName': ['Database Service Account'],
                    'userAccountControl': [66048],  # Password never expires
                    'servicePrincipalName': [
                        'MSSQLSvc/db.test.local:1433',
                        'MSSQLSvc/db.test.local'
                    ],
                    'pwdLastSet': [datetime.now() - timedelta(days=365)],
                    'lastLogon': [datetime.now() - timedelta(days=1)],
                    'memberOf': ['CN=Service Accounts,OU=Groups,DC=test,DC=local']
                }
            },
            {
                'dn': 'CN=Risky Service,OU=Service Accounts,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['svc.risky'],
                    'displayName': ['Risky Service Account'],
                    'userAccountControl': [66048],  # Password never expires
                    'servicePrincipalName': ['HTTP/web.test.local'],
                    'pwdLastSet': [datetime.now() - timedelta(days=730)],  # 2 years old
                    'memberOf': [
                        'CN=Domain Admins,CN=Users,DC=test,DC=local'  # Bad practice!
                    ]
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test check_service_accounts
        result = security_tools.check_service_accounts()
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['total_service_accounts'] == 2
        assert 'service_accounts' in response_data
        assert 'security_findings' in response_data
        
        # Check findings
        findings = response_data['security_findings']
        assert len(findings) >= 1  # Should find the risky service account
        
        # Verify risky account detection
        accounts = {acc['sAMAccountName']: acc for acc in response_data['service_accounts']}
        risky_account = accounts['svc.risky']
        assert risky_account['risk_level'] == 'HIGH'
        assert risky_account['password_age_days'] >= 700
    
    def test_generate_security_report_success(self, security_tools, mock_ldap_manager):
        """Test comprehensive security report generation."""
        # Mock multiple search results for comprehensive report
        # This test would typically call multiple other methods
        
        with patch.object(security_tools, 'get_domain_info') as mock_domain, \
             patch.object(security_tools, 'audit_admin_accounts') as mock_admin_audit, \
             patch.object(security_tools, 'check_password_policy') as mock_password_policy, \
             patch.object(security_tools, 'find_weak_passwords') as mock_weak_passwords:
            
            # Mock return values for each component
            mock_domain.return_value = [TextContent(type="text", text='{"domain": "test.local"}')]
            mock_admin_audit.return_value = [TextContent(type="text", text='{"total_admin_accounts": 5}')]
            mock_password_policy.return_value = [TextContent(type="text", text='{"compliance_status": {"overall_score": 85}}')]
            mock_weak_passwords.return_value = [TextContent(type="text", text='{"total_weak": 3}')]
            
            # Test generate_security_report
            result = security_tools.generate_security_report()
            
            # Verify result
            assert len(result) == 1
            assert isinstance(result[0], TextContent)
            
            # Parse JSON response
            response_data = json.loads(result[0].text)
            assert 'report_timestamp' in response_data
            assert 'executive_summary' in response_data
            assert 'detailed_findings' in response_data
            
            # Verify all sub-reports were called
            mock_domain.assert_called_once()
            mock_admin_audit.assert_called_once()
            mock_password_policy.assert_called_once()
            mock_weak_passwords.assert_called_once()
    
    def test_security_risk_assessment(self, security_tools):
        """Test security risk assessment logic."""
        # Test different risk scenarios
        
        # High risk: Multiple privileged groups + old password
        high_risk_account = {
            'memberOf': [
                'CN=Domain Admins,CN=Users,DC=test,DC=local',
                'CN=Enterprise Admins,CN=Users,DC=test,DC=local'
            ],
            'pwdLastSet': [datetime.now() - timedelta(days=200)],
            'lastLogon': [datetime.now() - timedelta(days=90)]
        }
        risk = security_tools._assess_account_risk(high_risk_account)
        assert risk == 'high'
        
        # Medium risk: One privileged group + recent activity
        medium_risk_account = {
            'memberOf': ['CN=Domain Admins,CN=Users,DC=test,DC=local'],
            'pwdLastSet': [datetime.now() - timedelta(days=30)],
            'lastLogon': [datetime.now() - timedelta(days=1)]
        }
        risk = security_tools._assess_account_risk(medium_risk_account)
        assert risk == 'medium'
        
        # Low risk: Regular user
        low_risk_account = {
            'memberOf': ['CN=Domain Users,CN=Users,DC=test,DC=local'],
            'pwdLastSet': [datetime.now() - timedelta(days=15)],
            'lastLogon': [datetime.now()]
        }
        risk = security_tools._assess_account_risk(low_risk_account)
        assert risk == 'low'
    
    def test_password_age_calculation(self, security_tools):
        """Test password age calculation."""
        # Test recent password
        recent_date = datetime.now() - timedelta(days=10)
        age = security_tools._calculate_password_age({'pwdLastSet': [recent_date]})
        assert age == 10
        
        # Test old password
        old_date = datetime.now() - timedelta(days=365)
        age = security_tools._calculate_password_age({'pwdLastSet': [old_date]})
        assert age == 365
        
        # Test never set password
        age = security_tools._calculate_password_age({'pwdLastSet': [None]})
        assert age == -1
        
        # Test missing attribute
        age = security_tools._calculate_password_age({})
        assert age == -1
    
    def test_is_privileged_group(self, security_tools):
        """Test privileged group detection."""
        # Test high-privilege groups
        assert security_tools._is_privileged_group('Domain Admins') == True
        assert security_tools._is_privileged_group('Enterprise Admins') == True
        assert security_tools._is_privileged_group('Schema Admins') == True
        assert security_tools._is_privileged_group('Backup Operators') == True
        
        # Test regular groups
        assert security_tools._is_privileged_group('Domain Users') == False
        assert security_tools._is_privileged_group('Sales Team') == False
        assert security_tools._is_privileged_group('Regular Group') == False
    
    def test_ldap_error_handling(self, security_tools, mock_ldap_manager):
        """Test LDAP error handling."""
        # Mock LDAP exception
        from ldap3.core.exceptions import LDAPException
        mock_ldap_manager.search.side_effect = LDAPException("Connection failed")
        
        # Test get_domain_info with error
        result = security_tools.get_domain_info()
        
        # Verify error handling
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'Connection failed' in response_data['error']
        assert response_data['type'] == 'LDAPException'
    
    def test_get_schema_info(self, security_tools):
        """Test schema information retrieval."""
        schema = security_tools.get_schema_info()
        
        assert 'operations' in schema
        assert 'security_attributes' in schema
        assert 'risk_levels' in schema
        assert 'required_permissions' in schema
        
        # Check some expected operations
        operations = schema['operations']
        assert 'get_domain_info' in operations
        assert 'audit_admin_accounts' in operations
        assert 'check_password_policy' in operations
        assert 'find_weak_passwords' in operations
        assert 'analyze_permissions' in operations
        assert 'detect_privilege_escalation' in operations
        assert 'check_service_accounts' in operations
        assert 'generate_security_report' in operations
        
        # Check risk levels (code uses lowercase)
        assert 'low' in schema['risk_levels']
        assert 'medium' in schema['risk_levels']
        assert 'high' in schema['risk_levels']
        assert 'critical' in schema['risk_levels']

