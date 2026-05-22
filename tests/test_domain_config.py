"""Tests for multi-domain credential configuration."""

import json
import os
import pytest
from unittest.mock import patch

from active_directory_mcp.config.domain_config import (
    _fqdn_to_base_dn,
    load_domain_map,
    is_readonly,
    make_ldap_manager,
    DomainCredentials,
)


class TestFqdnToBaseDn:
    def test_two_part_domain(self):
        assert _fqdn_to_base_dn("corp.local") == "DC=corp,DC=local"

    def test_three_part_domain(self):
        assert _fqdn_to_base_dn("sub.corp.local") == "DC=sub,DC=corp,DC=local"

    def test_single_label(self):
        assert _fqdn_to_base_dn("local") == "DC=local"


class TestLoadDomainMap:
    def test_empty_env_returns_empty(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("AD_DOMAINS", None)
            assert load_domain_map() == {}

    def test_valid_single_domain(self):
        domains = {
            "corp.local": {
                "host": "ldaps://dc01.corp.local",
                "bind_dn": "CN=svc-mcp,DC=corp,DC=local",
                "password": "secret",
            }
        }
        with patch.dict(os.environ, {"AD_DOMAINS": json.dumps(domains)}):
            result = load_domain_map()
        assert "corp.local" in result
        creds = result["corp.local"]
        assert creds.host == "ldaps://dc01.corp.local"
        assert creds.bind_dn == "CN=svc-mcp,DC=corp,DC=local"
        assert creds.password == "secret"
        assert creds.base_dn == "DC=corp,DC=local"  # derived from FQDN

    def test_explicit_base_dn_overrides_derived(self):
        domains = {
            "corp.local": {
                "host": "ldap://dc01.corp.local",
                "bind_dn": "CN=svc,DC=corp,DC=local",
                "password": "pw",
                "base_dn": "OU=Custom,DC=corp,DC=local",
            }
        }
        with patch.dict(os.environ, {"AD_DOMAINS": json.dumps(domains)}):
            result = load_domain_map()
        assert result["corp.local"].base_dn == "OU=Custom,DC=corp,DC=local"

    def test_multiple_domains(self):
        domains = {
            "corp.local": {"host": "ldaps://dc01.corp.local", "bind_dn": "CN=a,DC=corp,DC=local", "password": "p1"},
            "dev.local":  {"host": "ldaps://dc01.dev.local",  "bind_dn": "CN=b,DC=dev,DC=local",  "password": "p2"},
        }
        with patch.dict(os.environ, {"AD_DOMAINS": json.dumps(domains)}):
            result = load_domain_map()
        assert set(result.keys()) == {"corp.local", "dev.local"}

    def test_invalid_json_raises(self):
        with patch.dict(os.environ, {"AD_DOMAINS": "not-json"}):
            with pytest.raises(ValueError, match="not valid JSON"):
                load_domain_map()

    def test_missing_required_key_raises(self):
        domains = {"corp.local": {"host": "ldaps://dc01.corp.local"}}  # missing bind_dn, password
        with patch.dict(os.environ, {"AD_DOMAINS": json.dumps(domains)}):
            with pytest.raises(KeyError):
                load_domain_map()


class TestIsReadonly:
    @pytest.mark.parametrize("val", ["true", "True", "TRUE", "1", "yes"])
    def test_truthy_values(self, val):
        with patch.dict(os.environ, {"AD_READONLY": val}):
            assert is_readonly() is True

    @pytest.mark.parametrize("val", ["false", "False", "FALSE", "0", "no"])
    def test_falsy_values(self, val):
        with patch.dict(os.environ, {"AD_READONLY": val}):
            assert is_readonly() is False

    def test_defaults_to_readonly_when_unset(self):
        env = {k: v for k, v in os.environ.items() if k != "AD_READONLY"}
        with patch.dict(os.environ, env, clear=True):
            assert is_readonly() is True


class TestMakeLdapManager:
    def test_ldaps_enables_tls(self):
        creds = DomainCredentials(
            host="ldaps://dc01.corp.local",
            bind_dn="CN=svc,DC=corp,DC=local",
            password="secret",
            base_dn="DC=corp,DC=local",
        )
        mgr = make_ldap_manager("corp.local", creds)
        assert mgr.security_config.enable_tls is True
        assert mgr.ad_config.server == "ldaps://dc01.corp.local"
        assert mgr.ad_config.domain == "corp.local"
        assert mgr.ad_config.base_dn == "DC=corp,DC=local"
        assert mgr.ad_config.bind_dn == "CN=svc,DC=corp,DC=local"

    def test_ldap_disables_tls(self):
        creds = DomainCredentials(
            host="ldap://dc01.corp.local",
            bind_dn="CN=svc,DC=corp,DC=local",
            password="secret",
            base_dn="DC=corp,DC=local",
        )
        mgr = make_ldap_manager("corp.local", creds)
        assert mgr.security_config.enable_tls is False
