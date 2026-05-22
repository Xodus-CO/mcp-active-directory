"""Integration tests for the multi-domain Active Directory MCP server."""

import asyncio
import json
import os
import pytest
from unittest.mock import patch

from active_directory_mcp.server_http import ActiveDirectoryMCPServer


def _tool_names(server: ActiveDirectoryMCPServer) -> set:
    """Return the set of registered tool names (FastMCP 3.x uses async list_tools)."""
    return {t.name for t in asyncio.run(server.mcp.list_tools())}


SINGLE_DOMAIN_ENV = json.dumps({
    "corp.local": {
        "host": "ldap://dc01.corp.local",
        "bind_dn": "CN=svc-mcp,DC=corp,DC=local",
        "password": "secret",
    }
})

TWO_DOMAIN_ENV = json.dumps({
    "corp.local": {"host": "ldap://dc01.corp.local", "bind_dn": "CN=svc,DC=corp,DC=local", "password": "p1"},
    "dev.local":  {"host": "ldap://dc01.dev.local",  "bind_dn": "CN=svc,DC=dev,DC=local",  "password": "p2"},
})


class TestServerInit:
    def test_loads_domains_from_env(self):
        with patch.dict(os.environ, {"AD_DOMAINS": SINGLE_DOMAIN_ENV, "AD_READONLY": "true"}):
            server = ActiveDirectoryMCPServer()
        assert "corp.local" in server.domain_map
        assert server.readonly is True

    def test_starts_with_empty_domains(self):
        """Server should start even with no domains configured."""
        env = {k: v for k, v in os.environ.items() if k != "AD_DOMAINS"}
        with patch.dict(os.environ, env, clear=True):
            server = ActiveDirectoryMCPServer()
        assert server.domain_map == {}

    def test_readonly_false_when_disabled(self):
        with patch.dict(os.environ, {"AD_DOMAINS": SINGLE_DOMAIN_ENV, "AD_READONLY": "false"}):
            server = ActiveDirectoryMCPServer()
        assert server.readonly is False


class TestToolRegistration:
    def test_readonly_registers_23_tools(self):
        with patch.dict(os.environ, {"AD_DOMAINS": SINGLE_DOMAIN_ENV, "AD_READONLY": "true"}):
            server = ActiveDirectoryMCPServer()
        assert len(_tool_names(server)) == 23

    def test_readonly_excludes_write_tools(self):
        with patch.dict(os.environ, {"AD_DOMAINS": SINGLE_DOMAIN_ENV, "AD_READONLY": "true"}):
            server = ActiveDirectoryMCPServer()
        write_tools = {"create_user", "modify_user", "delete_user", "enable_user", "disable_user",
                       "reset_user_password", "create_group", "modify_group", "delete_group",
                       "add_group_member", "remove_group_member", "create_computer", "modify_computer",
                       "delete_computer", "enable_computer", "disable_computer",
                       "create_organizational_unit", "modify_organizational_unit",
                       "delete_organizational_unit", "move_organizational_unit"}
        assert _tool_names(server).isdisjoint(write_tools)

    def test_readwrite_registers_more_tools(self):
        with patch.dict(os.environ, {"AD_DOMAINS": SINGLE_DOMAIN_ENV, "AD_READONLY": "false"}):
            server = ActiveDirectoryMCPServer()
        assert len(_tool_names(server)) > 23

    def test_readwrite_includes_write_tools(self):
        with patch.dict(os.environ, {"AD_DOMAINS": SINGLE_DOMAIN_ENV, "AD_READONLY": "false"}):
            server = ActiveDirectoryMCPServer()
        names = _tool_names(server)
        assert "create_user" in names
        assert "delete_user" in names

    def test_fan_out_tools_always_registered(self):
        with patch.dict(os.environ, {"AD_DOMAINS": SINGLE_DOMAIN_ENV, "AD_READONLY": "true"}):
            server = ActiveDirectoryMCPServer()
        names = _tool_names(server)
        assert "search_all_domains_users" in names
        assert "search_all_domains_groups" in names
        assert "search_all_domains_computers" in names


class TestDomainLookup:
    def test_unknown_domain_raises_value_error(self):
        with patch.dict(os.environ, {"AD_DOMAINS": SINGLE_DOMAIN_ENV, "AD_READONLY": "true"}):
            server = ActiveDirectoryMCPServer()
        with pytest.raises(ValueError, match="Unknown domain"):
            server._mgr("nonexistent.local")

    def test_known_domain_creates_manager(self):
        with patch.dict(os.environ, {"AD_DOMAINS": SINGLE_DOMAIN_ENV, "AD_READONLY": "true"}):
            server = ActiveDirectoryMCPServer()
        mgr = server._mgr("corp.local")
        assert mgr.ad_config.domain == "corp.local"
        assert mgr.ad_config.base_dn == "DC=corp,DC=local"
