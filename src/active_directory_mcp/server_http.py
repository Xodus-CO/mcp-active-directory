"""Multi-domain HTTP MCP server for Active Directory.

Replaces the original single-domain server with per-call domain selection.
Credentials are loaded from the AD_DOMAINS environment variable at startup.
Write tools are omitted when AD_READONLY=true (the default).
"""

import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP
from mcp.types import TextContent as Content

from .config.domain_config import (
    DomainCredentials,
    load_domain_map,
    is_readonly,
    make_ldap_manager,
)
from .tools.user import UserTools
from .tools.group import GroupTools
from .tools.computer import ComputerTools
from .tools.organizational_unit import OrganizationalUnitTools
from .tools.security import SecurityTools

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("active-directory-mcp")


def _ok(data: Any) -> List[Content]:
    return [Content(type="text", text=json.dumps(data, indent=2, ensure_ascii=False, default=str))]


def _err(msg: str) -> List[Content]:
    return [Content(type="text", text=json.dumps({"error": msg}, indent=2))]


def _unwrap(contents: List[Content]) -> Any:
    """Parse JSON from a tool's Content list for embedding in fan-out results."""
    if not contents:
        return None
    try:
        return json.loads(contents[0].text)
    except (json.JSONDecodeError, AttributeError):
        return contents[0].text if contents else None


class ActiveDirectoryMCPServer:

    def __init__(self) -> None:
        self.domain_map: Dict[str, DomainCredentials] = load_domain_map()
        self.readonly: bool = is_readonly()

        if not self.domain_map:
            logger.warning("AD_DOMAINS is empty — server will start but all domain calls will fail.")
        else:
            logger.info("Loaded domains: %s", list(self.domain_map.keys()))
        logger.info("Readonly mode: %s", self.readonly)

        self.mcp = FastMCP("ActiveDirectoryMCP")
        self._register_tools()

    def _mgr(self, domain: str) -> Any:
        creds = self.domain_map.get(domain)
        if creds is None:
            raise ValueError(f"Unknown domain '{domain}'. Available: {list(self.domain_map.keys())}")
        return make_ldap_manager(domain, creds)

    def _register_tools(self) -> None:  # noqa: C901
        readonly = self.readonly

        # ── Utility ────────────────────────────────────────────────────────────

        @self.mcp.tool(description="List configured AD domain FQDNs and readonly status")
        def list_domains() -> List[Content]:
            return _ok({"domains": list(self.domain_map.keys()), "readonly": self.readonly})

        @self.mcp.tool(description="Test LDAP connectivity for a specific domain")
        def test_connection(domain: str) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = mgr.test_connection()
                mgr.disconnect()
                return _ok(result)
            except Exception as exc:
                return _err(str(exc))

        # ── Users ──────────────────────────────────────────────────────────────

        @self.mcp.tool(description="List users in Active Directory for a domain")
        def list_users(domain: str, ou: Optional[str] = None,
                       filter_criteria: Optional[str] = None,
                       attributes: Optional[list] = None) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = UserTools(mgr).list_users(ou, filter_criteria, attributes)
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        @self.mcp.tool(description="Get detailed information about a specific user")
        def get_user(domain: str, username: str,
                     attributes: Optional[list] = None) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = UserTools(mgr).get_user(username, attributes)
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        @self.mcp.tool(description="Get groups that a user is a member of")
        def get_user_groups(domain: str, username: str) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = UserTools(mgr).get_user_groups(username)
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        if not readonly:
            @self.mcp.tool(description="Create a new user in Active Directory")
            def create_user(domain: str, username: str, password: str,
                            first_name: str, last_name: str,
                            email: Optional[str] = None,
                            ou: Optional[str] = None,
                            additional_attributes: Optional[dict] = None) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = UserTools(mgr).create_user(
                        username, password, first_name, last_name, email, ou, additional_attributes)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Modify user attributes")
            def modify_user(domain: str, username: str, attributes: dict) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = UserTools(mgr).modify_user(username, attributes)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Delete a user from Active Directory")
            def delete_user(domain: str, username: str) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = UserTools(mgr).delete_user(username)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Enable a user account")
            def enable_user(domain: str, username: str) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = UserTools(mgr).enable_user(username)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Disable a user account")
            def disable_user(domain: str, username: str) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = UserTools(mgr).disable_user(username)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Reset user password")
            def reset_user_password(domain: str, username: str,
                                    new_password: Optional[str] = None,
                                    force_change: bool = True) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = UserTools(mgr).reset_password(username, new_password, force_change)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

        # ── Groups ─────────────────────────────────────────────────────────────

        @self.mcp.tool(description="List groups in Active Directory for a domain")
        def list_groups(domain: str, ou: Optional[str] = None,
                        filter_criteria: Optional[str] = None,
                        attributes: Optional[list] = None) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = GroupTools(mgr).list_groups(ou, filter_criteria, attributes)
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        @self.mcp.tool(description="Get detailed information about a specific group")
        def get_group(domain: str, group_name: str,
                      attributes: Optional[list] = None) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = GroupTools(mgr).get_group(group_name, attributes)
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        @self.mcp.tool(description="Get members of a group")
        def get_group_members(domain: str, group_name: str,
                              recursive: bool = False) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = GroupTools(mgr).get_members(group_name, recursive)
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        if not readonly:
            @self.mcp.tool(description="Create a new group in Active Directory")
            def create_group(domain: str, group_name: str,
                             display_name: Optional[str] = None,
                             description: Optional[str] = None,
                             ou: Optional[str] = None,
                             group_scope: str = "Global",
                             group_type: str = "Security",
                             additional_attributes: Optional[dict] = None) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = GroupTools(mgr).create_group(
                        group_name, display_name, description, ou,
                        group_scope, group_type, additional_attributes)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Modify group attributes")
            def modify_group(domain: str, group_name: str, attributes: dict) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = GroupTools(mgr).modify_group(group_name, attributes)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Delete a group from Active Directory")
            def delete_group(domain: str, group_name: str) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = GroupTools(mgr).delete_group(group_name)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Add a member to a group")
            def add_group_member(domain: str, group_name: str, member_dn: str) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = GroupTools(mgr).add_member(group_name, member_dn)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Remove a member from a group")
            def remove_group_member(domain: str, group_name: str, member_dn: str) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = GroupTools(mgr).remove_member(group_name, member_dn)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

        # ── Computers ──────────────────────────────────────────────────────────

        @self.mcp.tool(description="List computer objects in Active Directory for a domain")
        def list_computers(domain: str, ou: Optional[str] = None,
                           filter_criteria: Optional[str] = None,
                           attributes: Optional[list] = None) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = ComputerTools(mgr).list_computers(ou, filter_criteria, attributes)
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        @self.mcp.tool(description="Get detailed information about a specific computer")
        def get_computer(domain: str, computer_name: str,
                         attributes: Optional[list] = None) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = ComputerTools(mgr).get_computer(computer_name, attributes)
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        @self.mcp.tool(description="Get stale computers (not logged in for specified days)")
        def get_stale_computers(domain: str, days: int = 90) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = ComputerTools(mgr).get_stale_computers(days)
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        if not readonly:
            @self.mcp.tool(description="Create a new computer object in Active Directory")
            def create_computer(domain: str, computer_name: str,
                                description: Optional[str] = None,
                                ou: Optional[str] = None,
                                dns_hostname: Optional[str] = None,
                                additional_attributes: Optional[dict] = None) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = ComputerTools(mgr).create_computer(
                        computer_name, description, ou, dns_hostname, additional_attributes)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Modify computer attributes")
            def modify_computer(domain: str, computer_name: str,
                                attributes: dict) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = ComputerTools(mgr).modify_computer(computer_name, attributes)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Delete a computer from Active Directory")
            def delete_computer(domain: str, computer_name: str) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = ComputerTools(mgr).delete_computer(computer_name)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Enable a computer account")
            def enable_computer(domain: str, computer_name: str) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = ComputerTools(mgr).enable_computer(computer_name)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Disable a computer account")
            def disable_computer(domain: str, computer_name: str) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = ComputerTools(mgr).disable_computer(computer_name)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

        # ── Organizational Units ────────────────────────────────────────────────

        @self.mcp.tool(description="List Organizational Units in Active Directory for a domain")
        def list_organizational_units(domain: str, parent_ou: Optional[str] = None,
                                      filter_criteria: Optional[str] = None,
                                      attributes: Optional[list] = None,
                                      recursive: bool = True) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = OrganizationalUnitTools(mgr).list_ous(
                    parent_ou, filter_criteria, attributes, recursive)
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        @self.mcp.tool(description="Get detailed information about a specific Organizational Unit")
        def get_organizational_unit(domain: str, ou_dn: str,
                                    attributes: Optional[list] = None) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = OrganizationalUnitTools(mgr).get_ou(ou_dn, attributes)
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        @self.mcp.tool(description="Get contents of an Organizational Unit")
        def get_organizational_unit_contents(domain: str, ou_dn: str,
                                              object_types: Optional[list] = None) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = OrganizationalUnitTools(mgr).get_ou_contents(ou_dn, object_types)
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        if not readonly:
            @self.mcp.tool(description="Create a new Organizational Unit")
            def create_organizational_unit(domain: str, name: str,
                                           parent_ou: Optional[str] = None,
                                           description: Optional[str] = None,
                                           managed_by: Optional[str] = None,
                                           additional_attributes: Optional[dict] = None) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = OrganizationalUnitTools(mgr).create_ou(
                        name, parent_ou, description, managed_by, additional_attributes)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Modify OU attributes")
            def modify_organizational_unit(domain: str, ou_dn: str,
                                           attributes: dict) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = OrganizationalUnitTools(mgr).modify_ou(ou_dn, attributes)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Delete an Organizational Unit")
            def delete_organizational_unit(domain: str, ou_dn: str,
                                           force: bool = False) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = OrganizationalUnitTools(mgr).delete_ou(ou_dn, force)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

            @self.mcp.tool(description="Move an OU to a new parent")
            def move_organizational_unit(domain: str, ou_dn: str,
                                         new_parent_dn: str) -> List[Content]:
                try:
                    mgr = self._mgr(domain)
                    result = OrganizationalUnitTools(mgr).move_ou(ou_dn, new_parent_dn)
                    mgr.disconnect()
                    return result
                except Exception as exc:
                    return _err(str(exc))

        # ── Security ───────────────────────────────────────────────────────────

        @self.mcp.tool(description="Get domain information and security settings")
        def get_domain_info(domain: str) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = SecurityTools(mgr).get_domain_info()
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        @self.mcp.tool(description="Get information about privileged groups")
        def get_privileged_groups(domain: str) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = SecurityTools(mgr).get_privileged_groups()
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        @self.mcp.tool(description="Get effective permissions for a user")
        def get_user_permissions(domain: str, username: str) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = SecurityTools(mgr).get_user_permissions(username)
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        @self.mcp.tool(description="Get inactive users")
        def get_inactive_users(domain: str, days: int = 90,
                               include_disabled: bool = False) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = SecurityTools(mgr).get_inactive_users(days, include_disabled)
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        @self.mcp.tool(description="Get users with password policy violations")
        def get_password_policy_violations(domain: str) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = SecurityTools(mgr).get_password_policy_violations()
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        @self.mcp.tool(description="Audit administrative accounts")
        def audit_admin_accounts(domain: str) -> List[Content]:
            try:
                mgr = self._mgr(domain)
                result = SecurityTools(mgr).audit_admin_accounts()
                mgr.disconnect()
                return result
            except Exception as exc:
                return _err(str(exc))

        # ── Fan-out (cross-domain) ─────────────────────────────────────────────

        @self.mcp.tool(
            description="Search for users by name across all configured domains in parallel. "
                        "Returns per-domain results; failed domains report status=error instead of "
                        "failing the entire call."
        )
        def search_all_domains_users(query: str) -> List[Content]:
            results: Dict[str, Any] = {}

            def _search(fqdn: str) -> tuple:
                try:
                    mgr = make_ldap_manager(fqdn, self.domain_map[fqdn])
                    contents = UserTools(mgr).list_users(
                        filter_criteria=f"(|(cn=*{query}*)(sAMAccountName=*{query}*)(displayName=*{query}*))"
                    )
                    mgr.disconnect()
                    return fqdn, {"status": "ok", "data": _unwrap(contents)}
                except Exception as exc:
                    return fqdn, {"status": "error", "error": str(exc)}

            workers = min(10, max(1, len(self.domain_map)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(_search, fqdn): fqdn for fqdn in self.domain_map}
                for future in as_completed(futures):
                    fqdn, result = future.result()
                    results[fqdn] = result

            return _ok(results)

        @self.mcp.tool(
            description="Search for groups by name across all configured domains in parallel. "
                        "Returns per-domain results; failed domains report status=error."
        )
        def search_all_domains_groups(query: str) -> List[Content]:
            results: Dict[str, Any] = {}

            def _search(fqdn: str) -> tuple:
                try:
                    mgr = make_ldap_manager(fqdn, self.domain_map[fqdn])
                    contents = GroupTools(mgr).list_groups(
                        filter_criteria=f"(|(cn=*{query}*)(displayName=*{query}*))"
                    )
                    mgr.disconnect()
                    return fqdn, {"status": "ok", "data": _unwrap(contents)}
                except Exception as exc:
                    return fqdn, {"status": "error", "error": str(exc)}

            workers = min(10, max(1, len(self.domain_map)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(_search, fqdn): fqdn for fqdn in self.domain_map}
                for future in as_completed(futures):
                    fqdn, result = future.result()
                    results[fqdn] = result

            return _ok(results)

        @self.mcp.tool(
            description="Search for computers by hostname across all configured domains in parallel. "
                        "Returns per-domain results; failed domains report status=error."
        )
        def search_all_domains_computers(query: str) -> List[Content]:
            results: Dict[str, Any] = {}

            def _search(fqdn: str) -> tuple:
                try:
                    mgr = make_ldap_manager(fqdn, self.domain_map[fqdn])
                    contents = ComputerTools(mgr).list_computers(
                        filter_criteria=f"(cn=*{query}*)"
                    )
                    mgr.disconnect()
                    return fqdn, {"status": "ok", "data": _unwrap(contents)}
                except Exception as exc:
                    return fqdn, {"status": "error", "error": str(exc)}

            workers = min(10, max(1, len(self.domain_map)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(_search, fqdn): fqdn for fqdn in self.domain_map}
                for future in as_completed(futures):
                    fqdn, result = future.result()
                    results[fqdn] = result

            return _ok(results)

    def run(self, host: str = "0.0.0.0", port: int = 8000) -> None:
        host = os.environ.get("MCP_HOST", host)
        port = int(os.environ.get("MCP_PORT", str(port)))
        logger.info("Starting Active Directory MCP server on %s:%d", host, port)
        self.mcp.run(transport="http", host=host, port=port)


def main() -> None:
    ActiveDirectoryMCPServer().run()


if __name__ == "__main__":
    main()
