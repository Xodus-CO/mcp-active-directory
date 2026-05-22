"""Multi-domain credential configuration loaded from AD_DOMAINS environment variable."""

import json
import os
from dataclasses import dataclass
from typing import Dict

from .models import ActiveDirectoryConfig, SecurityConfig, PerformanceConfig
from ..core.ldap_manager import LDAPManager


@dataclass
class DomainCredentials:
    host: str       # ldaps://dc01.corp.local
    bind_dn: str    # CN=svc-mcp,OU=Service Accounts,DC=corp,DC=local
    password: str
    base_dn: str    # DC=corp,DC=local


def _fqdn_to_base_dn(fqdn: str) -> str:
    return ",".join(f"DC={part}" for part in fqdn.split("."))


def load_domain_map() -> Dict[str, DomainCredentials]:
    """Parse AD_DOMAINS JSON blob from environment.

    Expected format:
        {
            "corp.local": {
                "host": "ldaps://dc01.corp.local",
                "bind_dn": "CN=svc-mcp,...",
                "password": "secret",
                "base_dn": "DC=corp,DC=local"   # optional, derived from FQDN if absent
            }
        }
    """
    raw = os.environ.get("AD_DOMAINS", "")
    if not raw:
        return {}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"AD_DOMAINS is not valid JSON: {exc}") from exc

    result: Dict[str, DomainCredentials] = {}
    for fqdn, creds in data.items():
        base_dn = creds.get("base_dn") or _fqdn_to_base_dn(fqdn)
        result[fqdn] = DomainCredentials(
            host=creds["host"],
            bind_dn=creds["bind_dn"],
            password=creds["password"],
            base_dn=base_dn,
        )
    return result


def is_readonly() -> bool:
    """Return True unless AD_READONLY is explicitly set to false/0/no."""
    val = os.environ.get("AD_READONLY", "true").lower()
    return val not in ("false", "0", "no")


def make_ldap_manager(fqdn: str, creds: DomainCredentials) -> LDAPManager:
    """Construct a per-call LDAPManager for a single domain."""
    use_tls = creds.host.startswith("ldaps://")
    ad_config = ActiveDirectoryConfig(
        server=creds.host,
        domain=fqdn,
        base_dn=creds.base_dn,
        bind_dn=creds.bind_dn,
        password=creds.password,
        use_ssl=use_tls,
    )
    security_config = SecurityConfig(
        enable_tls=use_tls,
        validate_certificate=False,  # Internal AD DCs typically use private CA certs
    )
    return LDAPManager(
        ad_config=ad_config,
        security_config=security_config,
        performance_config=PerformanceConfig(),
    )
