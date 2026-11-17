"""Who is the signed-in user?

On App Service the Microsoft Entra sign-in is done by App Service Authentication ("Easy Auth"), which
sits in front of the app and passes the user's identity in the X-MS-CLIENT-PRINCIPAL header (base64
JSON holding the token's claims). The user is identified by tenant id + object id: both are immutable,
unlike an e-mail address or UPN.

TRUST WARNING: those headers can be forged by anyone UNLESS Easy Auth is enabled with "Require
authentication", in which case App Service strips and rewrites them. See README.md to check this.

For running on your PC there is a stand-in sign-in (/dev/as/<name>), enabled only by ALLOW_DEV_USER=1
and refused outright when running on App Service.
"""
import base64
import binascii
import json
import re
import uuid
from dataclasses import dataclass

import egnyte_oauth

PRINCIPAL_HEADER = "X-MS-CLIENT-PRINCIPAL"
DEV_COOKIE = "dev_user"
GUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
DEV_NAME = re.compile(r"[a-z0-9._-]{1,32}")

TENANT_CLAIMS = ("http://schemas.microsoft.com/identity/claims/tenantid", "tid")
OBJECT_CLAIMS = ("http://schemas.microsoft.com/identity/claims/objectidentifier", "oid")
NAME_CLAIMS = ("preferred_username", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
               "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "name")
MAX_HEADER_LENGTH = 16 * 1024


@dataclass(frozen=True)
class User:
    tenant_id: str
    object_id: str
    name: str            # for display only; never used as an identifier

    @property
    def key(self):
        """The stable identifier for this person, used to look up their stored Egnyte token."""
        return f"{self.tenant_id}:{self.object_id}"


def _claim(claims, names):
    for wanted in names:
        for claim in claims:
            if isinstance(claim, dict) and claim.get("typ") == wanted and isinstance(claim.get("val"), str):
                return claim["val"]
    return None


def parse_principal(header_value):
    """The User described by an X-MS-CLIENT-PRINCIPAL header value, or None if it is unusable."""
    if not header_value or len(header_value) > MAX_HEADER_LENGTH:
        return None
    try:
        padded = header_value + "=" * (-len(header_value) % 4)
        data = json.loads(base64.b64decode(padded, validate=True).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    claims = data.get("claims") if isinstance(data, dict) else None
    if not isinstance(claims, list):
        return None
    tenant, oid = _claim(claims, TENANT_CLAIMS), _claim(claims, OBJECT_CLAIMS)
    if not (tenant and oid and GUID.fullmatch(tenant) and GUID.fullmatch(oid)):
        return None
    name = _claim(claims, NAME_CLAIMS) or "(no name claim)"
    return User(tenant.lower(), oid.lower(), egnyte_oauth.safe_text(name, 128))


def dev_user(name):
    """A stable fake identity for local testing. Only called when ALLOW_DEV_USER=1."""
    if not (isinstance(name, str) and DEV_NAME.fullmatch(name)):
        return None
    tenant = uuid.uuid5(uuid.NAMESPACE_DNS, "tenant.dev.invalid")
    return User(str(tenant), str(uuid.uuid5(uuid.NAMESPACE_DNS, f"user.{name}.dev.invalid")), f"{name} (dev)")


def current_user(headers, cookies, settings):
    """The signed-in User for this request, or None."""
    user = parse_principal(headers.get(PRINCIPAL_HEADER))
    if user is None and settings.allow_dev_user:
        user = dev_user(cookies.get(DEV_COOKIE))
    return user
