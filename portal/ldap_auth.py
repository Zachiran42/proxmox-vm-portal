from __future__ import annotations

import re
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from ldap3 import AUTO_BIND_NONE, NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

_LDAP_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")


class LDAPConfigurationError(ValueError):
    pass


class LDAPUnavailable(RuntimeError):
    pass


class LDAPAccessDenied(ValueError):
    pass


@dataclass(frozen=True)
class LDAPIdentity:
    issuer: str
    subject: str
    username: str
    role: str


class LDAPClient:
    def __init__(
        self,
        *,
        uri: str,
        base_dn: str,
        user_filter: str,
        username_attribute: str,
        group_attribute: str,
        role_groups: dict[str, str],
        bind_dn: str = "",
        bind_password: str = "",
        ca_file: str = "",
        start_tls: bool = True,
    ):
        parsed = urlsplit(uri)
        if (
            parsed.scheme not in {"ldap", "ldaps"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise LDAPConfigurationError("URI LDAP/LDAPS invalide.")
        if parsed.scheme == "ldap" and not start_tls:
            raise LDAPConfigurationError("StartTLS est obligatoire avec ldap://.")
        if user_filter.count("{username}") != 1:
            raise LDAPConfigurationError("Le filtre LDAP doit contenir {username} une fois.")
        if bool(bind_dn) != bool(bind_password):
            raise LDAPConfigurationError("Le DN et le secret de bind sont indissociables.")
        if not base_dn or not username_attribute or not group_attribute:
            raise LDAPConfigurationError("Configuration LDAP incomplète.")
        if not role_groups.get("user"):
            raise LDAPConfigurationError("Un groupe LDAP utilisateur est obligatoire.")

        tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_file or None)
        self.server = Server(
            parsed.hostname,
            port=parsed.port or (636 if parsed.scheme == "ldaps" else 389),
            use_ssl=parsed.scheme == "ldaps",
            tls=tls,
            get_info=NONE,
            connect_timeout=8,
        )
        self.uri = uri.rstrip("/")
        self.base_dn = base_dn
        self.user_filter = user_filter
        self.username_attribute = username_attribute
        self.group_attribute = group_attribute
        self.role_groups = {
            role: group.casefold() for role, group in role_groups.items() if group
        }
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.start_tls = parsed.scheme == "ldap"

    def _connection(
        self, user: str | None = None, password: str | None = None
    ) -> Connection:
        connection = Connection(
            self.server,
            user=user or None,
            password=password or None,
            auto_bind=AUTO_BIND_NONE,
            receive_timeout=10,
            raise_exceptions=False,
        )
        if not connection.open():
            raise LDAPUnavailable("Connexion LDAP indisponible.")
        if self.start_tls and not connection.start_tls():
            connection.unbind()
            raise LDAPUnavailable("Négociation StartTLS impossible.")
        return connection

    def authenticate(self, username: str, password: str) -> LDAPIdentity | None:
        if not username or not password or len(username) > 128 or len(password) > 1024:
            return None
        service = self._connection(self.bind_dn, self.bind_password)
        try:
            if not service.bind():
                raise LDAPUnavailable("Bind de service LDAP refusé.")
            search_filter = self.user_filter.format(
                username=escape_filter_chars(username)
            )
            if not service.search(
                self.base_dn,
                search_filter,
                search_scope=SUBTREE,
                attributes=[self.username_attribute, self.group_attribute],
                size_limit=2,
            ):
                return None
            if len(service.entries) != 1:
                return None
            entry = service.entries[0]
            subject = entry.entry_dn
            usernames = entry[self.username_attribute].values
            groups = {
                str(value).casefold()
                for value in entry[self.group_attribute].values
            }
            if len(usernames) != 1:
                return None
            portal_username = str(usernames[0]).strip().lower()
            if (
                not _LDAP_USERNAME.fullmatch(portal_username)
                or not 1 <= len(subject) <= 255
            ):
                raise LDAPAccessDenied("Identité LDAP invalide.")
        except LDAPException as error:
            raise LDAPUnavailable("Recherche LDAP impossible.") from error
        finally:
            service.unbind()

        user_connection = self._connection(subject, password)
        try:
            if not user_connection.bind():
                return None
        except LDAPException:
            return None
        finally:
            user_connection.unbind()

        role = next(
            (
                candidate
                for candidate in ("admin", "operator", "user")
                if self.role_groups.get(candidate) in groups
            ),
            None,
        )
        if role is None:
            raise LDAPAccessDenied("Aucun groupe LDAP autorisé.")
        return LDAPIdentity(self.uri, subject, portal_username, role)

    def check_connection(self) -> None:
        connection = self._connection(self.bind_dn, self.bind_password)
        try:
            if not connection.bind():
                raise LDAPUnavailable("Bind de service LDAP refusé.")
        finally:
            connection.unbind()
