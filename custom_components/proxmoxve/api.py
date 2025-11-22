"""Handle API for Proxmox VE."""

from typing import Any

from homeassistant.const import CONF_USERNAME
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import issue_registry as ir
from proxmoxer import ProxmoxAPI
from proxmoxer.core import ResourceException
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectTimeout

from .const import (
    DEFAULT_PORT,
    DEFAULT_REALM,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    LOGGER,
    ProxmoxCommand,
    ProxmoxType,
)

POOL_MAXSIZE = 50


class ProxmoxClient:
    """A wrapper for the proxmoxer ProxmoxAPI client."""

    _proxmox: ProxmoxAPI | None

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        token_name: str = "",
        port: int | None = DEFAULT_PORT,
        realm: str | None = DEFAULT_REALM,
        verify_ssl: bool | None = DEFAULT_VERIFY_SSL,
    ) -> None:
        """Initialize the ProxmoxClient."""
        self._host = host
        self._port = port
        self._user = user
        self._token_name = token_name
        self._realm = realm
        self._password = password
        self._verify_ssl = verify_ssl
        self._pool_size = POOL_MAXSIZE
        self._proxmox = None

    def reconfigure(
        self,
        host: str,
        user: str,
        password: str,
        token_name: str = "",
        port: int | None = DEFAULT_PORT,
        realm: str | None = DEFAULT_REALM,
        verify_ssl: bool | None = DEFAULT_VERIFY_SSL,
    ) -> None:
        """Update stored credentials and drop the cached session if anything changed."""
        if (
            host,
            port,
            user,
            token_name,
            realm,
            password,
            verify_ssl,
        ) == (
            self._host,
            self._port,
            self._user,
            self._token_name,
            self._realm,
            self._password,
            self._verify_ssl,
        ):
            return

        self._host = host
        self._port = port
        self._user = user
        self._token_name = token_name
        self._realm = realm
        self._password = password
        self._verify_ssl = verify_ssl

        self.close()

    def _configure_pool(self) -> None:
        """Bump the urllib3 pool size so HA's concurrent polling does not exhaust it."""
        if self._proxmox is None:
            return

        session = (
            self._proxmox._store.get("session")
            if hasattr(self._proxmox, "_store")
            else None
        )
        if session is None:
            return

        adapter = HTTPAdapter(pool_maxsize=self._pool_size)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

    def build_client(self) -> None:
        """
        Construct the ProxmoxAPI client.

        Allows inserting the realm within the `user` value. The client is cached so we
        reuse a single requests session per config entry and avoid filling the urllib3
        connection pool with duplicate sessions.
        """
        if self._proxmox is not None:
            return

        user_id = self._user if "@" in self._user else f"{self._user}@{self._realm}"

        if self._token_name:
            self._proxmox = ProxmoxAPI(
                self._host,
                port=self._port,
                user=user_id,
                token_name=self._token_name,
                token_value=self._password,
                verify_ssl=self._verify_ssl,
                timeout=30,
            )
        else:
            self._proxmox = ProxmoxAPI(
                self._host,
                port=self._port,
                user=user_id,
                password=self._password,
                verify_ssl=self._verify_ssl,
                timeout=30,
            )

        self._configure_pool()

    def get_api_client(self) -> ProxmoxAPI:
        """Return the ProxmoxAPI client."""
        if self._proxmox is None:
            msg = "Proxmox client has not been built"
            raise HomeAssistantError(msg)
        return self._proxmox

    def close(self) -> None:
        """Close the underlying requests session so sockets are released."""
        if self._proxmox is None:
            return

        session = (
            self._proxmox._store.get("session")
            if hasattr(self._proxmox, "_store")
            else None
        )
        if session is not None and hasattr(session, "close"):
            session.close()
        self._proxmox = None


def get_api(
    proxmox: ProxmoxAPI,
    api_path: str,
) -> dict[str, Any] | None:
    """Return data from the Proxmox API."""
    api_result = proxmox.get(api_path)
    LOGGER.debug("API GET Response - %s: %s", api_path, api_result)
    return api_result


def post_api(
    proxmox: ProxmoxAPI,
    api_path: str,
) -> dict[str, Any] | None:
    """Post data to Proxmox API."""
    api_result = proxmox.post(api_path)
    LOGGER.debug("API POST - %s: %s", api_path, api_result)
    return api_result


def post_api_command(
    self,
    proxmox_client: ProxmoxClient,
    api_category: ProxmoxType,
    command: str,
    node: str,
    vm_id: int | None = None,
) -> Any:
    """Make proper api post status calls to set state."""
    result = None

    proxmox = proxmox_client.get_api_client()

    if command not in ProxmoxCommand:
        msg = "Invalid Command"
        raise ValueError(msg)

    issue_id = f"{self.config_entry.entry_id}_command_forbiden"
    resource = f"{api_category.capitalize()} {node}"
    if api_category is ProxmoxType.Node:
        issue_id = f"{self.config_entry.entry_id}_{node}_command_forbiden"
    elif api_category in (ProxmoxType.QEMU, ProxmoxType.LXC):
        issue_id = f"{self.config_entry.entry_id}_{vm_id}_command_forbiden"
        resource = f"{api_category.upper()} {vm_id}"

    try:
        # START_ALL, STOP_ALL, WAKEONLAN are not part of status API
        if api_category is ProxmoxType.Node and command in [
            ProxmoxCommand.START_ALL,
            ProxmoxCommand.STOP_ALL,
            ProxmoxCommand.WAKEONLAN,
        ]:
            result = post_api(proxmox, f"nodes/{node}/{command}")
        elif api_category is ProxmoxType.Node:
            result = post_api(proxmox, f"nodes/{node}/status?command={command}")
        elif command == ProxmoxCommand.HIBERNATE:
            result = post_api(
                proxmox,
                f"nodes/{node}/{api_category}/{vm_id}/status/{ProxmoxCommand.SUSPEND}?todisk=1",
            )
        else:
            result = post_api(
                proxmox, f"nodes/{node}/{api_category}/{vm_id}/status/{command}"
            )

    except ResourceException as error:
        if error.status_code == 403:
            permissions = str(error).split("(")[1].split(",")
            permission_check = (
                f"['perm','{permissions[0]}',[{permissions[1].strip().strip(')')}]]"
            )
            ir.create_issue(
                self.hass,
                DOMAIN,
                issue_id,
                is_fixable=False,
                severity=ir.IssueSeverity.ERROR,
                translation_key="resource_command_forbiden",
                translation_placeholders={
                    "resource": resource,
                    "user": self.config_entry.data[CONF_USERNAME],
                    "permission": permission_check,
                    "command": command,
                },
            )
            msg = f"Proxmox {resource} {command} error - {error}"
            raise HomeAssistantError(
                msg,
            ) from error

    except ConnectTimeout as error:
        msg = f"Proxmox {resource} {command} error - {error}"
        raise HomeAssistantError(
            msg,
        ) from error

    ir.delete_issue(
        self.hass,
        DOMAIN,
        issue_id,
    )

    return result
