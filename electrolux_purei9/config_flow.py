from voluptuous.schema_builder import Schema
from homeassistant import config_entries
from .const import DOMAIN
import voluptuous as vol


class SetupConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Setup config flow."""

    async def async_step_user(self, info):

        if info is not None:
            pass  # TODO: process info

        data_schema = {
            vol.Required("username"): str,
            vol.Required("password"): str,
        }

        return self.async_show_form(step_id="user", data_schema=vol.Schema(data_schema))