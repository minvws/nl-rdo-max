from inge6.config import _create_settings


def get_settings(setting_changes: dict = {}):  # pylint: disable=dangerous-default-value
    """
    change the default settings:

    sample dict:
        setting_changes = {
            'ratelimit.nof_attempts_s': 1
        }

    output:
        Setting object with defined changes
    """
    settings = _create_settings("inge6.conf.example")
    for setting, value in setting_changes.items():
        if "." not in setting:
            settings["DEFAULT"][setting] = str(value)
        else:
            try:
                section, name = setting.split(".")
            except ValueError as invalid_items_to_unpack:
                raise ValueError(
                    f"Setting is not recognized: {setting}"
                ) from invalid_items_to_unpack

            settings[section][name] = str(value)

    return settings
