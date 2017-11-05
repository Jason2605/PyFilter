class ConfigNotFound(Exception):
    """Raises when the config file cant be found"""
    pass


class DatabaseConfigException(Exception):
    """Raises when the database supplied in the config does not match sqlite/redis"""
    pass



