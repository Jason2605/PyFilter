"""
Custom exceptions used throughout PyFilter
"""


class DatabaseConfigException(Exception):
    """Raised when the supplied database config does not match sqlite or redis"""
