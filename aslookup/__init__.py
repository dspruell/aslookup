"""Multi-service IP-ASN lookup tool."""

from importlib.metadata import version

from .lookup import get_as_data

__all__ = (get_as_data,)


__application_name__ = __name__
__version__ = version(__application_name__)
__full_version__ = f"{__application_name__} {__version__}"
