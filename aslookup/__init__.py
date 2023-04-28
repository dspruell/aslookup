"""Multi-service IP-ASN lookup tool."""

from importlib.metadata import version

# XXX It appears in some cases this line is required for the script to
# function, and it's not clear why given that the function is not used in this
# module.
# from .lookup import get_as_data  # noqa: F401


__application_name__ = __name__
__version__ = version(__application_name__)
__full_version__ = f"{__application_name__} {__version__}"
