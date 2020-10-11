'Multi-service IP-AS lookup tool'

import pkg_resources

from .lookup import get_as_data  # noqa: F401


__application_name__ = __name__
__version__ = pkg_resources.get_distribution(__application_name__).version
__full_version__ = ' '.join([__application_name__, __version__])
