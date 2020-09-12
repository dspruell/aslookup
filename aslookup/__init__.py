'AS lookup tool'

import logging
import pkg_resources


__application_name__ = __name__
__version__ = pkg_resources.get_distribution(__application_name__).version
__full_version__ = ' '.join([__application_name__, __version__])
