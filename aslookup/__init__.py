'IP to AS lookup'

import logging
import pkg_resources


__version__ = pkg_resources.get_distribution('aslookup').version
__url__ = 'https://github.com/dspruell/aslookup'
__pkgtitle__ = 'aslookup'

logging.basicConfig(format='[%(levelname)s] %(message)s')

def get_version():
    'Return software version info'

    return u'{} {}'.format(__pkgtitle__, __version__)

