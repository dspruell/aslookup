'Exception classes and errors'


class LookupError(Exception):
    '''Base exception class.'''
    pass


class NoASDataError(LookupError):
    '''Supplied address is not currently part of an advertised prefix.'''
    pass


class NonroutableAddressError(LookupError):
    '''Supplied address is part of a non-routable IP allocation.'''
    pass


class AddressFormatError(LookupError):
    '''Supplied address is not a valid IPv4 address.'''
    pass
