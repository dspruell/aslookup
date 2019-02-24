# $Id: aslookup.py 904 2019-02-24 01:18:22Z dspruell $
#
# Copyright (c) 2012-2019 Darren Spruell <phatbuckett@gmail.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# Performs a lookup for a given IP address against Team Cymru or Shadowserver
# IP to ASN lookup services. See README.md for more information.
#
# Requires: dnspython http://www.dnspython.org/

import re
import sys
import argparse
from time import sleep
from collections import namedtuple
import dns.resolver, dns.reversename

AS_SERVICE = {
    'shadowserver': {
        'origin_prefix': 'origin.asn.shadowserver.org',
    },
    'cymru': {
        'origin_prefix': 'origin.asn.cymru.com',
        'as_description_prefix': 'asn.cymru.com',
    },
}

# IPs with these prefixes aren't routable on Internet and need not be sent
# to lookup service. Ref. RFC 5735.
IP_NOLOOKUP = {
    '0.':           'RFC 1122 IPv4 any',
    '127.':         'RFC 1122 loopback', 
    '10.':          'RFC 1918 range',
    # RFC 6598 100.64.0.0/10 100.64.0.0 - 100.127.255.255
    '169.254.':     'RFC 3927 link local range',
    '172.16.':      'RFC 1918 range',
    '172.17.':      'RFC 1918 range',
    '172.18.':      'RFC 1918 range',
    '172.19.':      'RFC 1918 range',
    '172.20.':      'RFC 1918 range',
    '172.21.':      'RFC 1918 range',
    '172.22.':      'RFC 1918 range',
    '172.23.':      'RFC 1918 range',
    '172.24.':      'RFC 1918 range',
    '172.25.':      'RFC 1918 range',
    '172.26.':      'RFC 1918 range',
    '172.27.':      'RFC 1918 range',
    '172.28.':      'RFC 1918 range',
    '172.29.':      'RFC 1918 range',
    '172.30.':      'RFC 1918 range',
    '172.31.':      'RFC 1918 range',
    '192.0.0.':     'RFC 5736 protocol assignment range',
    '192.0.2.':     'RFC 5737 TEST-NET-1 range',
    '192.88.99.':   'RFC 3068 6to4 relay anycast range',
    '192.168.':     'RFC 1918 range',
    '198.18.':      'RFC 2544 network device benchmark range',
    '198.19.':      'RFC 2544 network device benchmark range',
    '198.51.100.':  'RFC 5737 TEST-NET-2 range',
    '203.0.113.':   'RFC 5737 TEST-NET-3 range',
    '224.':         'RFC 5771 multicast range',
    '225.':         'RFC 5771 multicast range',
    '226.':         'RFC 5771 multicast range',
    '227.':         'RFC 5771 multicast range',
    '228.':         'RFC 5771 multicast range',
    '229.':         'RFC 5771 multicast range',
    '230.':         'RFC 5771 multicast range',
    '231.':         'RFC 5771 multicast range',
    '232.':         'RFC 5771 multicast range',
    '233.':         'RFC 5771 multicast range',
    '234.':         'RFC 5771 multicast range',
    '235.':         'RFC 5771 multicast range',
    '236.':         'RFC 5771 multicast range',
    '237.':         'RFC 5771 multicast range',
    '238.':         'RFC 5771 multicast range',
    '239.':         'RFC 5771 multicast range',
    '240.':         'RFC 1112 IANA future use reserved range',
    '241.':         'RFC 1112 IANA future use reserved range',
    '242.':         'RFC 1112 IANA future use reserved range',
    '243.':         'RFC 1112 IANA future use reserved range',
    '244.':         'RFC 1112 IANA future use reserved range',
    '245.':         'RFC 1112 IANA future use reserved range',
    '246.':         'RFC 1112 IANA future use reserved range',
    '247.':         'RFC 1112 IANA future use reserved range',
    '248.':         'RFC 1112 IANA future use reserved range',
    '249.':         'RFC 1112 IANA future use reserved range',
    '250.':         'RFC 1112 IANA future use reserved range',
    '251.':         'RFC 1112 IANA future use reserved range',
    '252.':         'RFC 1112 IANA future use reserved range',
    '253.':         'RFC 1112 IANA future use reserved range',
    '254.':         'RFC 1112 IANA future use reserved range',
    '255.':         'RFC 1112 IPv4 limited broadcast',
}

IPV4_FMT = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

# Structured record tuple
ASData = namedtuple('ASData', ['handle', 'asn', 'as_name', 'rir', 'reg_date',
                    'prefix', 'cc', 'domain', 'data_source'])

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


def validate_ipv4(addr):
    '''Validate that input is a valid IPv4 address.'''
    # Check that it's a valid IPv4 address format
    if not re.match(IPV4_FMT, addr):
        raise AddressFormatError('Invalid format for IPv4 address')
    for octet in addr.split('.'):
        if not 0 <= int(octet) <= 255:
            raise AddressFormatError('Invalid octet value for IPv4 address')

    # Verify address not in reserved/non-routable prefixes.
    for p in list(IP_NOLOOKUP.keys()):
        if addr.startswith(p):
            raise NonroutableAddressError(IP_NOLOOKUP[p])
    return

def get_cymru_data(s):
    '''Parse Team Cymru AS data query and return structured record tuple.'''
    s = s.strip('"')
    # Cymru results began to append a comma and country code to the end of the
    # AS name, polluting the data. Strip it off.
    s = re.sub(r', [A-Z]{2}$', '', s)
    fields = s.split(' | ')
    as_data = ASData(asn=fields[0],
                     handle='AS{0}'.format(fields[0]),
                     as_name=fields[4],
                     prefix=None,
                     domain=None,
                     cc=fields[1],
                     rir=fields[2],
                     reg_date=fields[3],
                     data_source='cymru')
    return as_data

def get_shadowserver_data(s):
    '''Parse Shadowserver AS data query and return structured record tuple.'''
    s = s.strip('"')
    # Shadowserver results began to append a comma and country code to the
    # end of the AS name, polluting the data. Strip it off.
    s = re.sub(r', [A-Z]{2}$', '', s)
    fields = s.split(' | ')
    as_data = ASData(asn=fields[0],
                     handle='AS{0}'.format(fields[0]),
                     as_name='{0} - {1}'.format(fields[2], fields[4]),
                     prefix=fields[1],
                     domain=fields[4],
                     cc=fields[3],
                     rir=None,
                     reg_date=None,
                     data_source='shadowserver')
    return as_data

def get_as_data(addr, service='shadowserver'):
    '''
    Query and return AS information for supplied IP address.

    Return string containing formatted AS information for a given IP address, 
    unless the address falls into these categories: it is not a valid IPv4 
    address, there is no current AS data for that address, (i.e. not part of an 
    announced prefix), or it is known to be a non-routable IP address. In these
    cases, an appropriate exception is raised.

    '''
    addr = addr.strip()
    try:
        validate_ipv4(addr)
    except AddressFormatError as e:
        raise
    except LookupError as e:
        raise LookupError('Ignoring: %s' % e)

    # Format IP to reversed-octet structure and issue origin lookup.
    rev_addr = '.'.join(reversed(addr.split('.')))
    origin_addr = '.'.join([rev_addr, AS_SERVICE[service]['origin_prefix']])
    try:
        answers = dns.resolver.query(origin_addr, 'TXT')
    except dns.resolver.NXDOMAIN:
        raise NoASDataError('No routing origin data for address')

    if answers:
        if service == 'shadowserver':
            # Shadowserver origin lookup response includes AS name information
            asdata_text = answers[0].to_text()
            asdata = get_shadowserver_data(asdata_text)
            # Shadowserver will still output information in cases that no ASN
            # is identified, so raise exception when this occurs
            if not asdata.asn:
                raise NoASDataError('No routing origin data for address')
        else:
            # Team Cymru origin lookup response returns only ASN and requires
            # second lookup to return AS name information
            origin_data = answers[0].to_text().strip('"')
            m = re.match(r'^\d+', origin_data)
            as_data_addr = 'AS{0}.{1}'.format(int(m.group(0)),
                                            AS_SERVICE[service]['as_description_prefix'])
            try:
                answers = dns.resolver.query(as_data_addr, 'TXT')
            except dns.resolver.NXDOMAIN:
                raise NoASDataError('No routing origin data for address')
            if answers:
                asdata_text = answers[0].to_text()
                asdata = get_cymru_data(asdata_text)
        return asdata

def main():
    description = 'Client to return autonomous system information for IPv4 addresses'
    epilog = ('One or more IP addresses may be passed as arguments on the '
              'command line. A list of IP addresses (newline-separated) may '
              'also be passed on standard input.')
    parser = argparse.ArgumentParser(description=description, epilog=epilog)
    parser.add_argument('-s', '--service', choices=['shadowserver', 'cymru'],
                        default='shadowserver',
                        help='service to query (default: %(default)s)')
    parser.add_argument('-H', '--header', action='store_true',
                        help='print descriptive header before output')
    parser.add_argument('-p', '--pause', action='store_true',
                        help='pause for one second between each query on address list input')
    parser.add_argument('-r', '--raw', action='store_true',
                        help='display internal ASData object showing the value '
                             'of each known field in the AS data')
    parser.add_argument('address', nargs='*', help='IPv4 address(es) on which to perform AS lookup')
    args = parser.parse_args()

    # Print header lines if specified
    if args.header:
        print('-' * 50)
        print('%-15s  %s' % ('IP Address', 'AS Information'))
        print('-' * 50)

    # Process addresses given as parameters or fed on stdin.
    # - Input as parameters: In this mode, invalid IP addresses result in
    #   script exiting with an error. Non-routable addresses result in
    #   message to stderr.
    # - Input on stdin: In this mode, invalid IP addresses result in script
    #   proceeding without exiting, in order to make it so that address lists
    #   process without interruption. All issues are output on stderr.
    in_src = args.address if args.address else sys.stdin
    for addr in in_src:
        addr = addr.strip()
        try:
            data = get_as_data(addr, service=args.service)
        except AddressFormatError as e:
            if args.address:
                parser.error('[{}] {}'.format(addr, e))
            else:
                stream = sys.stderr
                out_str = e
        except LookupError as e:
            stream = sys.stderr
            out_str = e
        else:
            stream = sys.stdout
            if not args.raw:
                out_str = '{0} | {1} | {2}'.format(data.handle, data.cc, data.as_name)

        print('%-15s  %s' % (addr, out_str), file=stream)
        if args.pause:
            sleep(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass

