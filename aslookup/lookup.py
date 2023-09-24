"""Lookup routines."""

import logging
import re
from collections import namedtuple
from ipaddress import IPv4Address

import dns.resolver
import dns.reversename
import pytricia
from defang import refang

from .exceptions import (
    AddressFormatError,
    NoASDataError,
    NonroutableAddressError,
)

logger = logging.getLogger(__name__)

AS_SERVICES = {
    "shadowserver": {
        "origin_suffix": "origin.asn.shadowserver.org",
    },
    "cymru": {
        "origin_suffix": "origin.asn.cymru.com",
        "as_description_suffix": "asn.cymru.com",
    },
}

# IPs with these prefixes aren't routable on Internet and need not be sent
# to lookup service. Ref. RFC 5735.
IP_NOLOOKUP_NETS = {
    "0.0.0.0/8": "RFC 1122 IPv4 any",
    "127.0.0.0/8": "RFC 1122 loopback",
    "10.0.0.0/8": "RFC 1918 range",
    "100.64.0.0/10": "RFC 6598 shared transition space",
    "169.254.0.0/16": "RFC 3927 link local range",
    "172.16.0.0/12": "RFC 1918 range",
    "192.0.0.0/24": "RFC 5736 protocol assignment range",
    "192.0.2.0/24": "RFC 5737 TEST-NET-1 range",
    "192.88.99.0/24": "RFC 3068 6to4 relay anycast range",
    "192.168.0.0/16": "RFC 1918 range",
    "198.18.0.0/15": "RFC 2544 network device benchmark range",
    "198.51.100.0/24": "RFC 5737 TEST-NET-2 range",
    "203.0.113.0/24": "RFC 5737 TEST-NET-3 range",
    "224.0.0.0/4": "RFC 5771 multicast range",
    "240.0.0.0/4": "RFC 1112 IANA future use reserved range",
    "255.0.0.0/8": "RFC 1112 IPv4 limited broadcast",
}

# Build the patricia tree
pyt = pytricia.PyTricia()
for net, descr in IP_NOLOOKUP_NETS.items():
    pyt[net] = descr
logger.debug("created exception network tree with %d networks", len(pyt))

IPV4_FMT = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
PREFIX_FMT = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")

# Structured record tuple
ASData = namedtuple(
    "ASData",
    [
        "handle",
        "asn",
        "as_name",
        "rir",
        "reg_date",
        "prefix",
        "cc",
        "domain",
        "isp",
        "data_source",
    ],
)


def validate_ipv4(addr):
    """
    Validate IP addresses.

    - Validate that input is a valid IPv4 address
    - Flag various reserved and non-routable addresses

    """
    # Check that it's a valid IPv4 address
    # if not re.match(IPV4_FMT, addr):
    #    raise AddressFormatError("Invalid format for IPv4 address")
    # for octet in addr.split("."):
    #    if not 0 <= int(octet) <= 255:
    #        raise AddressFormatError("Invalid octet value for IPv4 address")
    # Distinguish address family by IPv4 vs. IPv6 separator
    if "." not in addr:
        raise AddressFormatError("Invalid format for IPv4 address")

    try:
        IPv4Address(addr)
    except ValueError as e:
        raise AddressFormatError(f"Invalid IPv4 address: {e}")

    # Verify address not in reserved/non-routable prefixes.
    if addr in pyt:
        raise NonroutableAddressError(pyt.get(addr))
    return


def get_cymru_data(s, extra={}):
    """
    Parse Team Cymru AS data query and return structured record tuple.

    `extra` is a dict of additional fields that can be passed in, typically
    consisting of data from the origin DNS query.

    DNS answer format received, first query (2020-09-11):
        "15133 | 93.184.216.0/24 | EU | ripencc | 2008-06-02"
    DNS answer format received, second query (handled here) (2020-09-11):
        "15133 | US | arin | 2007-03-19 | EDGECAST, US"

    """
    s = s.strip('"')
    # Cymru results began to append a comma and country code to the end of the
    # AS name, polluting the data. Strip it off.
    s = re.sub(r", [A-Z]{2}$", "", s)
    fields = s.split("|")
    fields = [x.strip() for x in fields]
    as_data = ASData(
        asn=fields[0],
        handle=f"AS{fields[0]}",
        as_name=fields[4],
        prefix=extra.get("ip_prefix"),
        domain=None,
        cc=fields[1],
        rir=fields[2],
        reg_date=fields[3],
        isp=None,
        data_source="cymru",
    )
    return as_data


def get_shadowserver_data(s):
    """
    Parse Shadowserver AS data query and return structured record tuple.

    DNS answer format received (2020-09-11):
        "15133 | 93.184.216.0/24 | EDGECAST | US | EDGECAST"
    DNS answer format received (2021-03-20):
        "12876 | 212.129.0.0/18 |  | FR | Online SAS"

    """
    s = s.strip('"')
    # Shadowserver results at one point appended a comma and country code to
    # the end of the AS name, polluting the data. Strip it off.
    s = re.sub(r", [A-Z]{2}$", "", s)
    fields = s.split("|")
    fields = [x.strip() for x in fields]
    # For any response that returned AS data but no AS name, alert user.
    if fields[0] and not fields[2]:
        logger.warning("no value for AS name; overriding with ISP")

    as_data = ASData(
        asn=fields[0],
        handle=f"AS{fields[0]}",
        # If the AS Name field is blank, toss the ISP in and mark it as
        # an ISP override.
        as_name=fields[4] or fields[2],
        prefix=fields[1],
        domain=None,
        cc=fields[3],
        rir=None,
        reg_date=None,
        isp=fields[4],
        data_source="shadowserver",
    )
    return as_data


def get_as_data(addr, service="shadowserver"):
    """
    Query and return AS information for supplied IP address.

    Each IP-ASN service operates differently and returns slightly different
    fields in their responses.

    Return string containing formatted AS information for a given IP address,
    unless the address falls into these categories: it is not a valid IPv4
    address, there is no current AS data for that address, (i.e. not part of an
    announced prefix), or it is known to be a non-routable or reserved IP
    address. In these cases, an appropriate exception is raised.

    """
    # Remove leading or trailing whitespace and/or defanging of input
    addr = addr.strip()
    addr = refang(addr)

    try:
        validate_ipv4(addr)
    except AddressFormatError:
        raise
    except LookupError as e:
        raise LookupError("Ignoring: %s" % e)

    # Format IP to reversed-octet structure and issue origin lookup.
    rev_addr = ".".join(reversed(addr.split(".")))
    origin_addr = ".".join(
        [rev_addr, AS_SERVICES[service]["origin_suffix"]]
    )
    try:
        answers = dns.resolver.query(origin_addr, "TXT")
    except dns.resolver.NXDOMAIN:
        raise NoASDataError("No routing origin data for address")

    if answers:
        for a in answers:
            logger.debug("raw DNS record response: %s", a)
        if service == "shadowserver":
            # Shadowserver origin lookup response includes AS name information
            asdata_text = answers[0].to_text()
            asdata = get_shadowserver_data(asdata_text)
            # Shadowserver will still output information in cases that no ASN
            # is identified, so raise exception when this occurs
            if not asdata.asn:
                raise NoASDataError("No routing origin data for address")
        else:
            extra_data = {}

            # Team Cymru origin lookup response returns only ASN and requires
            # second lookup to return AS name information
            origin_data = answers[0].to_text().strip('"')
            m1 = re.match(r"^\d+", origin_data)
            if m1 is None:
                msg = (
                    f"Error in lookup from service {service} for IP {addr} "
                    f"(origin_data response: {origin_data})"
                )
                raise NoASDataError(msg)

            # Capture prefix from the origin data response
            m2 = PREFIX_FMT.search(origin_data)
            if m2 is not None:
                extra_data.update(ip_prefix=m2.group(0))

            # Run second query for AS name/description info
            _sfx = AS_SERVICES[service]["as_description_suffix"]
            as_data_addr = f"AS{m1.group(0)}.{_sfx}"
            try:
                answers = dns.resolver.query(as_data_addr, "TXT")
            except dns.resolver.NXDOMAIN:
                raise NoASDataError("No routing origin data for address")
            if answers:
                for a in answers:
                    logger.debug("raw DNS record response: %s", a)
                asdata_text = answers[0].to_text()
                asdata = get_cymru_data(asdata_text, extra=extra_data)
        return asdata
