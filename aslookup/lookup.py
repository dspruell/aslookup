"""Lookup routines."""

import logging
import re
from collections import namedtuple
from ipaddress import IPv4Address, IPv6Address, ip_address

import aiodns
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
        "origin_v4_suffix": "origin.asn.shadowserver.org",
        "origin_v6_suffix": "origin6.asn.shadowserver.org",
    },
    "cymru": {
        "origin_v4_suffix": "origin.asn.cymru.com",
        "origin_v6_suffix": "origin6.asn.cymru.com",
        "as_description_suffix": "asn.cymru.com",
    },
}

# IPs with these prefixes aren't routable on Internet and need not be sent
# to lookup service. Ref. RFC 5735 and RFC 5156.
IP_NOLOOKUP_NETS_V4 = {
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
IP_NOLOOKUP_NETS_V6 = {
    "::/128": "RFC 4291 IPv6 unspecified address",
    "::1/128": "RFC 4291 IPv6 loopback address",
    "::ffff:0:0/96": "RFC 4291 IPv4-mapped IPv6 addresses",
    "fe80::/10": "RFC 4291 IPv6 link-local unicast",
    "fc00::/7": "RFC 4193 IPv6 unique local unicast",
    "ff00::/8": "RFC 4291 IPv6 multicast",
    "2001:db8::/32": "RFC 3849 IPv6 documentation range",
    "2001:10::/28": "RFC 4843 IPv6 ORCHID range",
    "2001:20::/28": "RFC 7343 IPv6 ORCHIDv2 range",
    "2002::/16": "RFC 3056 6to4 addressing",
}

# Build the patricia trees
pyt_v4 = pytricia.PyTricia(24)
for net, descr in IP_NOLOOKUP_NETS_V4.items():
    pyt_v4[net] = descr
pyt_v6 = pytricia.PyTricia(128)
for net, descr in IP_NOLOOKUP_NETS_V6.items():
    pyt_v6[net] = descr

IPV4_PREFIX_FMT = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
IPV6_PREFIX_FMT = re.compile(
    r"([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/\d{1,3}\b"
)


class ASData(
    namedtuple(
        "ASData",
        [
            "address",  # Queried IP address
            "handle",  # Complete AS handle (ASXXXXX)
            "asn",  # AS number
            "as_name",  # AS name
            "rir",  # ASN registration RIR
            "reg_date",  # ASN registration date
            "prefix",  # Announced prefix
            "cc",  # Registered country ISO code
            "domain",  # AS or ISP domain
            "isp",  # ISP name
            "data_source",  # Provider servicing the query
        ],
    )
):
    """Structured record tuple.

    This tuple holds the information pertaining to an ASN data lookup.

    The `as_text()` method may be used to access a formatted simple text
    representation of the result.

    """

    __slots__ = ()

    def as_text(self):
        """Return formatted textual output."""
        return (
            f"{self.address:<15}  {self.handle} | {self.cc} | {self.as_name}"
        )


def get_ip_version(addr):
    """
    Determine IP version of address.

    Returns:
        int: 4 for IPv4, 6 for IPv6

    Raises:
        AddressFormatError: If address is not valid IPv4 or IPv6
    """
    try:
        ip_obj = ip_address(addr)
        return ip_obj.version
    except ValueError as e:
        raise AddressFormatError(f"Invalid IP address: {e}")


def validate_ip(addr):
    """
    Validate IP addresses.

    - Append a default network mask for IPv6 addresses
    - Validate that input is a valid IPv4 or IPv6 address
    - Flag various reserved and non-routable addresses

    """
    # Raises AddressFormatError if invalid
    ip_version = get_ip_version(addr)
    logger.debug("address %s protocol version: %d", addr, ip_version)

    try:
        if ip_version == 4:
            IPv4Address(addr)
            # Verify address not in reserved/non-routable prefixes.
            if addr in pyt_v4:
                raise NonroutableAddressError(pyt_v4.get(addr))
        elif ip_version == 6:
            IPv6Address(addr)
            if "/" not in addr:
                addr = addr + "/128"
            # Verify address not in reserved/non-routable prefixes.
            if addr in pyt_v6:
                raise NonroutableAddressError(pyt_v6.get(addr))
        else:
            raise AddressFormatError(
                f"unrecognized IP address version: {ip_version}"
            )
    except ValueError as e:
        raise AddressFormatError(f"Invalid IP address: {e}")

    return


# Keep backward compatibility alias
def validate_ipv4(addr):
    """Legacy function name for backward compatibility."""
    return validate_ip(addr)


def format_ipv6_for_dns(addr):
    """
    Format IPv6 address for reverse DNS lookup.

    Convert IPv6 address to nibble format for DNS queries.
    Example: 2001:db8::1
             -> 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2
    """
    ipv6_obj = IPv6Address(addr)
    # Get the full expanded form (no :: compression)
    expanded = ipv6_obj.exploded
    # Remove colons and convert to lowercase
    hex_string = expanded.replace(":", "").lower()
    # Reverse the string and insert dots between each character
    reversed_nibbles = ".".join(reversed(hex_string))
    return reversed_nibbles


def get_cymru_data(s, extra={}):
    """
    Parse Team Cymru AS data query and return structured record tuple.

    `extra` is a dict of additional fields that can be passed in, typically
    consisting of data from the origin DNS query.

    DNS answer format received, first query 2020-09-11:
        "15133 | 93.184.216.0/24 | EU | ripencc | 2008-06-02"
    DNS answer format received, second query, handled here, 2020-09-11:
        "15133 | US | arin | 2007-03-19 | EDGECAST, US"

    """
    s = s.strip('"')
    # Cymru results began to append a comma and country code to the end of the
    # AS name, polluting the data. Strip it off.
    s = re.sub(r", [A-Z]{2}$", "", s)
    fields = s.split("|")
    fields = [x.strip() for x in fields]
    as_data = ASData(
        address=extra["address"],
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


def get_shadowserver_data(s, extra={}):
    """
    Parse Shadowserver AS data query and return structured record tuple.

    DNS answer format received 2020-09-11:
        "15133 | 93.184.216.0/24 | EDGECAST | US | EDGECAST"
    DNS answer format received 2021-03-20:
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
        address=extra["address"],
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
    unless the address falls into these categories: it is not a valid IP
    address, there is no current AS data for that address, (i.e. not part of an
    announced prefix), or it is known to be a non-routable or reserved IP
    address. In these cases, an appropriate exception is raised.

    """
    # Remove leading or trailing whitespace and/or defanging of input
    addr = addr.strip()
    addr = refang(addr)

    try:
        validate_ip(addr)
    except AddressFormatError:
        raise
    except LookupError as e:
        raise LookupError("Ignoring: %s" % e)

    # Determine IP version and format accordingly
    ip_version = get_ip_version(addr)

    if ip_version == 4:
        # IPv4: Format IP to reversed-octet structure
        rev_addr = ".".join(reversed(addr.split(".")))
        origin_addr = ".".join(
            [rev_addr, AS_SERVICES[service]["origin_v4_suffix"]]
        )
    else:
        # IPv6: Format IP to reversed nibble structure
        rev_addr = format_ipv6_for_dns(addr)
        origin_addr = ".".join(
            [rev_addr, AS_SERVICES[service]["origin_v6_suffix"]]
        )

    try:
        logger.debug("issuing DNS query for %s", origin_addr)
        answers = dns.resolver.query(origin_addr, "TXT")
    except dns.resolver.NXDOMAIN:
        raise NoASDataError("No routing origin data for address")

    # Pass the query address in to either service handler
    extra_data = {"address": addr}

    if answers:
        for a in answers:
            logger.debug("raw DNS record response: %s", a)
        if service == "shadowserver":
            # Shadowserver origin lookup response includes AS name information
            asdata_text = answers[0].to_text()
            asdata = get_shadowserver_data(asdata_text, extra=extra_data)
            # Shadowserver will still output information in cases that no ASN
            # is identified, so raise exception when this occurs
            if not asdata.asn:
                raise NoASDataError("No routing origin data for address")
        else:
            # Team Cymru origin lookup response returns only the originating
            # ASN (but no as-name or org identity), so requires a second lookup
            # to return descriptive information.
            logger.debug("raw DNS record response: %s", answers[0].to_text())
            origin_data = answers[0].to_text().strip('"')
            m1 = re.match(r"^\d+", origin_data)
            if m1 is None:
                msg = (
                    f"Error in lookup from service {service} for IP {addr} "
                    f"(origin_data response: {origin_data})"
                )
                raise NoASDataError(msg)

            # Capture prefix from the origin data response
            m2 = (
                IPV4_PREFIX_FMT.search(origin_data)
                if ip_version == 4
                else None
            )
            m2 = (
                IPV6_PREFIX_FMT.search(origin_data)
                if ip_version == 6
                else None
            )
            if m2 is not None:
                extra_data.update(ip_prefix=m2.group(0))

            # Run second query for AS name/description info
            _sfx = AS_SERVICES[service]["as_description_suffix"]
            as_data_addr = f"AS{m1.group(0)}.{_sfx}"
            try:
                logger.debug("issuing DNS query for %s", origin_addr)
                answers = dns.resolver.query(as_data_addr, "TXT")
            except dns.resolver.NXDOMAIN:
                raise NoASDataError("No routing origin data for address")
            if answers:
                for a in answers:
                    logger.debug("raw DNS record response: %s", a)
                asdata_text = answers[0].to_text()
                asdata = get_cymru_data(asdata_text, extra=extra_data)
        return asdata


async def get_as_data_async(addr, service="shadowserver"):
    """
    Async version of get_as_data().

    Query and return AS information for supplied IP address using async DNS.
    """
    # Remove leading or trailing whitespace and/or defanging of input
    addr = addr.strip()
    addr = refang(addr)

    try:
        validate_ip(addr)
    except AddressFormatError:
        raise
    except LookupError as e:
        raise LookupError("Ignoring: %s" % e)

    # Determine IP version and format accordingly
    ip_version = get_ip_version(addr)

    if ip_version == 4:
        # IPv4: Format IP to reversed-octet structure
        rev_addr = ".".join(reversed(addr.split(".")))
        origin_addr = ".".join(
            [rev_addr, AS_SERVICES[service]["origin_v4_suffix"]]
        )
    else:
        # IPv6: Format IP to reversed nibble structure
        rev_addr = format_ipv6_for_dns(addr)
        origin_addr = ".".join(
            [rev_addr, AS_SERVICES[service]["origin_v6_suffix"]]
        )

    # Create async DNS resolver
    resolver = aiodns.DNSResolver()

    try:
        # Perform async DNS query
        logger.debug("issuing DNS query for %s", origin_addr)
        answers = await resolver.query(origin_addr, "TXT")
    except aiodns.error.DNSError:
        raise NoASDataError("No routing origin data for address")

    # Pass the query address in to either service handler
    extra_data = {"address": addr}

    if answers:
        for a in answers:
            logger.debug("raw DNS record response: %s", a)
        if service == "shadowserver":
            # Shadowserver origin lookup response includes AS name information
            asdata_text = answers[0].text
            asdata = get_shadowserver_data(asdata_text, extra=extra_data)
            # Shadowserver will still output information in cases that no ASN
            # is identified, so raise exception when this occurs
            if not asdata.asn:
                raise NoASDataError("No routing origin data for address")
        else:
            # Team Cymru origin lookup response returns only the originating
            # ASN (but no as-name or org identity), so requires a second lookup
            # to return descriptive information.
            logger.debug("raw DNS record response: %s", answers[0].text)
            origin_data = answers[0].text.strip('"')
            m1 = re.match(r"^\d+", origin_data)
            if m1 is None:
                msg = (
                    f"Error in lookup from service {service} for IP {addr} "
                    f"(origin_data response: {origin_data})"
                )
                raise NoASDataError(msg)

            # Capture prefix from the origin data response
            m2 = (
                IPV4_PREFIX_FMT.search(origin_data)
                if ip_version == 4
                else None
            )
            m2 = (
                IPV6_PREFIX_FMT.search(origin_data)
                if ip_version == 6
                else None
            )
            if m2 is not None:
                extra_data.update(ip_prefix=m2.group(0))

            # Run second query for AS name/description info
            _sfx = AS_SERVICES[service]["as_description_suffix"]
            as_data_addr = f"AS{m1.group(0)}.{_sfx}"
            try:
                logger.debug("issuing DNS query for %s", origin_addr)
                answers = await resolver.query(as_data_addr, "TXT")
            except aiodns.error.DNSError:
                raise NoASDataError("No routing origin data for address")
            if answers:
                for a in answers:
                    logger.debug("raw DNS record response: %s", a)
                asdata_text = answers[0].text
                asdata = get_cymru_data(asdata_text, extra=extra_data)
        return asdata
