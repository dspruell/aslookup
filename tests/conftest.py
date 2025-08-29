"""Shared test fixtures and configuration."""

import pytest
from unittest.mock import Mock, MagicMock
from aslookup.lookup import ASData


@pytest.fixture
def sample_ipv4_address():
    """Sample IPv4 address for testing."""
    return "8.8.8.8"


@pytest.fixture
def sample_ipv6_address():
    """Sample IPv6 address for testing."""
    return "2001:4860:4860::8888"


@pytest.fixture
def invalid_ip_addresses():
    """List of invalid IP addresses for testing."""
    return [
        "256.256.256.256",  # Invalid IPv4
        "192.168.1",        # Incomplete IPv4
        "a.b.c.d",          # Non-numeric IPv4
        "gggg::1",          # Invalid IPv6
        "not_an_ip",        # Not an IP at all
        "",                 # Empty string
        "   ",              # Whitespace only
    ]


@pytest.fixture
def private_ip_addresses():
    """List of private/non-routable IP addresses."""
    return [
        "192.168.1.1",      # RFC 1918
        "10.0.0.1",         # RFC 1918
        "172.16.0.1",       # RFC 1918
        "127.0.0.1",        # Loopback
        "169.254.1.1",      # Link local
        "224.0.0.1",        # Multicast
        "::1",              # IPv6 loopback
        "fe80::1",          # IPv6 link local
        "fc00::1",          # IPv6 unique local
        "2001:db8::1",      # IPv6 documentation
    ]


@pytest.fixture
def sample_shadowserver_response():
    """Sample Shadowserver DNS TXT response."""
    return '"15133 | 8.8.8.0/24 | GOOGLE | US | Google LLC"'


@pytest.fixture
def sample_cymru_origin_response():
    """Sample Team Cymru origin DNS TXT response."""
    return '"15169 | 8.8.8.0/24 | US | arin | 2000-03-30"'


@pytest.fixture
def sample_cymru_asn_response():
    """Sample Team Cymru ASN description DNS TXT response."""
    return '"15169 | US | arin | 2000-03-30 | GOOGLE, US"'


@pytest.fixture
def sample_asdata_shadowserver():
    """Sample ASData object from Shadowserver."""
    return ASData(
        address="8.8.8.8",
        handle="AS15133",
        asn="15133",
        as_name="Google LLC",
        rir=None,
        reg_date=None,
        prefix="8.8.8.0/24",
        cc="US",
        domain=None,
        isp="Google LLC",
        data_source="shadowserver",
    )


@pytest.fixture
def sample_asdata_cymru():
    """Sample ASData object from Team Cymru."""
    return ASData(
        address="8.8.8.8",
        handle="AS15169",
        asn="15169",
        as_name="GOOGLE, US",
        rir="arin",
        reg_date="2000-03-30",
        prefix="8.8.8.0/24",
        cc="US",
        domain=None,
        isp=None,
        data_source="cymru",
    )


@pytest.fixture
def mock_dns_resolver():
    """Mock DNS resolver for testing."""
    mock_resolver = Mock()
    mock_answer = Mock()
    mock_answer.to_text.return_value = '"15133 | 8.8.8.0/24 | GOOGLE | US | Google LLC"'
    mock_resolver.query.return_value = [mock_answer]
    return mock_resolver


@pytest.fixture
def mock_async_dns_resolver():
    """Mock async DNS resolver for testing."""
    mock_resolver = Mock()
    mock_answer = Mock()
    mock_answer.text = '"15133 | 8.8.8.0/24 | GOOGLE | US | Google LLC"'
    mock_resolver.query.return_value = [mock_answer]
    return mock_resolver
