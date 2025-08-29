"""Tests for aslookup.lookup module."""

from unittest.mock import Mock, patch

import aiodns.error
import dns.resolver
import pytest

from aslookup.exceptions import (
    AddressFormatError,
    NoASDataError,
    NonroutableAddressError,
)
from aslookup.lookup import (
    ASData,
    format_ipv6_for_dns,
    get_as_data,
    get_as_data_async,
    get_cymru_data,
    get_ip_version,
    get_shadowserver_data,
    validate_ip,
)


class TestIPValidation:
    """Test IP address validation functions."""

    def test_get_ip_version_ipv4(self, sample_ipv4_address):
        """Test IP version detection for IPv4."""
        assert get_ip_version(sample_ipv4_address) == 4

    def test_get_ip_version_ipv6(self, sample_ipv6_address):
        """Test IP version detection for IPv6."""
        assert get_ip_version(sample_ipv6_address) == 6

    def test_get_ip_version_invalid(self, invalid_ip_addresses):
        """Test IP version detection for invalid addresses."""
        for invalid_ip in invalid_ip_addresses:
            with pytest.raises(AddressFormatError):
                get_ip_version(invalid_ip)

    def test_validate_ip_valid_ipv4(self, sample_ipv4_address):
        """Test validation of valid IPv4 address."""
        # Should not raise any exception
        validate_ip(sample_ipv4_address)

    def test_validate_ip_valid_ipv6(self, sample_ipv6_address):
        """Test validation of valid IPv6 address."""
        # Should not raise any exception
        validate_ip(sample_ipv6_address)

    def test_validate_ip_invalid(self, invalid_ip_addresses):
        """Test validation of invalid IP addresses."""
        for invalid_ip in invalid_ip_addresses:
            with pytest.raises(AddressFormatError):
                validate_ip(invalid_ip)

    def test_validate_ip_private_addresses(self, private_ip_addresses):
        """Test validation of private/non-routable addresses."""
        for private_ip in private_ip_addresses:
            with pytest.raises(NonroutableAddressError):
                validate_ip(private_ip)

    def test_validate_ip_edge_cases(self):
        """Test validation edge cases."""
        # Test with whitespace
        with pytest.raises(AddressFormatError):
            validate_ip("  ")

        # Test with None (should raise AttributeError which becomes
        # AddressFormatError)
        with pytest.raises((AddressFormatError, AttributeError)):
            validate_ip(None)


class TestIPv6Formatting:
    """Test IPv6 DNS formatting functions."""

    def test_format_ipv6_for_dns_simple(self):
        """Test IPv6 DNS formatting for simple address."""
        addr = "2001:db8::1"
        result = format_ipv6_for_dns(addr)
        expected = (
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
        )
        assert result == expected

    def test_format_ipv6_for_dns_full(self):
        """Test IPv6 DNS formatting for full address."""
        addr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        result = format_ipv6_for_dns(addr)
        expected = (
            "4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2"
        )
        assert result == expected

    def test_format_ipv6_for_dns_loopback(self):
        """Test IPv6 DNS formatting for loopback address."""
        addr = "::1"
        result = format_ipv6_for_dns(addr)
        expected = (
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0"
        )
        assert result == expected


class TestDataParsing:
    """Test AS data parsing functions."""

    def test_get_shadowserver_data_basic(self, sample_shadowserver_response):
        """Test parsing basic Shadowserver response."""
        extra = {"address": "8.8.8.8"}
        result = get_shadowserver_data(sample_shadowserver_response, extra)

        assert isinstance(result, ASData)
        assert result.address == "8.8.8.8"
        assert result.asn == "15133"
        assert result.handle == "AS15133"
        assert result.as_name == "Google LLC"
        assert result.prefix == "8.8.8.0/24"
        assert result.cc == "US"
        assert result.isp == "Google LLC"
        assert result.data_source == "shadowserver"

    def test_get_shadowserver_data_empty_as_name(self):
        """Test Shadowserver response with empty AS name."""
        response = '"12876 | 212.129.0.0/18 |  | FR | Online SAS"'
        extra = {"address": "212.129.50.243"}
        result = get_shadowserver_data(response, extra)

        assert result.as_name == "Online SAS"  # Should use ISP name
        assert result.isp == "Online SAS"

    def test_get_cymru_data_basic(self, sample_cymru_asn_response):
        """Test parsing basic Team Cymru response."""
        extra = {"address": "8.8.8.8", "ip_prefix": "8.8.8.0/24"}
        result = get_cymru_data(sample_cymru_asn_response, extra)
        
        assert isinstance(result, ASData)
        assert result.address == "8.8.8.8"
        assert result.asn == "15169"
        assert result.handle == "AS15169"
        assert result.as_name == "GOOGLE"
        assert result.prefix == "8.8.8.0/24"
        assert result.cc == "US"
        assert result.rir == "arin"
        assert result.reg_date == "2000-03-30"
        assert result.data_source == "cymru"

    def test_get_cymru_data_country_code_cleanup(self):
        """Test Team Cymru response with country code suffix removal."""
        response = '"15169 | US | arin | 2000-03-30 | GOOGLE, US, US"'
        extra = {"address": "8.8.8.8"}
        result = get_cymru_data(response, extra)

        assert result.as_name == "GOOGLE, US"  # Country code suffix removed

    def test_get_shadowserver_data_country_code_cleanup(self):
        """Test Shadowserver response with country code suffix removal."""
        response = '"15133 | 8.8.8.0/24 | GOOGLE | US | Google LLC, US"'
        extra = {"address": "8.8.8.8"}
        result = get_shadowserver_data(response, extra)

        assert result.as_name == "Google LLC"  # Country code suffix removed


class TestASDataLookup:
    """Test main AS data lookup functions."""

    @patch('dns.resolver.query')
    def test_get_as_data_shadowserver_success(self, mock_query,
                                              sample_ipv4_address):
        """Test successful Shadowserver lookup."""
        # Mock DNS response
        mock_answer = Mock()
        mock_answer.to_text.return_value = (
            '"15133 | 8.8.8.0/24 | GOOGLE | US | Google LLC"'
        )
        mock_query.return_value = [mock_answer]

        result = get_as_data(sample_ipv4_address, service="shadowserver")

        assert isinstance(result, ASData)
        assert result.address == sample_ipv4_address
        assert result.asn == "15133"
        assert result.data_source == "shadowserver"

        # Verify DNS query was made to correct domain
        mock_query.assert_called_once()
        call_args = mock_query.call_args[0]
        assert "origin.asn.shadowserver.org" in call_args[0]

    @patch('dns.resolver.query')
    def test_get_as_data_cymru_success(self, mock_query, sample_ipv4_address):
        """Test successful Team Cymru lookup."""
        # Mock DNS responses for both queries
        origin_answer = Mock()
        origin_answer.to_text.return_value = (
            '"15169 | 8.8.8.0/24 | US | arin | 2000-03-30"'
        )

        asn_answer = Mock()
        asn_answer.to_text.return_value = (
            '"15169 | US | arin | 2000-03-30 | GOOGLE, US"'
        )

        mock_query.side_effect = [[origin_answer], [asn_answer]]

        result = get_as_data(sample_ipv4_address, service="cymru")

        assert isinstance(result, ASData)
        assert result.address == sample_ipv4_address
        assert result.asn == "15169"
        assert result.data_source == "cymru"

        # Verify both DNS queries were made
        assert mock_query.call_count == 2

    @patch('dns.resolver.query')
    def test_get_as_data_ipv6_shadowserver(self, mock_query,
                                           sample_ipv6_address):
        """Test IPv6 lookup with Shadowserver."""
        mock_answer = Mock()
        mock_answer.to_text.return_value = (
            '"15169 | 2001:4860:4860::/48 | GOOGLE | US | Google LLC"'
        )
        mock_query.return_value = [mock_answer]

        result = get_as_data(sample_ipv6_address, service="shadowserver")

        assert isinstance(result, ASData)
        assert result.address == sample_ipv6_address

        # Verify IPv6 DNS query format
        call_args = mock_query.call_args[0]
        assert "origin6.asn.shadowserver.org" in call_args[0]

    @patch('dns.resolver.query')
    def test_get_as_data_nxdomain(self, mock_query, sample_ipv4_address):
        """Test handling of NXDOMAIN DNS response."""
        mock_query.side_effect = dns.resolver.NXDOMAIN()

        with pytest.raises(NoASDataError):
            get_as_data(sample_ipv4_address)

    @patch('dns.resolver.query')
    def test_get_as_data_shadowserver_no_asn(self, mock_query,
                                             sample_ipv4_address):
        """Test Shadowserver response with no ASN."""
        mock_answer = Mock()
        mock_answer.to_text.return_value = '" | | | | "'
        mock_query.return_value = [mock_answer]

        with pytest.raises(NoASDataError):
            get_as_data(sample_ipv4_address, service="shadowserver")

    def test_get_as_data_invalid_ip(self, invalid_ip_addresses):
        """Test lookup with invalid IP addresses."""
        for invalid_ip in invalid_ip_addresses:
            with pytest.raises(AddressFormatError):
                get_as_data(invalid_ip)

    def test_get_as_data_private_ip(self, private_ip_addresses):
        """Test lookup with private IP addresses."""
        for private_ip in private_ip_addresses:
            with pytest.raises((LookupError, NonroutableAddressError)):
                get_as_data(private_ip)

    def test_get_as_data_defanged_input(self):
        """Test lookup with defanged IP address."""
        defanged_ip = "8[.]8[.]8[.]8"

        with patch('dns.resolver.query') as mock_query:
            mock_answer = Mock()
            mock_answer.to_text.return_value = (
                '"15133 | 8.8.8.0/24 | GOOGLE | US | Google LLC"'
            )
            mock_query.return_value = [mock_answer]

            result = get_as_data(defanged_ip)
            assert result.address == "8.8.8.8"  # Should be refanged


class TestAsyncASDataLookup:
    """Test async AS data lookup functions."""

    @pytest.mark.asyncio
    @patch('aiodns.DNSResolver')
    async def test_get_as_data_async_shadowserver_success(
        self, mock_resolver_class, sample_ipv4_address
    ):
        """Test successful async Shadowserver lookup."""
        # Mock async DNS response
        mock_resolver = Mock()
        mock_answer = Mock()
        mock_answer.text = '"15133 | 8.8.8.0/24 | GOOGLE | US | Google LLC"'
        
        # Create an async mock
        async def mock_query_async(*args, **kwargs):
            return [mock_answer]
        
        mock_resolver.query = mock_query_async
        mock_resolver_class.return_value = mock_resolver

        result = await get_as_data_async(sample_ipv4_address,
                                         service="shadowserver")

        assert isinstance(result, ASData)
        assert result.address == sample_ipv4_address
        assert result.asn == "15133"
        assert result.data_source == "shadowserver"

    @pytest.mark.asyncio
    @patch('aiodns.DNSResolver')
    async def test_get_as_data_async_cymru_success(
        self, mock_resolver_class, sample_ipv4_address
    ):
        """Test successful async Team Cymru lookup."""
        # Mock async DNS responses
        mock_resolver = Mock()

        origin_answer = Mock()
        origin_answer.text = '"15169 | 8.8.8.0/24 | US | arin | 2000-03-30"'

        asn_answer = Mock()
        asn_answer.text = '"15169 | US | arin | 2000-03-30 | GOOGLE, US"'

        # Create async mocks with call tracking
        call_count = 0
        async def mock_query_async(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [origin_answer]
            else:
                return [asn_answer]

        mock_resolver.query = mock_query_async
        mock_resolver_class.return_value = mock_resolver

        result = await get_as_data_async(sample_ipv4_address, service="cymru")

        assert isinstance(result, ASData)
        assert result.address == sample_ipv4_address
        assert result.asn == "15169"
        assert result.data_source == "cymru"

    @pytest.mark.asyncio
    @patch('aiodns.DNSResolver')
    async def test_get_as_data_async_dns_error(
        self, mock_resolver_class, sample_ipv4_address
    ):
        """Test async lookup with DNS error."""
        mock_resolver = Mock()
        mock_resolver.query.side_effect = aiodns.error.DNSError()
        mock_resolver_class.return_value = mock_resolver

        with pytest.raises(NoASDataError):
            await get_as_data_async(sample_ipv4_address)

    @pytest.mark.asyncio
    async def test_get_as_data_async_invalid_ip(self, invalid_ip_addresses):
        """Test async lookup with invalid IP addresses."""
        for invalid_ip in invalid_ip_addresses:
            with pytest.raises(AddressFormatError):
                await get_as_data_async(invalid_ip)
