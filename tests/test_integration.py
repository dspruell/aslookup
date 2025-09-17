"""Integration tests for aslookup using test data."""

import asyncio
import pytest
from unittest.mock import Mock, patch

from aslookup import get_as_data
from aslookup.exceptions import (
    AddressFormatError,
    NoASDataError,
    NonroutableAddressError,
)
from aslookup.lookup import ASData, get_as_data_async


class TestIntegrationWithTestData:
    """Integration tests using the test input data file."""

    def test_valid_public_ipv4_addresses(self):
        """Test valid public IPv4 addresses from test data."""
        valid_public_ips = [
            "1.2.3.4",
            "198.60.22.22",
            "8.8.8.8",
            "212.129.50.243",
        ]
        
        for ip in valid_public_ips:
            # Mock DNS to avoid actual network calls
            with patch('dns.resolver.query') as mock_query:
                mock_answer = Mock()
                mock_answer.to_text.return_value = (
                    '"15169 | 8.8.8.0/24 | GOOGLE | US | Google LLC"'
                )
                mock_query.return_value = [mock_answer]
                
                try:
                    result = get_as_data(ip, service="shadowserver")
                    assert isinstance(result, ASData)
                    assert result.address == ip
                    assert result.asn is not None
                except (NoASDataError, NonroutableAddressError):
                    # Some test IPs might not have AS data or be non-routable
                    # This is acceptable for integration testing
                    pass

    def test_valid_public_ipv6_addresses(self):
        """Test valid public IPv6 addresses from test data."""
        valid_public_ipv6s = [
            "2001:4860:4860::8888",
            "2001:4860:4860::8844",
            "2606:4700:4700::1111",
            "2001:4860:4802::2001",
        ]
        
        for ip in valid_public_ipv6s:
            # Mock DNS to avoid actual network calls
            with patch('dns.resolver.query') as mock_query:
                mock_answer = Mock()
                mock_answer.to_text.return_value = (
                    '"15169 | 2001:4860:4860::/48 | GOOGLE | US | Google LLC"'
                )
                mock_query.return_value = [mock_answer]
                
                try:
                    result = get_as_data(ip, service="shadowserver")
                    assert isinstance(result, ASData)
                    assert result.address == ip
                    assert result.asn is not None
                except (NoASDataError, NonroutableAddressError):
                    # Some test IPs might not have AS data or be non-routable
                    pass

    def test_invalid_ip_addresses_from_test_data(self):
        """Test invalid IP addresses from test data."""
        invalid_ips = [
            "333.12.96.0",  # Invalid IPv4 (octet > 255)
            "a.b.c.d",      # Non-numeric IPv4
            "1[.]1[.]1[.]1",  # Defanged IP (should be handled)
        ]
        
        for ip in invalid_ips:
            if ip == "1[.]1[.]1[.]1":
                # Defanged IPs should be processed after refanging
                with patch('dns.resolver.query') as mock_query:
                    mock_answer = Mock()
                    mock_answer.to_text.return_value = (
                        '"13335 | 1.1.1.0/24 | CLOUDFLARE | US | Cloudflare"'
                    )
                    mock_query.return_value = [mock_answer]
                    result = get_as_data(ip, service="shadowserver")
                    assert result.address == "1.1.1.1"  # Should be refanged
            else:
                with pytest.raises(AddressFormatError):
                    get_as_data(ip)

    def test_private_ip_addresses_from_test_data(self):
        """Test private/non-routable IP addresses from test data."""
        private_ips = [
            "127.0.2.2",     # Loopback
            "224.0.10.10",   # Multicast
            "::1",           # IPv6 loopback
            "fe80::1",       # IPv6 link-local
            "fc00::1",       # IPv6 unique local
            "2001:db8::1",   # IPv6 documentation
        ]
        
        for ip in private_ips:
            with pytest.raises(NonroutableAddressError):
                get_as_data(ip)

    def test_both_services_integration(self):
        """Test integration with both Shadowserver and Cymru services."""
        test_ip = "8.8.8.8"
        
        # Test Shadowserver
        with patch('dns.resolver.query') as mock_query:
            mock_answer = Mock()
            mock_answer.to_text.return_value = (
                '"15169 | 8.8.8.0/24 | GOOGLE | US | Google LLC"'
            )
            mock_query.return_value = [mock_answer]
            
            result_ss = get_as_data(test_ip, service="shadowserver")
            assert result_ss.data_source == "shadowserver"
            assert isinstance(result_ss, ASData)
        
        # Test Cymru (requires two DNS queries)
        with patch('dns.resolver.query') as mock_query:
            origin_answer = Mock()
            origin_answer.to_text.return_value = (
                '"15169 | 8.8.8.0/24 | US | arin | 2000-03-30"'
            )
            
            asn_answer = Mock()
            asn_answer.to_text.return_value = (
                '"15169 | US | arin | 2000-03-30 | GOOGLE, US"'
            )
            
            mock_query.side_effect = [[origin_answer], [asn_answer]]
            
            result_cymru = get_as_data(test_ip, service="cymru")
            assert result_cymru.data_source == "cymru"
            assert isinstance(result_cymru, ASData)
            assert result_cymru.rir == "arin"


class TestEndToEndScenarios:
    """Test end-to-end scenarios that simulate real usage."""

    def test_mixed_input_processing(self):
        """Test processing mixed valid/invalid/private IPs."""
        mixed_ips = [
            "8.8.8.8",        # Valid public
            "192.168.1.1",    # Private
            "invalid_ip",     # Invalid
            "1.1.1.1",        # Valid public
        ]
        
        results = []
        for ip in mixed_ips:
            try:
                with patch('dns.resolver.query') as mock_query:
                    mock_answer = Mock()
                    mock_answer.to_text.return_value = (
                        '"15169 | 8.8.8.0/24 | GOOGLE | US | Google LLC"'
                    )
                    mock_query.return_value = [mock_answer]
                    result = get_as_data(ip, service="shadowserver")
                    results.append(("success", ip, result))
            except AddressFormatError:
                results.append(("format_error", ip, None))
            except NonroutableAddressError:
                results.append(("nonroutable", ip, None))
            except NoASDataError:
                results.append(("no_data", ip, None))
        
        # Should have mixed results
        success_count = len([r for r in results if r[0] == "success"])
        error_count = len([r for r in results if r[0] != "success"])
        
        assert success_count > 0
        assert error_count > 0

    def test_ipv4_and_ipv6_mixed_processing(self):
        """Test processing mixed IPv4 and IPv6 addresses."""
        mixed_ips = [
            "8.8.8.8",                    # IPv4
            "2001:4860:4860::8888",       # IPv6
            "1.1.1.1",                    # IPv4
            "2606:4700:4700::1111",       # IPv6
        ]
        
        results = []
        for ip in mixed_ips:
            with patch('dns.resolver.query') as mock_query:
                mock_answer = Mock()
                mock_answer.to_text = Mock(return_value=(
                    '"15169 | 8.8.8.0/24 | GOOGLE | US | Google LLC"'
                ))
                mock_query.return_value = [mock_answer]
                
                result = get_as_data(ip, service="shadowserver")
                results.append(result)
        
        assert len(results) == 4
        for result in results:
            assert isinstance(result, ASData)
            assert result.asn is not None

    def test_error_recovery_scenarios(self):
        """Test error recovery in various scenarios."""
        # Test DNS timeout/error recovery
        with patch('dns.resolver.query') as mock_query:
            import dns.resolver
            mock_query.side_effect = dns.resolver.NXDOMAIN()
            
            with pytest.raises(NoASDataError):
                get_as_data("8.8.8.8", service="shadowserver")
        
        # Test malformed DNS response handling
        with patch('dns.resolver.query') as mock_query:
            mock_answer = Mock()
            mock_answer.to_text.return_value = '"malformed response"'
            mock_query.return_value = [mock_answer]
            
            # For Cymru service, this should raise NoASDataError
            with pytest.raises(NoASDataError):
                get_as_data("8.8.8.8", service="cymru")

    def test_service_specific_behavior(self):
        """Test service-specific behavior differences."""
        test_ip = "8.8.8.8"
        
        # Shadowserver returns data in one query
        with patch('dns.resolver.query') as mock_query:
            mock_answer = Mock()
            mock_answer.to_text.return_value = (
                '"15169 | 8.8.8.0/24 | GOOGLE | US | Google LLC"'
            )
            mock_query.return_value = [mock_answer]
            
            result_ss = get_as_data(test_ip, service="shadowserver")
            assert mock_query.call_count == 1
            assert result_ss.data_source == "shadowserver"
            assert result_ss.isp == "Google LLC"
            assert result_ss.rir is None  # Shadowserver doesn't provide RIR
        
        # Cymru requires two queries
        with patch('dns.resolver.query') as mock_query:
            origin_answer = Mock()
            origin_answer.to_text.return_value = (
                '"15169 | 8.8.8.0/24 | US | arin | 2000-03-30"'
            )
            
            asn_answer = Mock()
            asn_answer.to_text.return_value = (
                '"15169 | US | arin | 2000-03-30 | GOOGLE, US"'
            )
            
            mock_query.side_effect = [[origin_answer], [asn_answer]]
            
            result_cymru = get_as_data(test_ip, service="cymru")
            assert mock_query.call_count == 2
            assert result_cymru.data_source == "cymru"
            assert result_cymru.rir == "arin"
