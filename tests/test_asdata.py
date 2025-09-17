"""Tests for ASData namedtuple structure."""

import pytest

from aslookup.lookup import ASData


class TestASDataCreation:
    """Test ASData namedtuple creation and basic functionality."""

    def test_asdata_creation_with_all_fields(self):
        """Test creating ASData with all fields populated."""
        data = ASData(
            address="8.8.8.8",
            handle="AS15169",
            asn="15169",
            as_name="GOOGLE",
            rir="arin",
            reg_date="2000-03-30",
            prefix="8.8.8.0/24",
            cc="US",
            domain="google.com",
            isp="Google LLC",
            data_source="cymru",
        )

        assert data.address == "8.8.8.8"
        assert data.handle == "AS15169"
        assert data.asn == "15169"
        assert data.as_name == "GOOGLE"
        assert data.rir == "arin"
        assert data.reg_date == "2000-03-30"
        assert data.prefix == "8.8.8.0/24"
        assert data.cc == "US"
        assert data.domain == "google.com"
        assert data.isp == "Google LLC"
        assert data.data_source == "cymru"

    def test_asdata_creation_with_none_values(self):
        """Test creating ASData with None values for optional fields."""
        data = ASData(
            address="8.8.8.8",
            handle="AS15169",
            asn="15169",
            as_name="GOOGLE",
            rir=None,
            reg_date=None,
            prefix="8.8.8.0/24",
            cc="US",
            domain=None,
            isp=None,
            data_source="shadowserver",
        )

        assert data.address == "8.8.8.8"
        assert data.rir is None
        assert data.reg_date is None
        assert data.domain is None
        assert data.isp is None

    def test_asdata_immutability(self):
        """Test that ASData is immutable (namedtuple property)."""
        data = ASData(
            address="8.8.8.8",
            handle="AS15169",
            asn="15169",
            as_name="GOOGLE",
            rir="arin",
            reg_date="2000-03-30",
            prefix="8.8.8.0/24",
            cc="US",
            domain="google.com",
            isp="Google LLC",
            data_source="cymru",
        )

        # Should not be able to modify fields
        with pytest.raises(AttributeError):
            data.address = "1.1.1.1"

        with pytest.raises(AttributeError):
            data.asn = "12345"

    def test_asdata_field_access(self):
        """Test accessing ASData fields by name."""
        data = ASData(
            address="192.0.2.1",
            handle="AS64496",
            asn="64496",
            as_name="TEST-AS",
            rir="ripe",
            reg_date="2020-01-01",
            prefix="192.0.2.0/24",
            cc="NL",
            domain="example.org",
            isp="Test ISP",
            data_source="cymru",
        )

        # Test all field access
        assert hasattr(data, 'address')
        assert hasattr(data, 'handle')
        assert hasattr(data, 'asn')
        assert hasattr(data, 'as_name')
        assert hasattr(data, 'rir')
        assert hasattr(data, 'reg_date')
        assert hasattr(data, 'prefix')
        assert hasattr(data, 'cc')
        assert hasattr(data, 'domain')
        assert hasattr(data, 'isp')
        assert hasattr(data, 'data_source')


class TestASDataMethods:
    """Test ASData methods and functionality."""

    def test_as_text_method_basic(self, sample_asdata_shadowserver):
        """Test as_text method with basic data."""
        result = sample_asdata_shadowserver.as_text()
        expected = "8.8.8.8          AS15133 | US | Google LLC"
        assert result == expected

    def test_as_text_method_formatting(self):
        """Test as_text method formatting with different data."""
        data = ASData(
            address="2001:db8::1",
            handle="AS64512",
            asn="64512",
            as_name="EXAMPLE-AS",
            rir="arin",
            reg_date="2021-06-15",
            prefix="2001:db8::/32",
            cc="CA",
            domain="example.ca",
            isp="Example ISP",
            data_source="cymru",
        )

        result = data.as_text()
        expected = "2001:db8::1      AS64512 | CA | EXAMPLE-AS"
        assert result == expected

    def test_as_text_method_with_long_address(self):
        """Test as_text method with long IPv6 address."""
        data = ASData(
            address="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            handle="AS65001",
            asn="65001",
            as_name="LONG-ADDRESS-TEST",
            rir="ripe",
            reg_date="2019-12-31",
            prefix="2001:db8:85a3::/48",
            cc="DE",
            domain=None,
            isp=None,
            data_source="shadowserver",
        )

        result = data.as_text()
        # Should handle long addresses gracefully
        assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" in result
        assert "AS65001" in result
        assert "DE" in result
        assert "LONG-ADDRESS-TEST" in result

    def test_as_text_method_with_none_values(self):
        """Test as_text method when some fields are None."""
        data = ASData(
            address="10.0.0.1",
            handle="AS65000",
            asn="65000",
            as_name="PRIVATE-AS",
            rir=None,
            reg_date=None,
            prefix=None,
            cc="XX",
            domain=None,
            isp=None,
            data_source="test",
        )

        result = data.as_text()
        # Should handle None values without crashing
        assert "10.0.0.1" in result
        assert "AS65000" in result
        assert "XX" in result
        assert "PRIVATE-AS" in result


class TestASDataComparison:
    """Test ASData comparison and equality."""

    def test_asdata_equality(self):
        """Test ASData equality comparison."""
        data1 = ASData(
            address="8.8.8.8",
            handle="AS15169",
            asn="15169",
            as_name="GOOGLE",
            rir="arin",
            reg_date="2000-03-30",
            prefix="8.8.8.0/24",
            cc="US",
            domain="google.com",
            isp="Google LLC",
            data_source="cymru",
        )

        data2 = ASData(
            address="8.8.8.8",
            handle="AS15169",
            asn="15169",
            as_name="GOOGLE",
            rir="arin",
            reg_date="2000-03-30",
            prefix="8.8.8.0/24",
            cc="US",
            domain="google.com",
            isp="Google LLC",
            data_source="cymru",
        )

        assert data1 == data2

    def test_asdata_inequality(self):
        """Test ASData inequality comparison."""
        data1 = ASData(
            address="8.8.8.8",
            handle="AS15169",
            asn="15169",
            as_name="GOOGLE",
            rir="arin",
            reg_date="2000-03-30",
            prefix="8.8.8.0/24",
            cc="US",
            domain="google.com",
            isp="Google LLC",
            data_source="cymru",
        )

        data2 = ASData(
            address="1.1.1.1",  # Different address
            handle="AS13335",
            asn="13335",
            as_name="CLOUDFLARE",
            rir="arin",
            reg_date="2010-07-14",
            prefix="1.1.1.0/24",
            cc="US",
            domain="cloudflare.com",
            isp="Cloudflare Inc",
            data_source="shadowserver",
        )

        assert data1 != data2

    def test_asdata_hash(self):
        """Test ASData can be hashed (for use in sets/dicts)."""
        data = ASData(
            address="8.8.8.8",
            handle="AS15169",
            asn="15169",
            as_name="GOOGLE",
            rir="arin",
            reg_date="2000-03-30",
            prefix="8.8.8.0/24",
            cc="US",
            domain="google.com",
            isp="Google LLC",
            data_source="cymru",
        )

        # Should be able to hash the object
        hash_value = hash(data)
        assert isinstance(hash_value, int)

        # Should be able to use in set
        data_set = {data}
        assert len(data_set) == 1
        assert data in data_set

        # Should be able to use as dict key
        data_dict = {data: "test_value"}
        assert data_dict[data] == "test_value"


class TestASDataRepresentation:
    """Test ASData string representation and debugging."""

    def test_asdata_str_representation(self, sample_asdata_cymru):
        """Test string representation of ASData."""
        str_repr = str(sample_asdata_cymru)
        # Should contain the class name and field values
        assert "ASData" in str_repr
        assert "8.8.8.8" in str_repr
        assert "AS15169" in str_repr

    def test_asdata_repr_representation(self, sample_asdata_shadowserver):
        """Test repr representation of ASData."""
        repr_str = repr(sample_asdata_shadowserver)
        # Should be a valid Python expression that could recreate the object
        assert "ASData" in repr_str
        assert "address=" in repr_str
        assert "handle=" in repr_str
        assert "data_source=" in repr_str

    def test_asdata_field_iteration(self):
        """Test iterating over ASData fields."""
        data = ASData(
            address="203.0.113.1",
            handle="AS64497",
            asn="64497",
            as_name="DOC-AS",
            rir="arin",
            reg_date="2022-01-01",
            prefix="203.0.113.0/24",
            cc="US",
            domain="documentation.example",
            isp="Documentation ISP",
            data_source="test",
        )

        # Should be able to iterate over fields
        fields = list(data)
        assert len(fields) == 11  # Number of fields in ASData
        assert fields[0] == "203.0.113.1"  # address
        assert fields[1] == "AS64497"      # handle
        assert fields[2] == "64497"        # asn

    def test_asdata_field_names(self):
        """Test accessing field names."""
        data = ASData(
            address="198.51.100.1",
            handle="AS64498",
            asn="64498",
            as_name="TEST2-AS",
            rir="ripe",
            reg_date="2023-01-01",
            prefix="198.51.100.0/24",
            cc="GB",
            domain="test2.example",
            isp="Test2 ISP",
            data_source="cymru",
        )

        # Should have _fields attribute with field names
        expected_fields = (
            'address', 'handle', 'asn', 'as_name', 'rir', 'reg_date',
            'prefix', 'cc', 'domain', 'isp', 'data_source'
        )
        assert data._fields == expected_fields
