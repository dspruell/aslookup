"""Tests for aslookup.exceptions module."""

import pytest

from aslookup.exceptions import (
    AddressFormatError,
    LookupError,
    NoASDataError,
    NonroutableAddressError,
)


class TestExceptionHierarchy:
    """Test exception class hierarchy and inheritance."""

    def test_lookup_error_is_base_exception(self):
        """Test that LookupError is the base exception class."""
        assert issubclass(LookupError, Exception)

    def test_no_as_data_error_inheritance(self):
        """Test NoASDataError inherits from LookupError."""
        assert issubclass(NoASDataError, LookupError)
        assert issubclass(NoASDataError, Exception)

    def test_nonroutable_address_error_inheritance(self):
        """Test NonroutableAddressError inherits from LookupError."""
        assert issubclass(NonroutableAddressError, LookupError)
        assert issubclass(NonroutableAddressError, Exception)

    def test_address_format_error_inheritance(self):
        """Test AddressFormatError inherits from LookupError."""
        assert issubclass(AddressFormatError, LookupError)
        assert issubclass(AddressFormatError, Exception)


class TestExceptionInstantiation:
    """Test exception instantiation and message handling."""

    def test_lookup_error_creation(self):
        """Test LookupError can be created with message."""
        message = "Test lookup error"
        error = LookupError(message)
        assert str(error) == message
        assert isinstance(error, Exception)

    def test_no_as_data_error_creation(self):
        """Test NoASDataError can be created with message."""
        message = "No AS data available"
        error = NoASDataError(message)
        assert str(error) == message
        assert isinstance(error, LookupError)

    def test_nonroutable_address_error_creation(self):
        """Test NonroutableAddressError can be created with message."""
        message = "Address is not routable"
        error = NonroutableAddressError(message)
        assert str(error) == message
        assert isinstance(error, LookupError)

    def test_address_format_error_creation(self):
        """Test AddressFormatError can be created with message."""
        message = "Invalid address format"
        error = AddressFormatError(message)
        assert str(error) == message
        assert isinstance(error, LookupError)

    def test_exceptions_without_message(self):
        """Test exceptions can be created without message."""
        errors = [
            LookupError(),
            NoASDataError(),
            NonroutableAddressError(),
            AddressFormatError(),
        ]
        for error in errors:
            assert isinstance(error, Exception)
            # Should not raise when converted to string
            str(error)


class TestExceptionRaising:
    """Test that exceptions can be properly raised and caught."""

    def test_raise_lookup_error(self):
        """Test raising and catching LookupError."""
        message = "Test lookup error"
        with pytest.raises(LookupError) as exc_info:
            raise LookupError(message)
        assert str(exc_info.value) == message

    def test_raise_no_as_data_error(self):
        """Test raising and catching NoASDataError."""
        message = "No AS data found"
        with pytest.raises(NoASDataError) as exc_info:
            raise NoASDataError(message)
        assert str(exc_info.value) == message

    def test_raise_nonroutable_address_error(self):
        """Test raising and catching NonroutableAddressError."""
        message = "RFC 1918 private address"
        with pytest.raises(NonroutableAddressError) as exc_info:
            raise NonroutableAddressError(message)
        assert str(exc_info.value) == message

    def test_raise_address_format_error(self):
        """Test raising and catching AddressFormatError."""
        message = "Invalid IP address format"
        with pytest.raises(AddressFormatError) as exc_info:
            raise AddressFormatError(message)
        assert str(exc_info.value) == message


class TestExceptionCatching:
    """Test exception catching with inheritance."""

    def test_catch_specific_as_base(self):
        """Test that specific exceptions can be caught as base LookupError."""
        # NoASDataError should be catchable as LookupError
        with pytest.raises(LookupError):
            raise NoASDataError("Test message")

        # NonroutableAddressError should be catchable as LookupError
        with pytest.raises(LookupError):
            raise NonroutableAddressError("Test message")

        # AddressFormatError should be catchable as LookupError
        with pytest.raises(LookupError):
            raise AddressFormatError("Test message")

    def test_catch_multiple_exception_types(self):
        """Test catching multiple exception types."""
        exceptions_to_test = [
            NoASDataError("No data"),
            NonroutableAddressError("Private IP"),
            AddressFormatError("Bad format"),
        ]

        for exception in exceptions_to_test:
            with pytest.raises((NoASDataError, NonroutableAddressError,
                               AddressFormatError)):
                raise exception

    def test_exception_type_identification(self):
        """Test identifying specific exception types when caught."""
        try:
            raise NoASDataError("Test message")
        except LookupError as e:
            assert isinstance(e, NoASDataError)
            assert not isinstance(e, NonroutableAddressError)
            assert not isinstance(e, AddressFormatError)

        try:
            raise NonroutableAddressError("Test message")
        except LookupError as e:
            assert isinstance(e, NonroutableAddressError)
            assert not isinstance(e, NoASDataError)
            assert not isinstance(e, AddressFormatError)

        try:
            raise AddressFormatError("Test message")
        except LookupError as e:
            assert isinstance(e, AddressFormatError)
            assert not isinstance(e, NoASDataError)
            assert not isinstance(e, NonroutableAddressError)


class TestExceptionMessages:
    """Test exception message handling and formatting."""

    def test_exception_with_formatted_message(self):
        """Test exceptions with formatted messages."""
        ip_addr = "192.168.1.1"
        message = f"Address {ip_addr} is private"
        error = NonroutableAddressError(message)
        assert ip_addr in str(error)

    def test_exception_with_multiple_args(self):
        """Test exceptions with multiple arguments."""
        error = LookupError("Primary message", "Secondary info")
        # Should handle multiple arguments gracefully
        error_str = str(error)
        assert "Primary message" in error_str

    def test_exception_repr(self):
        """Test exception representation."""
        message = "Test error message"
        error = AddressFormatError(message)
        repr_str = repr(error)
        assert "AddressFormatError" in repr_str
        assert message in repr_str
