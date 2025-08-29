"""Tests for aslookup.cli module."""

import asyncio
import sys
from io import StringIO
from unittest.mock import Mock, patch

import pytest

from aslookup.cli import main, process_addresses_async, process_single_address
from aslookup.exceptions import AddressFormatError, LookupError
from aslookup.lookup import ASData


class TestCLIArgumentParsing:
    """Test CLI argument parsing functionality."""

    def test_basic_argument_parsing(self):
        """Test basic argument parsing with single IP."""
        with patch('aslookup.cli.asyncio.run') as mock_asyncio_run:
            with patch('sys.argv', ['as-lookup', '8.8.8.8']):
                with patch('aslookup.cli.process_addresses_async') as mock_process:
                    # Mock the async function to avoid coroutine warnings
                    mock_process.return_value = asyncio.Future()
                    mock_process.return_value.set_result(None)
                    
                    main()
                    mock_asyncio_run.assert_called_once()

    def test_service_argument_parsing(self):
        """Test service argument parsing."""
        with patch('aslookup.cli.asyncio.run') as mock_asyncio_run:
            with patch('sys.argv', ['as-lookup', '--service', 'shadowserver', '8.8.8.8']):
                with patch('aslookup.cli.process_addresses_async') as mock_process:
                    mock_process.return_value = asyncio.Future()
                    mock_process.return_value.set_result(None)
                    
                    main()
                    mock_asyncio_run.assert_called_once()

    def test_header_argument_parsing(self):
        """Test header argument parsing."""
        with patch('aslookup.cli.asyncio.run') as mock_asyncio_run:
            with patch('sys.argv', ['as-lookup', '--header', '8.8.8.8']):
                with patch('aslookup.cli.process_addresses_async') as mock_process:
                    mock_process.return_value = asyncio.Future()
                    mock_process.return_value.set_result(None)
                    
                    with patch('builtins.print') as mock_print:
                        main()
                        
                        # Should print header
                        mock_print.assert_any_call('-' * 50)
                        mock_print.assert_any_call('%-15s  %s' % ('IP Address',
                                                                  'AS Information'))

    def test_raw_argument_parsing(self):
        """Test raw output argument parsing."""
        with patch('aslookup.cli.asyncio.run') as mock_asyncio_run:
            with patch('sys.argv', ['as-lookup', '--raw', '8.8.8.8']):
                with patch('aslookup.cli.process_addresses_async') as mock_process:
                    mock_process.return_value = asyncio.Future()
                    mock_process.return_value.set_result(None)
                    
                    main()
                    mock_asyncio_run.assert_called_once()

    def test_verbose_argument_parsing(self):
        """Test verbose argument parsing."""
        with patch('aslookup.cli.asyncio.run') as mock_asyncio_run:
            with patch('sys.argv', ['as-lookup', '--verbose', '8.8.8.8']):
                with patch('aslookup.cli.process_addresses_async') as mock_process:
                    mock_process.return_value = asyncio.Future()
                    mock_process.return_value.set_result(None)
                    
                    main()
                    mock_asyncio_run.assert_called_once()

    def test_version_argument(self):
        """Test version argument exits with version info."""
        with patch('sys.argv', ['as-lookup', '--version']):
            with pytest.raises(SystemExit) as exc_info:
                with patch('sys.stderr', new_callable=StringIO) as mock_stderr:
                    main()

            assert exc_info.value.code == 0
            output = mock_stderr.getvalue()
            assert "aslookup" in output

    def test_multiple_addresses_argument(self):
        """Test multiple IP addresses as arguments."""
        with patch('aslookup.cli.asyncio.run') as mock_asyncio_run:
            with patch('sys.argv', ['as-lookup', '8.8.8.8', '1.1.1.1']):
                with patch('aslookup.cli.process_addresses_async') as mock_process:
                    mock_process.return_value = asyncio.Future()
                    mock_process.return_value.set_result(None)
                    
                    main()
                    mock_asyncio_run.assert_called_once()

    def test_invalid_service_argument(self):
        """Test invalid service argument."""
        with patch('sys.argv', ['as-lookup', '--service', 'invalid']):
            with pytest.raises(SystemExit):
                main()


class TestProcessSingleAddress:
    """Test processing single address functionality."""

    @pytest.mark.asyncio
    async def test_process_single_address_success(self, sample_asdata_shadowserver):
        """Test successful processing of single address."""
        with patch('aslookup.cli.get_as_data_async') as mock_get_data:
            mock_get_data.return_value = sample_asdata_shadowserver
            
            result = await process_single_address("8.8.8.8", "shadowserver", False)
            addr, out_str, error, stream = result
            
            assert addr == "8.8.8.8"
            assert "AS15133" in out_str
            assert "US" in out_str
            assert "Google LLC" in out_str
            assert error is None
            assert stream == sys.stdout

    @pytest.mark.asyncio
    async def test_process_single_address_raw_output(self, sample_asdata_cymru):
        """Test processing single address with raw output."""
        with patch('aslookup.cli.get_as_data_async') as mock_get_data:
            mock_get_data.return_value = sample_asdata_cymru
            
            result = await process_single_address("8.8.8.8", "cymru", True)
            addr, data, error, stream = result
            
            assert addr == "8.8.8.8"
            assert data == sample_asdata_cymru
            assert error is None
            assert stream == sys.stdout

    @pytest.mark.asyncio
    async def test_process_single_address_format_error(self):
        """Test processing single address with format error."""
        with patch('aslookup.cli.get_as_data_async') as mock_get_data:
            mock_get_data.side_effect = AddressFormatError("Invalid IP")
            
            result = await process_single_address("invalid_ip", "shadowserver", False)
            addr, error_msg, error, stream = result
            
            assert addr == "invalid_ip"
            assert "Invalid IP" in error_msg
            assert isinstance(error, AddressFormatError)
            assert stream == sys.stderr

    @pytest.mark.asyncio
    async def test_process_single_address_lookup_error(self):
        """Test processing single address with lookup error."""
        with patch('aslookup.cli.get_as_data_async') as mock_get_data:
            mock_get_data.side_effect = LookupError("No data found")
            
            result = await process_single_address("192.168.1.1", "shadowserver", False)
            addr, error_msg, error, stream = result
            
            assert addr == "192.168.1.1"
            assert "No data found" in error_msg
            assert isinstance(error, LookupError)
            assert stream == sys.stderr


class TestProcessAddressesAsync:
    """Test async address processing functionality."""

    @pytest.mark.asyncio
    async def test_process_addresses_empty_list(self):
        """Test processing empty address list."""
        # Create mock args object
        args = Mock()
        args.service = "shadowserver"
        args.raw = False
        args.pause = False
        args.address = []
        
        parser = Mock()
        
        # Should return without error
        await process_addresses_async([], args, parser)

    @pytest.mark.asyncio
    async def test_process_addresses_single_cmdline_success(self, sample_asdata_shadowserver):
        """Test processing single address from command line successfully."""
        with patch('aslookup.cli.get_as_data_async') as mock_get_data:
            with patch('builtins.print') as mock_print:
                mock_get_data.return_value = sample_asdata_shadowserver
                
                args = Mock()
                args.service = "shadowserver"
                args.raw = False
                args.pause = False
                args.address = ["8.8.8.8"]
                
                parser = Mock()
                
                await process_addresses_async(["8.8.8.8"], args, parser)
                
                # Should print the result
                mock_print.assert_called()
                output = str(mock_print.call_args)
                assert "8.8.8.8" in output

    @pytest.mark.asyncio
    async def test_process_addresses_single_cmdline_error(self):
        """Test processing single address from command line with error."""
        with patch('aslookup.cli.get_as_data_async') as mock_get_data:
            mock_get_data.side_effect = AddressFormatError("Invalid IP")
            
            args = Mock()
            args.service = "shadowserver"
            args.raw = False
            args.pause = False
            args.address = ["invalid_ip"]
            
            parser = Mock()
            parser.error = Mock()
            
            await process_addresses_async(["invalid_ip"], args, parser)
            
            # Should call parser.error
            parser.error.assert_called_once()
            call_args = parser.error.call_args[0][0]
            assert "invalid_ip" in call_args
            assert "Invalid IP" in call_args

    @pytest.mark.asyncio
    async def test_process_addresses_multiple_concurrent(self, sample_asdata_shadowserver,
                                                        sample_asdata_cymru):
        """Test processing multiple addresses concurrently."""
        with patch('aslookup.cli.get_as_data_async') as mock_get_data:
            with patch('builtins.print') as mock_print:
                # Return different data for different IPs
                def side_effect(addr, service):
                    if addr == "8.8.8.8":
                        return sample_asdata_shadowserver
                    else:
                        return sample_asdata_cymru
                
                mock_get_data.side_effect = side_effect
                
                args = Mock()
                args.service = "shadowserver"
                args.raw = False
                args.pause = False
                args.address = None  # Indicates stdin input
                
                parser = Mock()
                
                addresses = ["8.8.8.8", "1.1.1.1"]
                await process_addresses_async(addresses, args, parser)
                
                # Should print results for both addresses
                assert mock_print.call_count == 2

    @pytest.mark.asyncio
    async def test_process_addresses_with_pause(self, sample_asdata_shadowserver):
        """Test processing addresses with pause between requests."""
        with patch('aslookup.cli.get_as_data_async') as mock_get_data:
            with patch('builtins.print'):
                with patch('asyncio.sleep') as mock_sleep:
                    mock_get_data.return_value = sample_asdata_shadowserver
                    
                    args = Mock()
                    args.service = "shadowserver"
                    args.raw = False
                    args.pause = True
                    args.address = None
                    
                    parser = Mock()
                    
                    addresses = ["8.8.8.8", "1.1.1.1"]
                    await process_addresses_async(addresses, args, parser)
                    
                    # Should call sleep once (between the two addresses)
                    mock_sleep.assert_called_once_with(1)

    @pytest.mark.asyncio
    async def test_process_addresses_raw_output(self, sample_asdata_shadowserver):
        """Test processing addresses with raw output."""
        with patch('aslookup.cli.get_as_data_async') as mock_get_data:
            with patch('builtins.print') as mock_print:
                mock_get_data.return_value = sample_asdata_shadowserver
                
                args = Mock()
                args.service = "shadowserver"
                args.raw = True
                args.pause = False
                args.address = None
                
                parser = Mock()
                
                await process_addresses_async(["8.8.8.8"], args, parser)
                
                # Should print the ASData object directly
                mock_print.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_addresses_mixed_results(self, sample_asdata_shadowserver):
        """Test processing addresses with mixed success/error results."""
        with patch('aslookup.cli.get_as_data_async') as mock_get_data:
            with patch('builtins.print') as mock_print:
                def side_effect(addr, service):
                    if addr == "8.8.8.8":
                        return sample_asdata_shadowserver
                    else:
                        raise AddressFormatError("Invalid IP")
                
                mock_get_data.side_effect = side_effect
                
                args = Mock()
                args.service = "shadowserver"
                args.raw = False
                args.pause = False
                args.address = None
                
                parser = Mock()
                
                addresses = ["8.8.8.8", "invalid_ip"]
                await process_addresses_async(addresses, args, parser)
                
                # Should print both success and error results
                assert mock_print.call_count == 2


class TestCLIIntegration:
    """Test CLI integration scenarios."""

    def test_main_single_address_success(self, sample_asdata_shadowserver):
        """Test main function with single address success."""
        with patch('aslookup.cli.asyncio.run') as mock_run:
            with patch('sys.argv', ['as-lookup', '8.8.8.8']):
                with patch('aslookup.cli.process_addresses_async') as mock_process:
                    mock_process.return_value = asyncio.Future()
                    mock_process.return_value.set_result(None)
                    
                    main()
                    
                    mock_run.assert_called_once()

        """Test main function with stdin input."""
        with patch('aslookup.cli.asyncio.run') as mock_run:
            with patch('sys.argv', ['as-lookup']):
                with patch('aslookup.cli.process_addresses_async') as mock_process:
                    mock_process.return_value = asyncio.Future()
                    mock_process.return_value.set_result(None)
                    
                    with patch('sys.stdin', StringIO('8.8.8.8\n1.1.1.1\n')):
                        main()
                        
                        mock_run.assert_called_once()

    def test_main_cymru_service(self):
        """Test main function with Cymru service."""
        with patch('aslookup.cli.asyncio.run') as mock_run:
            with patch('sys.argv', ['as-lookup', '--service', 'cymru', '8.8.8.8']):
                with patch('aslookup.cli.process_addresses_async') as mock_process:
                    mock_process.return_value = asyncio.Future()
                    mock_process.return_value.set_result(None)
                    
                    main()
                    
                    mock_run.assert_called_once()

    def test_main_header_and_raw(self):
        """Test main function with header and raw output."""
        with patch('aslookup.cli.asyncio.run') as mock_run:
            with patch('sys.argv', ['as-lookup', '--header', '--raw', '8.8.8.8']):
                with patch('aslookup.cli.process_addresses_async') as mock_process:
                    mock_process.return_value = asyncio.Future()
                    mock_process.return_value.set_result(None)
                    
                    main()
                    
                    mock_run.assert_called_once()

    def test_main_empty_stdin(self):
        """Test main function with empty stdin."""
        with patch('aslookup.cli.asyncio.run') as mock_run:
            with patch('sys.argv', ['as-lookup']):
                with patch('aslookup.cli.process_addresses_async') as mock_process:
                    mock_process.return_value = asyncio.Future()
                    mock_process.return_value.set_result(None)
                    
                    with patch('sys.stdin', StringIO('')):
                        main()
                        
                        mock_run.assert_called_once()

    def test_main_defanged_input(self):
        """Test main function with defanged IP input."""
        with patch('aslookup.cli.asyncio.run') as mock_run:
            with patch('sys.argv', ['as-lookup']):
                with patch('aslookup.cli.process_addresses_async') as mock_process:
                    mock_process.return_value = asyncio.Future()
                    mock_process.return_value.set_result(None)
                    
                    with patch('sys.stdin', StringIO('8[.]8[.]8[.]8\n')):
                        main()
                        
                        mock_run.assert_called_once()
