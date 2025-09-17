"""aslookup CLI module."""

import argparse
import asyncio
import logging
import sys
from os import linesep

from defang import refang

from . import __full_version__
from .exceptions import AddressFormatError, LookupError
from .lookup import get_as_data_async

DEFAULT_LOOKUP_SOURCE = "cymru"

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aslookup")


def main():
    """Run main CLI."""
    description = (
        "Client to return autonomous system information for IP addresses"
    )
    epilog = (
        "One or more IP addresses may be passed as arguments on the "
        "command line. A list of IP addresses (newline-separated) may "
        "also be passed on standard input."
    )
    parser = argparse.ArgumentParser(description=description, epilog=epilog)
    parser.add_argument(
        "-s",
        "--service",
        choices=["shadowserver", "cymru"],
        default=DEFAULT_LOOKUP_SOURCE,
        help="service to query (default: %(default)s)",
    )
    parser.add_argument(
        "-H",
        "--header",
        action="store_true",
        help="print descriptive header before output",
    )
    parser.add_argument(
        "-p",
        "--pause",
        action="store_true",
        help="pause for one second between each query on "
        "address list input",
    )
    parser.add_argument(
        "-r",
        "--raw",
        action="store_true",
        help="display internal ASData object showing the "
        "value of each known field in the AS data",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="store_true",
        help="display package version",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="loglevel",
        action="store_const",
        const=logging.DEBUG,
        default=logging.WARNING,
        help="show verbose output",
    )
    parser.add_argument(
        "address",
        nargs="*",
        help="IP address(es) on which to perform AS lookup",
    )
    args = parser.parse_args()

    logger.setLevel(args.loglevel)
    logger.debug(
        "logging level: %s", logging.getLevelName(logger.getEffectiveLevel())
    )

    # Print software version
    if args.version:
        parser.exit(status=0, message=__full_version__ + linesep)

    # Print header lines if specified
    if args.header:
        print("-" * 50)
        print("%-15s  %s" % ("IP Address", "AS Information"))
        print("-" * 50)

    # Process addresses given as parameters or fed on stdin.
    # - Input as parameters: In this mode, invalid IP addresses result in
    #   script exiting with an error. Non-routable addresses result in
    #   message to stderr.
    # - Input on stdin: In this mode, invalid IP addresses result in script
    #   proceeding without exiting, in order to make it so that address lists
    #   process without interruption. All issues are output on stderr.
    in_src = args.address if args.address else sys.stdin

    # Collect all addresses first
    addresses = []
    for addr in in_src:
        addr = addr.strip()
        addr = refang(addr)
        if addr:  # Skip empty lines
            addresses.append(addr)

    # Run async processing
    asyncio.run(process_addresses_async(addresses, args, parser))


async def process_single_address(addr, service, raw_output):
    """Process a single address asynchronously."""
    try:
        data = await get_as_data_async(addr, service=service)
        stream = sys.stdout
        if not raw_output:
            out_str = "{0} | {1} | {2}".format(
                data.handle, data.cc, data.as_name
            )
        else:
            # For raw output, we need to return the data object
            return addr, data, None, sys.stdout
        return addr, out_str, None, stream
    except AddressFormatError as e:
        return addr, str(e), e, sys.stderr
    except LookupError as e:
        return addr, str(e), e, sys.stderr


async def process_addresses_async(addresses, args, parser):
    """Process multiple addresses concurrently."""
    if not addresses:
        return

    # Limit concurrent requests to avoid overwhelming DNS servers
    semaphore = asyncio.Semaphore(15)

    async def process_with_semaphore(addr):
        async with semaphore:
            return await process_single_address(addr, args.service, args.raw)

    # For single address or when using command line args, handle errors
    # differently
    if len(addresses) == 1 and args.address:
        # Single address from command line - exit on error
        addr = addresses[0]
        try:
            result = await process_single_address(addr, args.service, args.raw)
            addr, out_str, error, stream = result
            if error and isinstance(error, AddressFormatError):
                parser.error("[{}] {}".format(addr, error))
            if args.raw and stream == sys.stdout:
                print(out_str)  # out_str is actually the data object
            else:
                print("%-15s  %s" % (addr, out_str), file=stream)
        except Exception as e:
            parser.error("[{}] {}".format(addr, e))
    else:
        # Multiple addresses or stdin input - process concurrently
        tasks = [process_with_semaphore(addr) for addr in addresses]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                # Handle unexpected exceptions
                addr = addresses[i]
                print("%-15s  %s" % (addr, str(result)), file=sys.stderr)
            else:
                addr, out_str, error, stream = result
                if args.raw and stream == sys.stdout:
                    print(out_str)  # out_str is actually the data object
                else:
                    print("%-15s  %s" % (addr, out_str), file=stream)

            # Handle pause between requests
            if args.pause and i < len(results) - 1:
                await asyncio.sleep(1)
