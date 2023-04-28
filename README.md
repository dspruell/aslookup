# aslookup
Python client for IP to ASN lookup services

aslookup is a client utility for two of the public IP/AS query services
operated by the following organizations:

* Shadowserver -- https://www.shadowserver.org/wiki/pmwiki.php/Services/IP-BGP
* Team Cymru -- http://www.team-cymru.org/IP-ASN-mapping.html

The client implements both a simple Python module (aslookup) as well as a CLI
utility (`as-lookup`). The lookups are currently done using DNS, which works
well for a one-off lookups. It is not optimized for bulk lookups over the
Whois protocol.

Currently only IPv4 addresses are looked up. The client also maintains a
listing of IP networks which are unroutable internet addresses, typically
special use ranges in RFCs. In this way it can both filter out addresses from
queries which are a waste of time, as well as provide context to the user on
the address.

## Installation

The app has been tested on Python 3.

It's best to install the program into a Python virtualenv. If you will only use
the command line interface, the recommended way to install it is using
[pipx](https://pypa.github.io/pipx/):

    pipx install aslookup

If you will use aslookup as a library, you'll instead want to install it using
`pip` in your target Python environment:

    python3 -m pip install aslookup

## Usage

### Python module

The Python module defaults to querying the Team Cymru data service. The
desired service may be specified by passing the *service* parameter to
`get_as_data`.

```python
from aslookup import get_as_data
ip = "8.8.8.8"
get_as_data(ip, service="shadowserver")
```

### CLI script

It is possible to provide multiple IP addresses as arguments to the script, or 
to send them as a list on standard input, in which cases the script loops over 
them and returns output on separate lines. When providing invalid IPv4 
addresses as arguments, the script reports the problem on standard error and 
exits with an error. When providing input on stdin, the error is reported on 
standard output but execution is not aborted.

    as-lookup 8.8.8.8 9.9.9.9

or:

    as-lookup < ipaddrs.txt

### Test data

A list of test values for the script is included in the file `tests/test_input.txt`.
This can be useful to validate included IP prefix classifications and see the
output format.

    as-lookup < tests/test_input.txt

