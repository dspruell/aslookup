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

The app has been tested on Python 3. The script requires the *dnspython*
package. If missing, it will be installed automatically.

It's best to install the program into a Python virtualenv.

Recommended installation from PyPI using pip (make sure to use the pip or
python command from your target Python 3 environment)!

    pip3 install aslookup

## Usage

### Python module

The Python module defaults to querying the Shadowserver data service. The
desired service may be specified by passing the *service* parameter to
`get_as_data`.

```python
from aslookup import get_as_data
ip = '8.8.8.8'
get_as_data(ip, service='cymru')
```

### CLI script

It is possible to provide multiple IP addresses as arguments to the script, or 
to send them as a list on standard input, in which cases the script loops over 
them and returns output on separate lines. When providing invalid IPv4 
addresses as arguments, the script reports the problem on standard error and 
exits with an error. When providing input on stdin, the error is reported on 
standard output but execution is not aborted.

    as-lookup 8.8.8.8 11.22.33.44

### Test data

A list of test values for the script is included in the file `test_input.txt`.
This can be useful to validate included IP prefix classifications and see the
output format.

    as-lookup < test_input.txt

