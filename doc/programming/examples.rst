

.. _examples:

========
Examples
========

We collect some example Spicy parsers here that come with a growing
collection of `Spicy-based Zeek analyzers
<https://github.com/zeek/spicy-analyzers>`_. Check out that repository
for more examples.

.. rubric:: TFTP

A TFTP analyzer for Zeek, implementing the original RFC 1350 protocol
(no extensions). It comes with a Zeek script producing a typical
``tftp.log`` log file.

This analyzer is a good introductory example because the Spicy side is
pretty straight-forward. The Zeek-side logging is more tricky because
of the data transfer happening over a separate network session.

    - `TFTP Spicy grammar <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/tftp/tftp.spicy>`_
    - `Spicy code for TFTP analyzer Zeek integration <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/tftp/zeek_tftp.spicy>`_
    - `TFTP Zeek analyzer definition (EVT) <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/tftp//tftp.evt>`_
    - `Zeek TFTP script for logging <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/tftp//tftp.zeek>`_

.. rubric:: HTTP

A nearly complete HTTP parser. This parser was used with the original
Spicy prototype to compare output with Zeek's native handwritten HTTP
parser. We observed only negligible differences.

    - `HTTP Spicy grammar <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/http/http.spicy>`_
    - `Spicy code for HTTP analyzer Zeek integration <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/http//zeek_http.spicy>`_
    - `HTTP Zeek analyzer definition (EVT)  <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/http/http.evt>`_

.. rubric:: DNS

A comprehensive DNS parser. This parser was used with the original
Spicy prototype to compare output with Zeek's native handwritten DNS
parser. We observed only negligible differences.

The DNS parser is a good example of using :ref:`random access
<random_access>`.

    - `DNS Spicy grammar <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/dns/dns.spicy>`_
    - `Spicy code for DNS analyzer Zeek integration <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/dns/zeek_dns.spicy>`_
    - `DNS Zeek analyzer definition (EVT)  <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/dns/dns.evt>`_

.. rubric:: DHCP

A nearly complete DHCP parser. This parser extracts most DHCP option
messages understood by Zeek. The Zeek integration is almost direct and
most of the work is in formulating the parser itself.

    - `DHCP Spicy grammar <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/dhcp/dhcp.spicy>`_
    - `Spicy code for DHCP analyzer Zeek integration <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/dhcp/zeek_dhcp.spicy>`_
    - `DHCP analyzer Zeek analyzer definition (EVT)  <https://github.com/zeek/spicy-analyzers/blob/main/analyzer/dhcp/dhcp.evt>`_
